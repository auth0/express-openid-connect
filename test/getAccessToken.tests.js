'use strict';

const assert = require('chai').assert;
const sinon = require('sinon');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});
const nock = require('nock');

const { auth } = require('..');
const { create: createServer } = require('./fixture/server');
const { makeIdToken } = require('./fixture/cert');
const { epoch } = require('../lib/utils/epoch');

const baseUrl = 'http://localhost:3000';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
  clientSecret: '__test_client_secret__',
  authorizationParams: {
    response_type: 'code',
    audience: 'https://api.example.com/',
    scope: 'openid profile offline_access',
  },
};

/**
 * Boots a server with the given router and an optional route handler.
 * Returns the server. Each test seeds its own session via POST /session.
 */
const setup = async ({
  authConfig = {},
  routeHandler,
  routePath = '/get-token',
} = {}) => {
  const authOpts = { ...defaultConfig, ...authConfig };
  const router = auth(authOpts);

  if (routeHandler) {
    router.get(routePath, routeHandler);
  }

  return createServer(router);
};

describe('req.oidc.getAccessToken()', () => {
  let server;

  afterEach(() => {
    if (server) {
      server.close();
      server = null;
    }
    nock.cleanAll();
  });

  // ---------------------------------------------------------------------------
  // 1. Cache hit — default audience, valid token
  // ---------------------------------------------------------------------------
  it('returns cached token when not expired (no audience option)', async () => {
    const futureExp = epoch() + 3600;
    const idToken = makeIdToken();

    server = await setup({
      routeHandler: async (req, res) => {
        const result = await req.oidc.getAccessToken();
        res.json({
          access_token: result.access_token,
          token_type: result.token_type,
          expires_in: result.expires_in,
        });
      },
    });

    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: idToken,
        access_token: '__cached_access_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_at: futureExp,
        tokenSets: [
          {
            audience: 'https://api.example.com/',
            access_token: '__cached_access_token__',
            scope: 'openid profile offline_access',
            expires_at: futureExp,
          },
        ],
      },
    });

    const result = await request
      .get('/get-token', { baseUrl, jar, json: true })
      .then((r) => r.body);

    assert.equal(result.access_token, '__cached_access_token__');
    assert.equal(result.token_type, 'Bearer');
    assert.isNumber(result.expires_in);
    assert.isTrue(result.expires_in > 0);
  });

  // ---------------------------------------------------------------------------
  // 2. Expired default token → refresh
  // ---------------------------------------------------------------------------
  it('refreshes an expired default-audience token and updates the session', async () => {
    const idToken = makeIdToken({ c_hash: '77QmUPtjPfzWtF2AnpK9RQ' });
    const pastExp = epoch() - 60;

    server = await setup({
      routeHandler: async (req, res) => {
        const result = await req.oidc.getAccessToken();
        res.json({ access_token: result.access_token });
      },
    });

    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: idToken,
        access_token: '__old_access_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_at: pastExp,
      },
    });

    const spy = sinon.spy(() => ({
      access_token: '__refreshed_access_token__',
      refresh_token: '__new_refresh_token__',
      token_type: 'Bearer',
      expires_in: 86400,
      scope: 'openid profile offline_access',
    }));
    const {
      interceptors: [interceptor],
    } = nock('https://op.example.com', {
      allowUnmocked: true,
    })
      .post('/oauth/token')
      .reply(200, spy);

    const result = await request
      .get('/get-token', { baseUrl, jar, json: true })
      .then((r) => r.body);

    nock.removeInterceptor(interceptor);

    sinon.assert.calledOnce(spy);
    assert.equal(result.access_token, '__refreshed_access_token__');

    const [, reqBody] = spy.firstCall.args;
    assert.match(reqBody, /grant_type=refresh_token/);
    assert.match(reqBody, /refresh_token=__test_refresh_token__/);
  });

  // ---------------------------------------------------------------------------
  // 3. Cache hit for explicit audience
  // ---------------------------------------------------------------------------
  it('returns cached token for an explicit audience without a token endpoint call', async () => {
    const futureExp = epoch() + 3600;
    const idToken = makeIdToken();

    server = await setup({
      routeHandler: async (req, res) => {
        const result = await req.oidc.getAccessToken({
          audience: 'https://api-b.example.com/',
          scope: 'read:reports',
        });
        res.json({ access_token: result.access_token });
      },
    });

    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: idToken,
        access_token: '__default_access_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_at: futureExp,
        tokenSets: [
          {
            audience: 'https://api.example.com/',
            access_token: '__default_access_token__',
            scope: 'openid profile offline_access',
            expires_at: futureExp,
          },
          {
            audience: 'https://api-b.example.com/',
            access_token: '__api_b_access_token__',
            scope: 'read:reports',
            expires_at: futureExp,
          },
        ],
      },
    });

    const result = await request
      .get('/get-token', { baseUrl, jar, json: true })
      .then((r) => r.body);

    // Correct token returned — proves cache was used, no exchange needed
    assert.equal(result.access_token, '__api_b_access_token__');
  });

  // ---------------------------------------------------------------------------
  // 4. MRRT exchange — new audience not yet in tokenSets
  // ---------------------------------------------------------------------------
  it('exchanges the refresh token for a new audience (MRRT) and stores it in tokenSets', async () => {
    const idToken = makeIdToken({ c_hash: '77QmUPtjPfzWtF2AnpK9RQ' });
    const futureExp = epoch() + 3600;

    server = await setup({
      routeHandler: async (req, res) => {
        const result = await req.oidc.getAccessToken({
          audience: 'https://api-b.example.com/',
          scope: 'read:reports',
        });
        res.json({ access_token: result.access_token });
      },
    });

    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: idToken,
        access_token: '__default_access_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_at: futureExp,
        tokenSets: [
          {
            audience: 'https://api.example.com/',
            access_token: '__default_access_token__',
            scope: 'openid profile offline_access',
            expires_at: futureExp,
          },
        ],
      },
    });

    const spy = sinon.spy(() => ({
      access_token: '__api_b_access_token__',
      refresh_token: '__new_refresh_token__',
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'read:reports',
    }));
    const {
      interceptors: [interceptor],
    } = nock('https://op.example.com', {
      allowUnmocked: true,
    })
      .post('/oauth/token')
      .reply(200, spy);

    const result = await request
      .get('/get-token', { baseUrl, jar, json: true })
      .then((r) => r.body);
    nock.removeInterceptor(interceptor);

    sinon.assert.calledOnce(spy);
    assert.equal(result.access_token, '__api_b_access_token__');

    const [, reqBody] = spy.firstCall.args;
    assert.match(reqBody, /audience=https%3A%2F%2Fapi-b\.example\.com%2F/);
    assert.match(reqBody, /scope=read%3Areports/);

    // New token must be cached in tokenSets
    const session = await request
      .get('/session', { baseUrl, jar, json: true })
      .then((r) => r.body);
    const apiBEntry = session.tokenSets.find(
      (ts) => ts.audience === 'https://api-b.example.com/',
    );
    assert.ok(apiBEntry, 'tokenSets should have an entry for api-b');
    assert.equal(apiBEntry.access_token, '__api_b_access_token__');

    // Flat fields for the config audience must be unchanged
    assert.equal(session.access_token, '__default_access_token__');
  });

  // ---------------------------------------------------------------------------
  // 5. Backward compat — old session with no tokenSets
  // ---------------------------------------------------------------------------
  it('silently hydrates tokenSets from flat session fields on first call (pre-MRRT session)', async () => {
    const futureExp = epoch() + 3600;
    const idToken = makeIdToken();

    server = await setup({
      routeHandler: async (req, res) => {
        const result = await req.oidc.getAccessToken();
        res.json({
          access_token: result.access_token,
          tokenSetsLength: req.appSession.tokenSets?.length,
        });
      },
    });

    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: idToken,
        access_token: '__legacy_access_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_at: futureExp,
        // no tokenSets — simulates a pre-MRRT session
      },
    });

    const result = await request
      .get('/get-token', { baseUrl, jar, json: true })
      .then((r) => r.body);

    assert.equal(result.access_token, '__legacy_access_token__');
    assert.equal(result.tokenSetsLength, 1, 'tokenSets should be initialised');
  });

  // ---------------------------------------------------------------------------
  // 6. Scope superset cache hit
  // ---------------------------------------------------------------------------
  it('returns cached token when requested scopes are a subset of cached scopes', async () => {
    const futureExp = epoch() + 3600;
    const idToken = makeIdToken();

    server = await setup({
      routeHandler: async (req, res) => {
        // Request only 'read:reports' but cache has 'read:reports write:reports'
        const result = await req.oidc.getAccessToken({
          audience: 'https://api.example.com/',
          scope: 'read:reports',
        });
        res.json({ access_token: result.access_token });
      },
    });

    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: idToken,
        access_token: '__broad_scope_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_at: futureExp,
        tokenSets: [
          {
            audience: 'https://api.example.com/',
            access_token: '__broad_scope_token__',
            scope: 'read:reports write:reports',
            expires_at: futureExp,
          },
        ],
      },
    });

    const result = await request
      .get('/get-token', { baseUrl, jar, json: true })
      .then((r) => r.body);

    // Correct token returned — proves cache was hit without a new exchange
    assert.equal(result.access_token, '__broad_scope_token__');
  });

  // ---------------------------------------------------------------------------
  // 7. No session → error
  // ---------------------------------------------------------------------------
  it('throws when the user has no active session', async () => {
    server = await setup({
      routeHandler: async (req, res) => {
        try {
          await req.oidc.getAccessToken();
          res.json({ ok: true });
        } catch (e) {
          res.status(401).json({ message: e.message });
        }
      },
    });

    const jar = request.jar(); // fresh jar — no session seeded
    const result = await request
      .get('/get-token', { baseUrl, jar, json: true })
      .then((r) => r.body);

    assert.match(result.message, /active session/i);
  });

  // ---------------------------------------------------------------------------
  // 8. Expired token + no refresh token → error
  // ---------------------------------------------------------------------------
  it('throws when the token is expired and no refresh token exists', async () => {
    const idToken = makeIdToken();
    const pastExp = epoch() - 60;

    server = await setup({
      routeHandler: async (req, res) => {
        try {
          await req.oidc.getAccessToken();
          res.json({ ok: true });
        } catch (e) {
          res.status(400).json({ message: e.message });
        }
      },
    });

    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: idToken,
        access_token: '__expired_token__',
        // no refresh_token
        token_type: 'Bearer',
        expires_at: pastExp,
      },
    });

    const result = await request
      .get('/get-token', { baseUrl, jar, json: true })
      .then((r) => r.body);

    assert.match(result.message, /refresh token/i);
  });

  // ---------------------------------------------------------------------------
  // 9. SessionExpiredError when sessionExpiresAt ceiling has passed
  // ---------------------------------------------------------------------------
  it('throws SessionExpiredError when the IdP session ceiling has been reached', async () => {
    const idToken = makeIdToken();

    // Seed the session ceiling directly in the route handler to avoid the
    // appSession middleware rejecting the session before we can test it.
    server = await setup({
      routeHandler: async (req, res) => {
        // Manually inject a past ceiling into the already-loaded session
        req.appSession.sessionExpiresAt = epoch() - 60;
        try {
          await req.oidc.getAccessToken();
          res.json({ ok: true });
        } catch (e) {
          res.status(401).json({ message: e.message, name: e.name });
        }
      },
    });

    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: idToken,
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_at: epoch() + 3600,
      },
    });

    const result = await request
      .get('/get-token', { baseUrl, jar, json: true })
      .then((r) => r.body);

    assert.equal(result.name, 'SessionExpiredError');
  });

  // ---------------------------------------------------------------------------
  // 10. sessionExpiresAt is preserved after MRRT exchange
  // ---------------------------------------------------------------------------
  it('preserves sessionExpiresAt after an MRRT token exchange', async () => {
    const idToken = makeIdToken({ c_hash: '77QmUPtjPfzWtF2AnpK9RQ' });
    const futureExp = epoch() + 3600;
    const sessionCeiling = epoch() + 7200;

    server = await setup({
      routeHandler: async (req, res) => {
        await req.oidc.getAccessToken({
          audience: 'https://api-b.example.com/',
          scope: 'read:reports',
        });
        res.json({ sessionExpiresAt: req.appSession.sessionExpiresAt });
      },
    });

    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: idToken,
        access_token: '__default_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_at: futureExp,
        sessionExpiresAt: sessionCeiling,
        tokenSets: [
          {
            audience: 'https://api.example.com/',
            access_token: '__default_token__',
            scope: 'openid profile offline_access',
            expires_at: futureExp,
          },
        ],
      },
    });

    const {
      interceptors: [interceptor],
    } = nock('https://op.example.com', {
      allowUnmocked: true,
    })
      .post('/oauth/token')
      .reply(200, {
        access_token: '__api_b_token__',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'read:reports',
      });

    const result = await request
      .get('/get-token', { baseUrl, jar, json: true })
      .then((r) => r.body);
    nock.removeInterceptor(interceptor);

    assert.equal(
      result.sessionExpiresAt,
      sessionCeiling,
      'sessionExpiresAt must be preserved across MRRT exchange',
    );
  });

  // ---------------------------------------------------------------------------
  // 11. Flat access_token kept in sync after refreshing the config audience
  // ---------------------------------------------------------------------------
  it('keeps flat access_token in sync when refreshing the config audience', async () => {
    const idToken = makeIdToken({ c_hash: '77QmUPtjPfzWtF2AnpK9RQ' });
    const pastExp = epoch() - 60;

    server = await setup({
      routeHandler: async (req, res) => {
        await req.oidc.getAccessToken();
        res.json({
          flatAccessToken: req.appSession.access_token,
          legacyAccessToken: req.oidc.accessToken?.access_token,
        });
      },
    });

    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: idToken,
        access_token: '__old_access_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_at: pastExp,
      },
    });

    const {
      interceptors: [interceptor],
    } = nock('https://op.example.com', {
      allowUnmocked: true,
    })
      .post('/oauth/token')
      .reply(200, {
        access_token: '__refreshed_access_token__',
        refresh_token: '__new_refresh_token__',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'openid profile offline_access',
      });

    const result = await request
      .get('/get-token', { baseUrl, jar, json: true })
      .then((r) => r.body);
    nock.removeInterceptor(interceptor);

    assert.equal(
      result.flatAccessToken,
      '__refreshed_access_token__',
      'flat access_token should be updated in session',
    );
    assert.equal(
      result.legacyAccessToken,
      '__refreshed_access_token__',
      'req.oidc.accessToken should reflect the new token',
    );
  });
});

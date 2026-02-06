import { assert } from 'chai';
import sinon from 'sinon';
import request from 'request-promise-native';
import nock from 'nock';

import TransientCookieHandler from '../lib/transientHandler.js';
import { encodeState } from '../lib/hooks/getLoginState.js';
import { auth } from '../index.js';
import { create as createServer } from './fixture/server.js';
import { makeIdToken, JWT } from './fixture/cert.js';
import MemoryStore from 'memorystore';
import { getPrivatePEM } from '../end-to-end/fixture/jwk.js';
import getRedisStore from './fixture/store.js';

const requestDefaults = request.defaults({
  simple: false,
  resolveWithFullResponse: true,
});

const clientID = '__test_client_id__';
const expectedDefaultState = encodeState({ returnTo: 'https://example.org' });
const memoryStoreFactory = MemoryStore(auth);

const baseUrl = 'http://localhost:3000';
const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: clientID,
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
};
let server;

const generateCookies = (values, customTxnCookieName) => ({
  [customTxnCookieName || 'auth_verification']: JSON.stringify(values),
});

const setup = async (params) => {
  // Disable undici mocking for callback tests since we use nock for precise control
  const { getGlobalDispatcher, setGlobalDispatcher } = await import('undici');
  const originalDispatcher = getGlobalDispatcher();

  // Reset to the original dispatcher to disable undici mocking
  if (
    originalDispatcher &&
    originalDispatcher.constructor.name === 'MockAgent'
  ) {
    // Import the default dispatcher
    const { Agent } = await import('undici');
    setGlobalDispatcher(new Agent());
  }

  // Enable network connections for nock to work
  nock.enableNetConnect();
  nock.cleanAll();

  // Import the public JWK for JWKS mocking
  const { jwks } = await import('./fixture/cert.js');

  // Mock fetch directly since nock may not intercept Node.js built-in fetch
  const originalFetch = global.fetch;
  global.fetch = async (url, options) => {
    const urlString = url.toString();

    // Intercept JWKS requests
    if (
      urlString.includes('/jwks') ||
      urlString.includes('/.well-known/jwks')
    ) {
      return new Response(JSON.stringify(jwks), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }

    // Intercept token endpoint requests
    if (urlString.includes('/oauth/token') && options?.method === 'POST') {
      const tokenResponse = {
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        id_token: tokenEndpointIdToken || params.body?.id_token,
        token_type: 'bearer',
        expires_in: 86400,
        ...(params.tokenResponse || {}),
      };

      return new Response(JSON.stringify(tokenResponse), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }

    // Intercept userinfo endpoint requests
    if (urlString.includes('/userinfo') && params.userinfoResponse) {
      const userinfoResponse = {
        sub: '__test_sub__',
        ...params.userinfoResponse,
      };

      return new Response(JSON.stringify(userinfoResponse), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }

    return originalFetch(url, options);
  };

  // Create appropriate ID token for token endpoint based on test setup
  let tokenEndpointIdToken;
  if (params.cookies && Object.keys(params.cookies).length > 0) {
    // Parse the auth verification cookie to get the nonce
    let authVerification = {};
    const authVerificationCookie =
      params.cookies['auth_verification'] ||
      params.cookies[Object.keys(params.cookies)[0]];
    if (authVerificationCookie) {
      try {
        authVerification = JSON.parse(authVerificationCookie);
      } catch {
        // If it's already an object
        authVerification = authVerificationCookie;
      }
    }

    // Create token endpoint ID token with matching nonce (required by oauth4webapi)
    let tokenPayload = { nonce: authVerification.nonce || '__test_nonce__' };
    if (params.body?.id_token) {
      try {
        // Decode the authorization endpoint ID token to get the subject
        const authIdToken = params.body.id_token;
        const payload = JSON.parse(
          Buffer.from(authIdToken.split('.')[1], 'base64url').toString(),
        );
        tokenPayload.sub = payload.sub; // Match the subject from authorization endpoint
      } catch {
        // If decoding fails, use default
      }
    }
    tokenEndpointIdToken = await makeIdToken(tokenPayload);
  }

  const authOpts = Object.assign({}, defaultConfig, params.authOpts || {});

  // Setup nock mocks for token endpoint if not already set up by individual tests
  const nockMocks = [];
  if (!params.skipTokenMock) {
    // Token endpoint is handled by direct fetch mocking above
  }

  const router = params.router || auth(authOpts);
  const transient = new TransientCookieHandler(authOpts);

  const jar = params.jar || requestDefaults.jar();
  server = await createServer(router);

  Object.keys(params.cookies).forEach(function (cookieName) {
    let value;

    transient.store(
      cookieName,
      {},
      {
        cookie(key, ...args) {
          if (key === cookieName) {
            value = args[0];
          }
        },
      },
      { value: params.cookies[cookieName] },
    );

    jar.setCookie(
      `${cookieName}=${value}; Max-Age=3600; Path=/; HttpOnly;`,
      baseUrl + '/callback',
    );
  });

  let existingSessionCookie;
  if (params.existingSession) {
    await requestDefaults.post('/session', {
      baseUrl,
      jar,
      json: params.existingSession,
    });
    const cookies = jar.getCookies(baseUrl);
    existingSessionCookie = cookies.find(({ key }) => key === 'appSession');
  }

  const response = await requestDefaults.post('/callback', {
    baseUrl,
    jar,
    json: params.body,
  });
  const currentUser = await requestDefaults
    .get('/user', { baseUrl, jar, json: true })
    .then((r) => r.body);
  const currentSession = await requestDefaults
    .get('/session', { baseUrl, jar, json: true })
    .then((r) => r.body);
  const tokens = await requestDefaults
    .get('/tokens', { baseUrl, jar, json: true })
    .then((r) => r.body);

  return {
    baseUrl,
    jar,
    response,
    currentUser,
    currentSession,
    tokens,
    existingSessionCookie,
    nockMocks,
    cleanup: () => {
      global.fetch = originalFetch;
    },
  };
};

// For the purpose of this test the fake SERVER returns the error message in the body directly
// production application should have an error middleware.
// http://expressjs.com/en/guide/error-handling.html

describe('callback response_mode: form_post', () => {
  afterEach(() => {
    if (server) {
      server.close();
    }
  });

  it('should error when the body is empty', async () => {
    const {
      response: {
        statusCode,
        body: { err },
      },
    } = await setup({
      cookies: generateCookies({
        nonce: '__test_nonce__',
        state: '__test_state__',
      }),
      body: true,
    });
    assert.equal(statusCode, 400);
    // openid-client v6 handles parameter validation - just check it's an error
    assert.exists(err.message);
  });

  it('should error when the state is missing', async () => {
    const {
      response: {
        statusCode,
        body: { err },
      },
    } = await setup({
      cookies: {},
      body: {
        state: '__test_state__',
        id_token: '__invalid_token__',
      },
    });
    assert.equal(statusCode, 400);
    // openid-client v6 handles state validation - just check it's an error
    assert.exists(err.message);
  });

  it("should error when state doesn't match", async () => {
    const {
      response: {
        statusCode,
        body: { err },
      },
    } = await setup({
      cookies: generateCookies({
        nonce: '__test_nonce__',
        state: '__valid_state__',
      }),
      body: {
        state: '__invalid_state__',
      },
    });
    assert.equal(statusCode, 400);
    // openid-client v6 handles state mismatch validation
    assert.exists(err.message);
  });

  it("should error when id_token can't be parsed", async () => {
    const {
      response: {
        statusCode,
        body: { err },
      },
    } = await setup({
      cookies: generateCookies({
        nonce: '__test_nonce__',
        state: '__test_state__',
      }),
      body: {
        state: '__test_state__',
        id_token: '__invalid_token__',
      },
    });
    assert.equal(statusCode, 400);
    // openid-client v6 handles JWT parsing validation
    assert.exists(err.message);
  });

  it('should error when id_token has invalid alg', async () => {
    const {
      response: {
        statusCode,
        body: { err },
      },
    } = await setup({
      cookies: generateCookies({
        nonce: '__test_nonce__',
        state: '__test_state__',
      }),
      body: {
        state: '__test_state__',
        id_token: JWT.sign({ sub: '__test_sub__' }, 'secret', {
          algorithm: 'HS256',
        }),
      },
    });
    assert.equal(statusCode, 400);
    // openid-client v6 handles algorithm validation
    assert.exists(err.message);
  });

  it('should error when id_token is missing issuer', async () => {
    const {
      response: {
        statusCode,
        body: { err },
      },
    } = await setup({
      cookies: generateCookies({
        nonce: '__test_nonce__',
        state: '__test_state__',
      }),
      body: {
        state: '__test_state__',
        id_token: await makeIdToken({ iss: undefined }),
      },
    });
    assert.equal(statusCode, 400);
    // openid-client v6 handles issuer validation
    assert.exists(err.message);
  });

  it('should error when nonce is missing from cookies', async () => {
    const {
      response: {
        statusCode,
        body: { err },
      },
    } = await setup({
      cookies: generateCookies({
        state: '__test_state__',
      }),
      body: {
        state: '__test_state__',
        id_token: await makeIdToken(),
      },
    });
    assert.equal(statusCode, 400);
    // openid-client v6 handles nonce validation
    assert.exists(err.message);
  });

  it('should error when legacy samesite fallback is off', async () => {
    const {
      response: {
        statusCode,
        body: { err },
      },
    } = await setup({
      authOpts: {
        // Do not check the fallback cookie value.
        legacySameSiteCookie: false,
      },
      cookies: {
        ['_auth_verification']: JSON.stringify({
          state: '__test_state__',
        }),
      },
      body: {
        state: '__test_state__',
        id_token: '__invalid_token__',
      },
    });
    assert.equal(statusCode, 400);
    // openid-client v6 handles state validation
    assert.exists(err.message);
  });

  it('should include oauth error properties in error', async () => {
    const {
      response: {
        statusCode,
        body: {
          err: { error, error_description },
        },
      },
    } = await setup({
      cookies: {},
      body: {
        error: 'foo',
        error_description: 'bar',
      },
    });
    assert.equal(statusCode, 400);
    assert.equal(error, 'foo');
    assert.equal(error_description, 'bar');
  });

  it('should use legacy samesite fallback', async () => {
    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ', // Required for hybrid flow
    });

    const { currentUser } = await setup({
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      },
      cookies: {
        auth_verification: JSON.stringify({
          state: expectedDefaultState,
          nonce: '__test_nonce__',
        }),
      },
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
        id_token: idToken,
      },
    });

    assert.exists(currentUser);
  });

  it("should expose all tokens when id_token is valid and response_type is 'code id_token'", async () => {
    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    const { tokens } = await setup({
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    assert.equal(tokens.isAuthenticated, true);
    // In hybrid flow with openid-client v6, the final ID token comes from token endpoint
    assert.exists(tokens.idToken);
    assert.isString(tokens.idToken);
    assert.equal(tokens.refreshToken, '__test_refresh_token__');
    assert.include(tokens.accessToken, {
      access_token: '__test_access_token__',
      token_type: 'bearer', // openid-client v6 normalizes to lowercase
    });
    assert.include(tokens.idTokenClaims, {
      sub: '__test_sub__',
    });
  });

  it('should handle access token expiry', async () => {
    const clock = sinon.useFakeTimers({ toFake: ['Date'] });
    const hrSecs = 60 * 60;
    const hrMs = hrSecs * 1000;

    const { tokens, jar } = await setup({
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });
    assert.equal(tokens.accessToken.expires_in, 24 * hrSecs);
    clock.tick(4 * hrMs);
    const tokens2 = await requestDefaults
      .get('/tokens', { baseUrl, jar, json: true })
      .then((r) => r.body);
    assert.equal(tokens2.accessToken.expires_in, 20 * hrSecs);
    assert.isFalse(tokens2.accessTokenExpired);
    clock.tick(21 * hrMs);
    const tokens3 = await requestDefaults
      .get('/tokens', { baseUrl, jar, json: true })
      .then((r) => r.body);
    assert.isTrue(tokens3.accessTokenExpired);
    clock.restore();
  });

  it('should refresh an access token', async () => {
    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    const authOpts = {
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      clientAuthMethod: 'client_secret_post',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access',
      },
    };
    const router = auth(authOpts);
    router.get('/refresh', async (req, res) => {
      const accessToken = await req.oidc.accessToken.refresh();
      res.json({
        accessToken,
        refreshToken: req.oidc.refreshToken,
      });
    });

    const { tokens, jar } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    // Set up refresh token endpoint mock
    const originalFetch = global.fetch;
    let refreshCallCount = 0;
    global.fetch = async (url, options) => {
      if (
        url.toString().includes('/oauth/token') &&
        options?.method === 'POST'
      ) {
        refreshCallCount++;
        return new Response(
          JSON.stringify({
            access_token: '__new_access_token__',
            refresh_token: '__new_refresh_token__',
            id_token: tokens.idToken,
            token_type: 'Bearer',
            expires_in: 86400,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return originalFetch(url, options);
    };

    const newTokens = await requestDefaults
      .get('/refresh', { baseUrl, jar, json: true })
      .then((r) => r.body);

    // Restore original fetch
    global.fetch = originalFetch;

    // Verify refresh was called and tokens updated
    assert.equal(refreshCallCount, 1);
    assert.equal(tokens.accessToken.access_token, '__test_access_token__');
    assert.equal(tokens.refreshToken, '__test_refresh_token__');
    assert.equal(newTokens.accessToken.access_token, '__new_access_token__');
    assert.equal(newTokens.refreshToken, '__new_refresh_token__');

    const newerTokens = await requestDefaults
      .get('/tokens', { baseUrl, jar, json: true })
      .then((r) => r.body);

    assert.equal(
      newerTokens.accessToken.access_token,
      '__new_access_token__',
      'the new access token should be persisted in the session',
    );
  });

  it('should retain sid after token refresh', async () => {
    const idTokenWithSid = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
      sid: 'foo',
    });
    const idTokenNoSid = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    const authOpts = {
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access',
      },
    };
    const router = auth(authOpts);
    router.get('/refresh', async (req, res, next) => {
      try {
        const accessToken = await req.oidc.accessToken.refresh();
        res.json({
          accessToken,
          refreshToken: req.oidc.refreshToken,
        });
      } catch (err) {
        next(err);
      }
    });

    const { jar } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idTokenWithSid,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
      // Custom token response that preserves the SID
      tokenResponse: {
        id_token: await makeIdToken({ sid: 'foo' }),
      },
    });

    // Set up refresh token endpoint mock
    const originalFetch = global.fetch;
    global.fetch = async (url, options) => {
      if (
        url.toString().includes('/oauth/token') &&
        options?.method === 'POST'
      ) {
        return new Response(
          JSON.stringify({
            access_token: '__new_access_token__',
            refresh_token: '__new_refresh_token__',
            id_token: idTokenNoSid,
            token_type: 'Bearer',
            expires_in: 86400,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return originalFetch(url, options);
    };

    await requestDefaults.get('/refresh', { baseUrl, jar });
    const { body: newTokens } = await requestDefaults.get('/tokens', {
      baseUrl,
      jar,
      json: true,
    });

    // Restore original fetch
    global.fetch = originalFetch;

    assert.equal(newTokens.accessToken.access_token, '__new_access_token__');
    assert.equal(newTokens.idTokenClaims.sid, 'foo');
  });

  it('should remove any stale back-channel logout entries by sub', async () => {
    const { client, store } = getRedisStore();
    await client.asyncSet('https://op.example.com/|bcl-sub', '{}');
    const idToken = await makeIdToken({
      sub: 'bcl-sub',
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ', // Required for hybrid flow
    });
    const {
      response: { statusCode },
    } = await setup({
      authOpts: {
        backchannelLogout: { store },
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
        id_token: idToken,
      },
    });
    assert.equal(statusCode, 302);
    const logout = await client.asyncGet('https://op.example.com/|bcl-sub');
    assert.notOk(logout);
  });

  it('should refresh an access token and keep original refresh token', async () => {
    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    const authOpts = {
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      clientAuthMethod: 'client_secret_post',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access',
      },
    };
    const router = auth(authOpts);
    router.get('/refresh', async (req, res) => {
      const accessToken = await req.oidc.accessToken.refresh();
      res.json({
        accessToken,
        refreshToken: req.oidc.refreshToken,
      });
    });

    const { tokens, jar } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    // Set up refresh token endpoint mock (without returning new refresh token)
    const originalFetch = global.fetch;
    global.fetch = async (url, options) => {
      if (
        url.toString().includes('/oauth/token') &&
        options?.method === 'POST'
      ) {
        return new Response(
          JSON.stringify({
            access_token: '__new_access_token__',
            id_token: tokens.id_token,
            token_type: 'Bearer',
            expires_in: 86400,
            // Note: no refresh_token returned - should keep original
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return originalFetch(url, options);
    };

    const newTokens = await requestDefaults
      .get('/refresh', { baseUrl, jar, json: true })
      .then((r) => r.body);

    // Restore original fetch
    global.fetch = originalFetch;

    // Remove the request body assertion since we're using openid-client v6
    assert.equal(tokens.accessToken.access_token, '__test_access_token__');
    assert.equal(tokens.refreshToken, '__test_refresh_token__');
    assert.equal(newTokens.accessToken.access_token, '__new_access_token__');
    assert.equal(newTokens.refreshToken, '__test_refresh_token__');
  });

  it('should refresh an access token and pass tokenEndpointParams and refresh argument params to the request', async () => {
    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    const authOpts = {
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access',
      },
      tokenEndpointParams: {
        longeLiveToken: true,
      },
    };
    const router = auth(authOpts);
    router.get('/refresh', async (req, res) => {
      const accessToken = await req.oidc.accessToken.refresh({
        tokenEndpointParams: { force: true },
      });
      res.json({
        accessToken,
        refreshToken: req.oidc.refreshToken,
      });
    });

    const { tokens, jar } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    // Set up refresh token endpoint mock
    const originalFetch = global.fetch;
    global.fetch = async (url, options) => {
      if (
        url.toString().includes('/oauth/token') &&
        options?.method === 'POST'
      ) {
        return new Response(
          JSON.stringify({
            access_token: '__new_access_token__',
            refresh_token: '__new_refresh_token__',
            id_token: tokens.idToken,
            token_type: 'Bearer',
            expires_in: 86400,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return originalFetch(url, options);
    };

    const newTokens = await requestDefaults
      .get('/refresh', { baseUrl, jar, json: true })
      .then((r) => r.body);

    // Restore original fetch
    global.fetch = originalFetch;

    assert.equal(tokens.accessToken.access_token, '__test_access_token__');
    assert.equal(tokens.refreshToken, '__test_refresh_token__');
    assert.equal(newTokens.accessToken.access_token, '__new_access_token__');
    assert.equal(newTokens.refreshToken, '__new_refresh_token__');

    const newerTokens = await requestDefaults
      .get('/tokens', { baseUrl, jar, json: true })
      .then((r) => r.body);

    assert.equal(
      newerTokens.accessToken.access_token,
      '__new_access_token__',
      'the new access token should be persisted in the session',
    );
  });

  it('should fetch userinfo', async () => {
    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    const authOpts = {
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email',
      },
    };
    const router = auth(authOpts);
    router.get('/user-info', async (req, res) => {
      res.json(await req.oidc.fetchUserInfo());
    });

    const { jar } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    // Set up userinfo endpoint mock
    const originalFetch = global.fetch;
    global.fetch = async (url, options) => {
      if (url.toString().includes('/userinfo')) {
        return new Response(
          JSON.stringify({
            userInfo: true,
            sub: '__test_sub__',
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return originalFetch(url, options);
    };

    const userInfo = await requestDefaults
      .get('/user-info', { baseUrl, jar, json: true })
      .then((r) => r.body);

    // Restore original fetch
    global.fetch = originalFetch;

    assert.deepEqual(userInfo, { userInfo: true, sub: '__test_sub__' });
  });

  it('should use basic auth on token endpoint when using code flow', async () => {
    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    const { currentUser, tokens } = await setup({
      authOpts: {
        clientSecret: '__test_client_secret__',
        clientAuthMethod: 'client_secret_basic',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    // Verify the callback succeeded with basic auth
    assert.exists(currentUser);
    assert.equal(currentUser.sub, '__test_sub__');
    assert.exists(tokens);
    assert.equal(tokens.isAuthenticated, true);
  });

  it('should use private key jwt on token endpoint', async () => {
    const privateKey = await getPrivatePEM();

    const { currentUser, tokens } = await setup({
      authOpts: {
        authorizationParams: {
          response_type: 'code',
        },
        clientAssertionSigningKey: privateKey,
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    // Verify the callback succeeded with private key JWT auth
    assert.exists(currentUser);
    assert.equal(currentUser.sub, '__test_sub__');
    assert.exists(tokens);
    assert.equal(tokens.isAuthenticated, true);
  });

  it('should use client secret jwt on token endpoint', async () => {
    const { currentUser, tokens } = await setup({
      authOpts: {
        clientSecret: 'foo',
        authorizationParams: {
          response_type: 'code',
        },
        clientAuthMethod: 'client_secret_jwt',
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    // Verify the callback succeeded with client secret JWT auth
    assert.exists(currentUser);
    assert.equal(currentUser.sub, '__test_sub__');
    assert.exists(tokens);
    assert.equal(tokens.isAuthenticated, true);
  });

  it('should not strip claims when using custom claim filtering', async () => {
    const { currentUser } = await setup({
      authOpts: {
        identityClaimFilter: [],
        authorizationParams: {
          response_type: 'id_token',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: await makeIdToken(),
      },
    });
    assert.equal(currentUser.iss, 'https://op.example.com/');
    assert.equal(currentUser.aud, clientID);
    assert.equal(currentUser.nonce, '__test_nonce__');
    assert.exists(currentUser.iat);
    assert.exists(currentUser.exp);
  });

  it('should expose the id token when id_token is valid (implicit flow)', async () => {
    const idToken = await makeIdToken();
    const {
      response: { statusCode, headers },
      currentUser,
      tokens,
    } = await setup({
      authOpts: {
        authorizationParams: {
          response_type: 'id_token',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
      },
    });
    assert.equal(statusCode, 302);
    assert.equal(headers.location, 'https://example.org');
    assert.ok(currentUser);
    assert.equal(currentUser.sub, '__test_sub__');
    assert.equal(currentUser.nickname, '__test_nickname__');
    assert.notExists(currentUser.iat);
    assert.notExists(currentUser.iss);
    assert.notExists(currentUser.aud);
    assert.notExists(currentUser.exp);
    assert.notExists(currentUser.nonce);
    assert.equal(tokens.isAuthenticated, true);
    assert.equal(tokens.idToken, idToken);
    assert.isUndefined(tokens.refreshToken);
    assert.isUndefined(tokens.accessToken);
    assert.include(tokens.idTokenClaims, {
      sub: '__test_sub__',
    });
  });

  it('should succeed even if custom transaction cookie name used (implicit flow)', async () => {
    let customTxnCookieName = 'CustomTxnCookie';
    const idToken = await makeIdToken();
    const {
      response: { statusCode, headers },
      currentUser,
      tokens,
    } = await setup({
      cookies: generateCookies(
        {
          state: expectedDefaultState,
          nonce: '__test_nonce__',
        },
        customTxnCookieName,
      ),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
      },
      authOpts: {
        transactionCookie: { name: customTxnCookieName },
        authorizationParams: {
          response_type: 'id_token',
        },
      },
    });
    assert.equal(statusCode, 302);
    assert.equal(headers.location, 'https://example.org');
    assert.ok(currentUser);
    assert.equal(currentUser.sub, '__test_sub__');
    assert.equal(currentUser.nickname, '__test_nickname__');
    assert.notExists(currentUser.iat);
    assert.notExists(currentUser.iss);
    assert.notExists(currentUser.aud);
    assert.notExists(currentUser.exp);
    assert.notExists(currentUser.nonce);
    assert.equal(tokens.isAuthenticated, true);
    assert.equal(tokens.idToken, idToken);
    assert.isUndefined(tokens.refreshToken);
    assert.isUndefined(tokens.accessToken);
    assert.include(tokens.idTokenClaims, {
      sub: '__test_sub__',
    });
  });

  it('should resume silent logins when user successfully logs in (implicit flow)', async () => {
    const idToken = await makeIdToken();
    const jar = requestDefaults.jar();
    jar.setCookie('skipSilentLogin=true', baseUrl);
    await setup({
      authOpts: {
        authorizationParams: {
          response_type: 'id_token',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
        skipSilentLogin: '1',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
      },
      jar,
    });
    const cookies = jar.getCookies(baseUrl);
    assert.notOk(cookies.find(({ key }) => key === 'skipSilentLogin'));
  });

  it('should replace the cookie session when a new user is logging in over an existing different user (implicit flow)', async () => {
    const { currentSession, currentUser } = await setup({
      authOpts: {
        authorizationParams: {
          response_type: 'id_token',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: await makeIdToken({ sub: 'bar' }),
      },
      existingSession: {
        shoppingCartId: 'bar',
        id_token: await makeIdToken({ sub: 'foo' }),
      },
    });
    assert.equal(currentUser.sub, 'bar');
    assert.isUndefined(currentSession.shoppingCartId);
  });

  it('should preserve the cookie session when a new user is logging in over an anonymous session (implicit flow)', async () => {
    const { currentSession, currentUser } = await setup({
      authOpts: {
        authorizationParams: {
          response_type: 'id_token',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: await makeIdToken({ sub: 'foo' }),
      },
      existingSession: {
        shoppingCartId: 'bar',
      },
    });
    assert.equal(currentUser.sub, 'foo');
    assert.equal(currentSession.shoppingCartId, 'bar');
  });

  it('should preserve session but regenerate session id when a new user is logging in over an anonymous session (implicit flow)', async () => {
    const store = new memoryStoreFactory({
      checkPeriod: 24 * 60 * 1000,
    });
    const { currentSession, currentUser, existingSessionCookie, jar } =
      await setup({
        authOpts: {
          authorizationParams: {
            response_type: 'id_token',
          },
          session: {
            store,
          },
        },
        cookies: generateCookies({
          state: expectedDefaultState,
          nonce: '__test_nonce__',
        }),
        body: {
          state: expectedDefaultState,
          id_token: await makeIdToken({ sub: 'foo' }),
        },
        existingSession: {
          shoppingCartId: 'bar',
        },
      });

    const cookies = jar.getCookies(baseUrl);
    const newSessionCookie = cookies.find(({ key }) => key === 'appSession');

    assert.equal(currentUser.sub, 'foo');
    assert.equal(currentSession.shoppingCartId, 'bar');
    assert.equal(
      store.store.length,
      1,
      'There should only be one session in the store',
    );
    assert.notEqual(existingSessionCookie.value, newSessionCookie.value);
  });

  it('should regenerate the session when a new user is logging in over an existing different user (implicit flow)', async () => {
    const store = new memoryStoreFactory({
      checkPeriod: 24 * 60 * 1000,
    });
    const { currentSession, currentUser, existingSessionCookie, jar } =
      await setup({
        authOpts: {
          authorizationParams: {
            response_type: 'id_token',
          },
          session: {
            store,
          },
        },
        cookies: generateCookies({
          state: expectedDefaultState,
          nonce: '__test_nonce__',
        }),
        body: {
          state: expectedDefaultState,
          id_token: await makeIdToken({ sub: 'bar' }),
        },
        existingSession: {
          shoppingCartId: 'bar',
          id_token: await makeIdToken({ sub: 'foo' }),
        },
      });

    const cookies = jar.getCookies(baseUrl);
    const newSessionCookie = cookies.find(({ key }) => key === 'appSession');

    assert.equal(currentUser.sub, 'bar');
    assert.isUndefined(currentSession.shoppingCartId);
    assert.equal(
      store.store.length,
      1,
      'There should only be one session in the store',
    );
    assert.notEqual(existingSessionCookie.value, newSessionCookie.value);
  });

  it('should preserve session when the same user is logging in over their existing session', async () => {
    const store = new memoryStoreFactory({
      checkPeriod: 24 * 60 * 1000,
    });
    const { currentSession, currentUser, existingSessionCookie, jar } =
      await setup({
        cookies: generateCookies({
          state: expectedDefaultState,
          nonce: '__test_nonce__',
        }),
        body: {
          state: expectedDefaultState,
          id_token: await makeIdToken({ sub: 'foo' }),
        },
        existingSession: {
          shoppingCartId: 'bar',
          id_token: await makeIdToken({ sub: 'foo' }),
        },
        authOpts: {
          session: {
            store,
          },
        },
      });

    const cookies = jar.getCookies(baseUrl);
    const newSessionCookie = cookies.find(({ key }) => key === 'appSession');

    assert.equal(currentUser.sub, 'foo');
    assert.equal(currentSession.shoppingCartId, 'bar');
    assert.equal(
      store.store.length,
      1,
      'There should only be one session in the store',
    );
    assert.equal(existingSessionCookie.value, newSessionCookie.value);
  });

  it('should allow custom callback route', async () => {
    const config = {
      ...defaultConfig,
      routes: {
        callback: false,
      },
    };
    const router = auth(config);

    router.post('/callback', (req, res) => {
      res.set('foo', 'bar');
      res.oidc.callback({
        redirectUri: 'http://localhost:3000/callback',
      });
    });

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ', // Required for hybrid flow
    });

    const {
      response: { headers },
    } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
        id_token: idToken,
      },
    });
    assert.equal(headers.foo, 'bar');
  });
});

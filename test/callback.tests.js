const assert = require('chai').assert;
const sinon = require('sinon');
const jose = require('jose');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});

const TransientCookieHandler = require('../lib/transientHandler');
const { encodeState } = require('../lib/hooks/getLoginState');
const { auth } = require('..');
const { create: createServer } = require('./fixture/server');
const { makeIdToken } = require('./fixture/cert');
const clientID = '__test_client_id__';
const expectedDefaultState = encodeState({ returnTo: 'https://example.org' });
const nock = require('nock');
const MemoryStore = require('memorystore')(auth);

const baseUrl = 'http://localhost:3000';
const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: clientID,
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
};
let server;

const generateCookies = (values) => ({
  auth_verification: JSON.stringify(values),
});

const setup = async (params) => {
  const authOpts = Object.assign({}, defaultConfig, params.authOpts || {});
  const router = params.router || auth(authOpts);
  const transient = new TransientCookieHandler(authOpts);

  const jar = params.jar || request.jar();
  server = await createServer(router);
  let tokenReqHeader;
  let tokenReqBody;

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
      { value: params.cookies[cookieName] }
    );

    jar.setCookie(
      `${cookieName}=${value}; Max-Age=3600; Path=/; HttpOnly;`,
      baseUrl + '/callback'
    );
  });

  const {
    interceptors: [interceptor],
  } = nock('https://op.example.com', { allowUnmocked: true })
    .post('/oauth/token')
    .reply(200, function (uri, requestBody) {
      tokenReqHeader = this.req.headers;
      tokenReqBody = requestBody;
      return {
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        id_token: params.body.id_token,
        token_type: 'Bearer',
        expires_in: 86400,
      };
    });

  let existingSessionCookie;
  if (params.existingSession) {
    await request.post('/session', {
      baseUrl,
      jar,
      json: params.existingSession,
    });
    const cookies = jar.getCookies(baseUrl);
    existingSessionCookie = cookies.find(({ key }) => key === 'appSession');
  }

  const response = await request.post('/callback', {
    baseUrl,
    jar,
    json: params.body,
  });
  const currentUser = await request
    .get('/user', { baseUrl, jar, json: true })
    .then((r) => r.body);
  const currentSession = await request
    .get('/session', { baseUrl, jar, json: true })
    .then((r) => r.body);
  const tokens = await request
    .get('/tokens', { baseUrl, jar, json: true })
    .then((r) => r.body);

  nock.removeInterceptor(interceptor);

  return {
    baseUrl,
    jar,
    response,
    currentUser,
    currentSession,
    tokenReqHeader,
    tokenReqBody,
    tokens,
    existingSessionCookie,
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
    assert.equal(err.message, 'state missing from the response');
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
    assert.equal(err.message, 'checks.state argument is missing');
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
    assert.match(err.message, /state mismatch/i);
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
    assert.equal(
      err.message,
      'failed to decode JWT (JWTMalformed: JWTs must have three components)'
    );
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
        id_token: jose.JWT.sign({ sub: '__test_sub__' }, 'secret', {
          algorithm: 'HS256',
        }),
      },
    });
    assert.equal(statusCode, 400);
    assert.match(err.message, /unexpected JWT alg received/i);
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
        id_token: makeIdToken({ iss: undefined }),
      },
    });
    assert.equal(statusCode, 400);
    assert.match(err.message, /missing required JWT property iss/i);
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
        id_token: makeIdToken(),
      },
    });
    assert.equal(statusCode, 400);
    assert.match(err.message, /nonce mismatch/i);
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
        _auth_verification: JSON.stringify({ state: '__test_state__' }),
      },
      body: {
        state: '__test_state__',
        id_token: '__invalid_token__',
      },
    });
    assert.equal(statusCode, 400);
    assert.equal(err.message, 'checks.state argument is missing');
  });

  it('should use legacy samesite fallback', async () => {
    const { currentUser } = await setup({
      authOpts: {
        identityClaimFilter: [],
      },
      cookies: {
        _auth_verification: JSON.stringify({
          state: expectedDefaultState,
          nonce: '__test_nonce__',
        }),
      },
      body: {
        state: expectedDefaultState,
        id_token: makeIdToken(),
      },
    });

    assert.exists(currentUser);
  });

  it('should not strip claims when using custom claim filtering', async () => {
    const { currentUser } = await setup({
      authOpts: {
        identityClaimFilter: [],
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: makeIdToken(),
      },
    });
    assert.equal(currentUser.iss, 'https://op.example.com/');
    assert.equal(currentUser.aud, clientID);
    assert.equal(currentUser.nonce, '__test_nonce__');
    assert.exists(currentUser.iat);
    assert.exists(currentUser.exp);
  });

  it('should expose the id token when id_token is valid', async () => {
    const idToken = makeIdToken();
    const {
      response: { statusCode, headers },
      currentUser,
      tokens,
    } = await setup({
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

  it("should expose all tokens when id_token is valid and response_type is 'code id_token'", async () => {
    const idToken = makeIdToken({
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
    assert.equal(tokens.idToken, idToken);
    assert.equal(tokens.refreshToken, '__test_refresh_token__');
    assert.include(tokens.accessToken, {
      access_token: '__test_access_token__',
      token_type: 'Bearer',
    });
    assert.include(tokens.idTokenClaims, {
      sub: '__test_sub__',
    });
  });

  it('should handle access token expiry', async () => {
    const clock = sinon.useFakeTimers({ toFake: ['Date'] });
    const idToken = makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });
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
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });
    assert.equal(tokens.accessToken.expires_in, 24 * hrSecs);
    clock.tick(4 * hrMs);
    const tokens2 = await request
      .get('/tokens', { baseUrl, jar, json: true })
      .then((r) => r.body);
    assert.equal(tokens2.accessToken.expires_in, 20 * hrSecs);
    assert.isFalse(tokens2.accessTokenExpired);
    clock.tick(21 * hrMs);
    const tokens3 = await request
      .get('/tokens', { baseUrl, jar, json: true })
      .then((r) => r.body);
    assert.isTrue(tokens3.accessTokenExpired);
    clock.restore();
  });

  it('should refresh an access token', async () => {
    const idToken = makeIdToken({
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

    const reply = sinon.spy(() => ({
      access_token: '__new_access_token__',
      refresh_token: '__new_refresh_token__',
      id_token: tokens.idToken,
      token_type: 'Bearer',
      expires_in: 86400,
    }));
    const {
      interceptors: [interceptor],
    } = nock('https://op.example.com', { allowUnmocked: true })
      .post('/oauth/token')
      .reply(200, reply);

    const newTokens = await request
      .get('/refresh', { baseUrl, jar, json: true })
      .then((r) => r.body);
    nock.removeInterceptor(interceptor);

    sinon.assert.calledWith(
      reply,
      '/oauth/token',
      'grant_type=refresh_token&refresh_token=__test_refresh_token__'
    );

    assert.equal(tokens.accessToken.access_token, '__test_access_token__');
    assert.equal(tokens.refreshToken, '__test_refresh_token__');
    assert.equal(newTokens.accessToken.access_token, '__new_access_token__');
    assert.equal(newTokens.refreshToken, '__new_refresh_token__');

    const newerTokens = await request
      .get('/tokens', { baseUrl, jar, json: true })
      .then((r) => r.body);

    assert.equal(
      newerTokens.accessToken.access_token,
      '__new_access_token__',
      'the new access token should be persisted in the session'
    );
  });

  it('should refresh an access token and keep original refresh token', async () => {
    const idToken = makeIdToken({
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

    const reply = sinon.spy(() => ({
      access_token: '__new_access_token__',
      id_token: tokens.id_token,
      token_type: 'Bearer',
      expires_in: 86400,
    }));
    const {
      interceptors: [interceptor],
    } = nock('https://op.example.com', { allowUnmocked: true })
      .post('/oauth/token')
      .reply(200, reply);

    const newTokens = await request
      .get('/refresh', { baseUrl, jar, json: true })
      .then((r) => r.body);
    nock.removeInterceptor(interceptor);

    sinon.assert.calledWith(
      reply,
      '/oauth/token',
      'grant_type=refresh_token&refresh_token=__test_refresh_token__'
    );

    assert.equal(tokens.accessToken.access_token, '__test_access_token__');
    assert.equal(tokens.refreshToken, '__test_refresh_token__');
    assert.equal(newTokens.accessToken.access_token, '__new_access_token__');
    assert.equal(newTokens.refreshToken, '__test_refresh_token__');
  });

  it('should refresh an access token and pass tokenEndpointParams and refresh argument params to the request', async () => {
    const idToken = makeIdToken({
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

    const { tokens, jar, tokenReqBody } = await setup({
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

    const reply = sinon.spy(() => ({
      access_token: '__new_access_token__',
      refresh_token: '__new_refresh_token__',
      id_token: tokens.idToken,
      token_type: 'Bearer',
      expires_in: 86400,
    }));
    const {
      interceptors: [interceptor],
    } = nock('https://op.example.com', { allowUnmocked: true })
      .post('/oauth/token')
      .reply(200, reply);

    const newTokens = await request
      .get('/refresh', { baseUrl, jar, json: true })
      .then((r) => r.body);
    nock.removeInterceptor(interceptor);

    sinon.assert.calledWith(
      reply,
      '/oauth/token',
      'longeLiveToken=true&force=true&grant_type=refresh_token&refresh_token=__test_refresh_token__'
    );

    assert.equal(tokens.accessToken.access_token, '__test_access_token__');
    assert.equal(tokens.refreshToken, '__test_refresh_token__');
    assert.equal(newTokens.accessToken.access_token, '__new_access_token__');
    assert.equal(newTokens.refreshToken, '__new_refresh_token__');
    assert.match(tokenReqBody, /longeLiveToken=true/);

    const newerTokens = await request
      .get('/tokens', { baseUrl, jar, json: true })
      .then((r) => r.body);

    assert.equal(
      newerTokens.accessToken.access_token,
      '__new_access_token__',
      'the new access token should be persisted in the session'
    );
  });

  it('should fetch userinfo', async () => {
    const idToken = makeIdToken({
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

    const {
      interceptors: [interceptor],
    } = nock('https://op.example.com', { allowUnmocked: true })
      .get('/userinfo')
      .reply(200, () => ({
        userInfo: true,
        sub: '__test_sub__',
      }));

    const userInfo = await request
      .get('/user-info', { baseUrl, jar, json: true })
      .then((r) => r.body);

    nock.removeInterceptor(interceptor);

    assert.deepEqual(userInfo, { userInfo: true, sub: '__test_sub__' });
  });

  it('should use basic auth on token endpoint when using code flow', async () => {
    const idToken = makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    const { tokenReqBody, tokenReqHeader } = await setup({
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

    const credentials = Buffer.from(
      tokenReqHeader.authorization.replace('Basic ', ''),
      'base64'
    );
    assert.equal(credentials, '__test_client_id__:__test_client_secret__');
    assert.match(
      tokenReqBody,
      /code=jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y/
    );
  });

  it('should resume silent logins when user successfully logs in', async () => {
    const idToken = makeIdToken();
    const jar = request.jar();
    jar.setCookie('skipSilentLogin=true', baseUrl);
    await setup({
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

  context('when afterCallack is configured', async () => {
    it('should allow modification of the session', async () => {
      const idToken = makeIdToken({
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
        afterCallback: async (req, res, session) => {
          const userInfo = await req.oidc.fetchUserInfo();
          return { ...session, ...userInfo };
        },
      };

      // userinfo endpoint will be returned to req.oidc.fetchUserInfo
      const {
        interceptors: [interceptor],
      } = nock('https://op.example.com', { allowUnmocked: true })
        .get('/userinfo')
        .reply(200, () => ({
          org_id: 'auth_org_123',
        }));

      const router = auth(authOpts);
      router.get('/session', async (req, res) => {
        res.json({ session: req['appSession'] });
      });

      const { jar } = await setup({
        router,
        authOpts: {
          clientSecret: '__test_client_secret__',
          authorizationParams: {
            response_type: 'code id_token',
            audience: 'https://api.example.com/',
            scope: 'openid profile email',
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

      nock.removeInterceptor(interceptor);

      const body = await request
        .get('/session', { baseUrl, jar, json: true })
        .then((r) => r.body);

      assert.deepEqual(body.session.org_id, 'auth_org_123');
    });

    it('should allow thrown error to fail the request', async () => {
      const idToken = makeIdToken({
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
        afterCallback: async () => {
          throw { status: 999 };
        },
      };
      const {
        response: { statusCode },
      } = await setup({
        router: auth(authOpts),
        authOpts,
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

      assert.equal(statusCode, 999);
    });
  });

  it('should replace the cookie session when a new user is logging in over an existing different user', async () => {
    const { currentSession, currentUser } = await setup({
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: makeIdToken({ sub: 'bar' }),
      },
      existingSession: {
        shoppingCartId: 'bar',
        id_token: makeIdToken({ sub: 'foo' }),
      },
    });

    assert.equal(currentUser.sub, 'bar');
    assert.isUndefined(currentSession.shoppingCartId);
  });

  it('should preserve the cookie session when a new user is logging in over an anonymous session', async () => {
    const { currentSession, currentUser } = await setup({
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: makeIdToken({ sub: 'foo' }),
      },
      existingSession: {
        shoppingCartId: 'bar',
      },
    });

    assert.equal(currentUser.sub, 'foo');
    assert.equal(currentSession.shoppingCartId, 'bar');
  });

  it('should preserve session but regenerate session id when a new user is logging in over an anonymous session', async () => {
    const store = new MemoryStore({
      checkPeriod: 24 * 60 * 1000,
    });
    const { currentSession, currentUser, existingSessionCookie, jar } = await setup({
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: makeIdToken({ sub: 'foo' }),
      },
      existingSession: {
        shoppingCartId: 'bar',
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
      'There should only be one session in the store'
    );
    assert.notEqual(existingSessionCookie.value, newSessionCookie.value);
  });

  it('should preserve session when the same user is logging in over their existing session', async () => {
    const store = new MemoryStore({
      checkPeriod: 24 * 60 * 1000,
    });
    const { currentSession, currentUser, existingSessionCookie, jar } = await setup({
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: makeIdToken({ sub: 'foo' }),
      },
      existingSession: {
        shoppingCartId: 'bar',
        id_token: makeIdToken({ sub: 'foo' }),
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
      'There should only be one session in the store'
    );
    assert.equal(existingSessionCookie.value, newSessionCookie.value);
  });

  it('should regenerate the session when a new user is logging in over an existing different user', async () => {
    const store = new MemoryStore({
      checkPeriod: 24 * 60 * 1000,
    });
    const { currentSession, currentUser, existingSessionCookie, jar } = await setup({
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: makeIdToken({ sub: 'bar' }),
      },
      existingSession: {
        shoppingCartId: 'bar',
        id_token: makeIdToken({ sub: 'foo' }),
      },
      authOpts: {
        session: {
          store,
        },
      },
    });

    const cookies = jar.getCookies(baseUrl);
    const newSessionCookie = cookies.find(({ key }) => key === 'appSession');
    
    assert.equal(currentUser.sub, 'bar');
    assert.isUndefined(currentSession.shoppingCartId);
    assert.equal(
      store.store.length,
      1,
      'There should only be one session in the store'
    );
    assert.notEqual(existingSessionCookie.value, newSessionCookie.value);
  });
});

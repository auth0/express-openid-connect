const assert = require('chai').assert;
const sinon = require('sinon');
const jose = require('jose');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});

const TransientCookieHandler = require('../lib/transientHandler');
const { encodeState } = require('../lib/hooks/getLoginState');
const expressOpenid = require('..');
const { create: createServer } = require('./fixture/server');
const cert = require('./fixture/cert');
const clientID = '__test_client_id__';
const expectedDefaultState = encodeState({ returnTo: 'https://example.org' });
const nock = require('nock');

const baseUrl = 'http://localhost:3000';
let server;

const setup = async (params) => {
  const authOpts = Object.assign(
    {},
    {
      secret: '__test_session_secret__',
      clientID: clientID,
      baseURL: 'https://example.org',
      issuerBaseURL: 'https://op.example.com',
      authRequired: false,
    },
    params.authOpts || {}
  );
  const router = expressOpenid.auth(authOpts);
  const transient = new TransientCookieHandler(authOpts);

  const jar = request.jar();
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

  const response = await request.post('/callback', {
    baseUrl,
    jar,
    json: params.body,
  });
  const currentUser = await request
    .get('/user', { baseUrl, jar, json: true })
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
    tokenReqHeader,
    tokenReqBody,
    tokens,
  };
};

function makeIdToken(payload) {
  payload = Object.assign(
    {
      nickname: '__test_nickname__',
      sub: '__test_sub__',
      iss: 'https://op.example.com/',
      aud: clientID,
      iat: Math.round(Date.now() / 1000),
      exp: Math.round(Date.now() / 1000) + 60000,
      nonce: '__test_nonce__',
    },
    payload
  );

  return jose.JWT.sign(payload, cert.key, {
    algorithm: 'RS256',
    header: { kid: cert.kid },
  });
}

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
      cookies: {
        nonce: '__test_nonce__',
        state: '__test_state__',
      },
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
      cookies: {
        nonce: '__test_nonce__',
        state: '__valid_state__',
      },
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
      cookies: {
        nonce: '__test_nonce__',
        state: '__test_state__',
      },
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
      cookies: {
        nonce: '__test_nonce__',
        state: '__test_state__',
      },
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
      cookies: {
        nonce: '__test_nonce__',
        state: '__test_state__',
      },
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
      cookies: {
        state: '__test_state__',
      },
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
        // Only set the fallback cookie value.
        _state: '__test_state__',
      },
      body: {
        state: '__test_state__',
        id_token: '__invalid_token__',
      },
    });
    assert.equal(statusCode, 400);
    assert.equal(err.message, 'checks.state argument is missing');
  });

  it('should not strip claims when using custom claim filtering', async () => {
    const { currentUser } = await setup({
      authOpts: {
        identityClaimFilter: [],
      },
      cookies: {
        _state: expectedDefaultState,
        _nonce: '__test_nonce__',
      },
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
      cookies: {
        _state: expectedDefaultState,
        _nonce: '__test_nonce__',
      },
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
      cookies: {
        _state: expectedDefaultState,
        _nonce: '__test_nonce__',
      },
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
      cookies: {
        _state: expectedDefaultState,
        _nonce: '__test_nonce__',
      },
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
      cookies: {
        _state: expectedDefaultState,
        _nonce: '__test_nonce__',
      },
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
});

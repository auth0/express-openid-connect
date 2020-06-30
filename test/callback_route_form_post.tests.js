const assert = require('chai').assert;
const jose = require('jose');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

const TransientCookieHandler = require('../lib/transientHandler');
const { encodeState } = require('../lib/hooks/getLoginState');
const expressOpenid = require('..');
const server = require('./fixture/server');
const cert = require('./fixture/cert');
const clientID = '__test_client_id__';
const expectedDefaultState = encodeState({ returnTo: 'https://example.org' });
const nock = require('nock');
const sinon = require('sinon');

function setup(params) {
  return async function () {
    const authOpts = Object.assign({}, {
      secret: '__test_session_secret__',
      clientID: clientID,
      baseURL: 'https://example.org',
      issuerBaseURL: 'https://op.example.com',
      authRequired: false
    }, params.authOpts || {});
    const router = expressOpenid.auth(authOpts);
    const transient = new TransientCookieHandler(authOpts);

    let baseUrl;

    const jar = request.jar();
    this.jar = jar;
    this.baseUrl = baseUrl = await server.create(router);

    Object.keys(params.cookies).forEach(function (cookieName) {
      let value;
      transient.store(cookieName, {}, {
        cookie(key, ...args) {
          if (key === cookieName) {
            value = args[0];
          }
        }
      }, { value: params.cookies[cookieName]});

      jar.setCookie(
        `${cookieName}=${value}; Max-Age=3600; Path=/; HttpOnly;`,
        baseUrl + '/callback'
      );
    });

    this.response = await request.post('/callback', { baseUrl, jar, json: params.body });
    this.currentUser = await request.get('/user', { baseUrl, jar, json: true }).then(r => r.body);
    this.tokens = await request.get('/tokens', { baseUrl, jar, json: true }).then(r => r.body);

  };
}

function makeIdToken (payload) {
  payload = Object.assign({
    nickname: '__test_nickname__',
    sub: '__test_sub__',
    iss: 'https://op.example.com/',
    aud: clientID,
    iat: Math.round(Date.now() / 1000),
    exp: Math.round(Date.now() / 1000) + 60000,
    nonce: '__test_nonce__'
  }, payload);

  return jose.JWT.sign(payload, cert.key, { algorithm: 'RS256', header: { kid: cert.kid } });
}

// For the purpose of this test the fake SERVER returns the error message in the body directly
// production application should have an error middleware.
// http://expressjs.com/en/guide/error-handling.html

describe('callback routes response_type: id_token, response_mode: form_post', function () {
  describe('when body is empty', function() {
    beforeEach(setup({
      cookies: {
        nonce: '__test_nonce__',
        state: '__test_state__'
      },
      body: true
    }));

    it('should return 400', function () {
      assert.equal(this.response.statusCode, 400);
    });

    it('should return the reason to the error handler', function () {
      assert.equal(this.response.body.err.message, 'state missing from the response');
    });
  });

  describe('when state is missing', function() {
    beforeEach(setup({
      cookies: {},
      body: {
        state: '__test_state__',
        id_token: '__invalid_token__'
      }
    }));

    it('should return 400', function () {
      assert.equal(this.response.statusCode, 400);
    });

    it('should return the reason to the error handler', function () {
      assert.equal(this.response.body.err.message, 'checks.state argument is missing');
    });
  });

  describe("when state doesn't match", function() {
    beforeEach(setup({
      cookies: {
        nonce: '__test_nonce__',
        state: '__valid_state__'
      },
      body: {
        state: '__invalid_state__'
      }
    }));

    it('should return 400', function () {
      assert.equal(this.response.statusCode, 400);
    });

    it('should return the reason to the error handler', function () {
      assert.match(this.response.body.err.message, /state mismatch/i);
    });
  });

  describe("when id_token can't be parsed", function() {
    beforeEach(setup({
      cookies: {
        nonce: '__test_nonce__',
        state: '__test_state__'
      },
      body: {
        state: '__test_state__',
        id_token: '__invalid_token__'
      }
    }));

    it('should return 400', function () {
      assert.equal(this.response.statusCode, 400);
    });

    it('should return the reason to the error handler', function () {
      assert.equal(
        this.response.body.err.message,
        'failed to decode JWT (JWTMalformed: JWTs must have three components)'
      );
    });
  });

  describe('when id_token has invalid alg', function() {
    beforeEach(setup({
      cookies: {
        nonce: '__test_nonce__',
        state: '__test_state__'
      },
      body: {
        state: '__test_state__',
        id_token: jose.JWT.sign({ sub: '__test_sub__' }, 'secret', { algorithm: 'HS256' })
      }
    }));

    it('should return 400', function () {
      assert.equal(this.response.statusCode, 400);
    });

    it('should return the reason to the error handler', function () {
      assert.match(this.response.body.err.message, /unexpected JWT alg received/i);
    });
  });

  describe('when id_token is missing issuer', function() {
    beforeEach(setup({
      cookies: {
        nonce: '__test_nonce__',
        state: '__test_state__'
      },
      body: {
        state: '__test_state__',
        id_token: makeIdToken({ iss: undefined })
      }
    }));

    it('should return 400', function () {
      assert.equal(this.response.statusCode, 400);
    });

    it('should return the reason to the error handler', function () {
      assert.match(this.response.body.err.message, /missing required JWT property iss/i);
    });
  });

  describe('when nonce is missing from cookies', function() {
    beforeEach(setup({
      cookies: {
        state: '__test_state__'
      },
      body: {
        state: '__test_state__',
        id_token: makeIdToken()
      }
    }));

    it('should return the reason to the error handler', function () {
      assert.match(this.response.body.err.message, /nonce mismatch/i);
    });
  });

  describe('when id_token is valid', function() {
    const idToken = makeIdToken();

    beforeEach(setup({
      cookies: {
        _state: expectedDefaultState,
        _nonce: '__test_nonce__'
      },
      body: {
        state: expectedDefaultState,
        id_token: idToken
      }
    }));

    it('should return 302', function () {
      assert.equal(this.response.statusCode, 302);
    });

    it('should redirect to the intended url', function () {
      assert.equal(this.response.headers.location, 'https://example.org');
    });

    it('should contain the claims in the current session', function () {
      assert.ok(this.currentUser);
      assert.equal(this.currentUser.sub, '__test_sub__');
      assert.equal(this.currentUser.nickname, '__test_nickname__');
    });

    it('should strip validation claims from the ID tokens', function () {
      assert.notExists(this.currentUser.iat);
      assert.notExists(this.currentUser.iss);
      assert.notExists(this.currentUser.aud);
      assert.notExists(this.currentUser.exp);
      assert.notExists(this.currentUser.nonce);
    });

    it('should expose the tokens in the request', async function () {
      assert.equal(this.tokens.isAuthenticated, true);
      assert.equal(this.tokens.idToken, idToken);
      assert.isUndefined(this.tokens.refreshToken);
      assert.isUndefined(this.tokens.accessToken);
      assert.include(this.tokens.idTokenClaims, {
        sub: '__test_sub__'
      });
    });
  });

  describe('when legacy samesite fallback is off', function() {
    beforeEach(setup({
      authOpts: {
        // Do not check the fallback cookie value.
        legacySameSiteCookie: false
      },
      cookies: {
        // Only set the fallback cookie value.
        _state: '__test_state__'
      },
      body: {
        state: '__test_state__',
        id_token: '__invalid_token__'
      }
    }));

    it('should return 400', function () {
      assert.equal(this.response.statusCode, 400);
    });

    it('should return the reason to the error handler', function () {
      assert.equal(this.response.body.err.message, 'checks.state argument is missing');
    });
  });

  describe('uses custom claim filtering', function() {
    beforeEach(setup({
      authOpts: {
        identityClaimFilter: []
      },
      cookies: {
        _state: expectedDefaultState,
        _nonce: '__test_nonce__'
      },
      body: {
        state: expectedDefaultState,
        id_token: makeIdToken()
      }
    }));

    it('should have previously-stripped claims', function () {
      assert.equal(this.currentUser.iss, 'https://op.example.com/');
      assert.equal(this.currentUser.aud, clientID);
      assert.equal(this.currentUser.nonce, '__test_nonce__');
      assert.exists(this.currentUser.iat);
      assert.exists(this.currentUser.exp);
    });
  });
});

describe('callback routes response_type: code id_token, response_mode: form_post', function () {

  describe('when id_token is valid', function() {

    const idToken = makeIdToken();
    let requestSpy;

    beforeEach(function() {
      requestSpy = sinon.spy();
      nock('https://op.example.com', { allowUnmocked: true })
        .persist()
        .post('/oauth/token')
        .reply(200, function(uri, requestBody) {
          requestSpy(this.req, requestBody);
          return {
            access_token: '__test_access_token__',
            refresh_token: '__test_refresh_token__',
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 86400
          };
        });
    });

    beforeEach(setup({
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access'
        }
      },
      cookies: {
        _state: expectedDefaultState,
        _nonce: '__test_nonce__'
      },
      body: {
        state: expectedDefaultState,
        id_token: makeIdToken({
          c_hash: '77QmUPtjPfzWtF2AnpK9RQ'
        }),
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      }
    }));

    afterEach(() => {
      requestSpy = null;
    });

    it('should expose the tokens in the request', async function () {
      assert.equal(this.tokens.isAuthenticated, true);
      assert.equal(this.tokens.idToken, idToken);
      assert.equal(this.tokens.refreshToken, '__test_refresh_token__');
      assert.include(this.tokens.accessToken, {
        access_token: '__test_access_token__',
        token_type: 'Bearer'
      });
      assert.include(this.tokens.idTokenClaims, {
        sub: '__test_sub__'
      });
    });

    it('should call the token endpoint with Basic HTTP auth', async function () {
      const headers = requestSpy.firstCall.args[0].headers;
      const authHeader = Buffer.from(headers.authorization.replace('Basic ', ''), 'base64').toString();
      assert.equal(authHeader, '__test_client_id__:__test_client_secret__');
    });

    it('should call the token endpoint with code in the body', async function () {
      const body = requestSpy.firstCall.args[1];
      assert.match(body, /code=jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y/);
    });
  });

});

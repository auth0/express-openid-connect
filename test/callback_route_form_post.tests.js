const assert = require('chai').assert;
const jose = require('jose');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

const TransientCookieHandler = require('../lib/transientHandler');
const { encodeState } = require('../lib/hooks/getLoginState');
const expressOpenid = require('..');
const { create: createServer } = require('./fixture/server');
const cert = require('./fixture/cert');
const clientID = '__test_client_id__';
const expectedDefaultState = encodeState({ returnTo: 'https://example.org' });
const baseUrl = 'http://localhost:3000';

function testCase (params) {
  return () => {
    const authOpts = Object.assign({}, {
      secret: '__test_session_secret__',
      clientID: clientID,
      baseURL: 'https://example.org',
      issuerBaseURL: 'https://op.example.com',
      authRequired: false
    }, params.authOpts || {});
    const router = expressOpenid.auth(authOpts);
    const transient = new TransientCookieHandler(authOpts);
    let server;

    const jar = request.jar();

    before(async function () {
      this.jar = jar;
      server = await createServer(router);

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
    });

    after(() => {
      server.close();
    });

    params.assertions();
  };
}

function makeIdToken (payload) {
  if (typeof payload !== 'object') {
    payload = {
      nickname: '__test_nickname__',
      sub: '__test_sub__',
      iss: 'https://op.example.com/',
      aud: clientID,
      iat: Math.round(Date.now() / 1000),
      exp: Math.round(Date.now() / 1000) + 60000,
      nonce: '__test_nonce__'
    };
  }

  return jose.JWT.sign(payload, cert.key, { algorithm: 'RS256', header: { kid: cert.kid } });
}

// For the purpose of this test the fake SERVER returns the error message in the body directly
// production application should have an error middleware.
// http://expressjs.com/en/guide/error-handling.html

describe('callback routes response_type: id_token, response_mode: form_post', function () {
  describe('when body is empty', testCase({
    cookies: {
      nonce: '__test_nonce__',
      state: '__test_state__'
    },
    body: true,
    assertions () {
      it('should return 400', function () {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function () {
        assert.equal(this.response.body.err.message, 'state missing from the response');
      });
    }
  }));

  describe('when state is missing', testCase({
    cookies: {},
    body: {
      state: '__test_state__',
      id_token: '__invalid_token__'
    },
    assertions () {
      it('should return 400', function () {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function () {
        assert.equal(this.response.body.err.message, 'checks.state argument is missing');
      });
    }
  }));

  describe("when state doesn't match", testCase({
    cookies: {
      nonce: '__test_nonce__',
      state: '__valid_state__'
    },
    body: {
      state: '__invalid_state__'
    },
    assertions () {
      it('should return 400', function () {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function () {
        assert.match(this.response.body.err.message, /state mismatch/i);
      });
    }
  }));

  describe("when id_token can't be parsed", testCase({
    cookies: {
      nonce: '__test_nonce__',
      state: '__test_state__'
    },
    body: {
      state: '__test_state__',
      id_token: '__invalid_token__'
    },
    assertions () {
      it('should return 400', function () {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function () {
        assert.equal(
          this.response.body.err.message,
          'failed to decode JWT (JWTMalformed: JWTs must have three components)'
        );
      });
    }
  }));

  describe('when id_token has invalid alg', testCase({
    cookies: {
      nonce: '__test_nonce__',
      state: '__test_state__'
    },
    body: {
      state: '__test_state__',
      id_token: jose.JWT.sign({ sub: '__test_sub__' }, 'secret', { algorithm: 'HS256' })
    },
    assertions () {
      it('should return 400', function () {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function () {
        assert.match(this.response.body.err.message, /unexpected JWT alg received/i);
      });
    }
  }));

  describe('when id_token is missing issuer', testCase({
    cookies: {
      nonce: '__test_nonce__',
      state: '__test_state__'
    },
    body: {
      state: '__test_state__',
      id_token: makeIdToken({ sub: '__test_sub__' })
    },
    assertions () {
      it('should return 400', function () {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function () {
        assert.match(this.response.body.err.message, /missing required JWT property iss/i);
      });
    }
  }));

  describe('when nonce is missing from cookies', testCase({
    cookies: {
      state: '__test_state__'
    },
    body: {
      state: '__test_state__',
      id_token: makeIdToken()
    },
    assertions () {
      it('should return the reason to the error handler', function () {
        assert.match(this.response.body.err.message, /nonce mismatch/i);
      });
    }
  }));

  describe('when id_token is valid', testCase({
    cookies: {
      _state: expectedDefaultState,
      _nonce: '__test_nonce__'
    },
    body: {
      state: expectedDefaultState,
      id_token: makeIdToken()
    },
    assertions () {
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

      it('should expose the user in the request', async function () {
        const res = await request.get('/user', {
          baseUrl: baseUrl,
          json: true,
          jar: this.jar
        });
        assert.equal(res.body.nickname, '__test_nickname__');
      });
    }
  }));

  describe('when legacy samesite fallback is off', testCase({
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
    },
    assertions () {
      it('should return 400', function () {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function () {
        assert.equal(this.response.body.err.message, 'checks.state argument is missing');
      });
    }
  }));

  describe('uses custom claim filtering', testCase({
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
    },
    assertions () {
      it('should have previously-stripped claims', function () {
        assert.equal(this.currentUser.iss, 'https://op.example.com/');
        assert.equal(this.currentUser.aud, clientID);
        assert.equal(this.currentUser.nonce, '__test_nonce__');
        assert.exists(this.currentUser.iat);
        assert.exists(this.currentUser.exp);
      });
    }
  }));
});

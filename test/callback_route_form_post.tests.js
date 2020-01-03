const assert = require('chai').assert;
const jwt = require('jsonwebtoken');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

const expressOpenid = require('..');
const server = require('./fixture/server');
const cert = require('./fixture/cert');
const clientID = '__test_client_id__';

function testCase(params) {
  return () => {
    const authOpts = Object.assign({}, {
      appSessionSecret: '__test_session_secret__',
      clientID: clientID,
      baseURL: 'https://example.org',
      issuerBaseURL: 'https://test.auth0.com',
      required: false
    }, params.authOpts || {});
    const router = expressOpenid.auth(authOpts);

    let baseUrl;

    const jar = request.jar();

    before(async function() {
      this.jar = jar;
      this.baseUrl = baseUrl = await server.create(router);

      Object.keys(params.cookies).forEach(function(cookieName) {
        jar.setCookie(
          `${cookieName}=${params.cookies[cookieName]}; Max-Age=3600; Path=/; HttpOnly;`,
          baseUrl + '/callback',
        );
      });

      this.response = await request.post('/callback', {baseUrl, jar, json: params.body});
      this.currentUser = await request.get('/user', {baseUrl, jar, json: true}).then(r => r.body);
    });

    params.assertions();
  };
}

function makeIdToken(payload) {
  if (typeof payload !== 'object' ) {
    payload = {
      'nickname': '__test_nickname__',
      'sub': '__test_sub__',
      'iss': 'https://test.auth0.com/',
      'aud': clientID,
      'iat': Math.round(Date.now() / 1000),
      'exp': Math.round(Date.now() / 1000) + 60000,
      'nonce': '__test_nonce__'
    };
  }

  return jwt.sign(payload, cert.key, { algorithm: 'RS256', header: { kid: cert.kid } });
}

//For the purpose of this test the fake SERVER returns the error message in the body directly
//production application should have an error middleware.
//http://expressjs.com/en/guide/error-handling.html


describe('callback routes response_type: id_token, response_mode: form_post', function() {
  describe('when body is empty', testCase({
    cookies: {
      nonce: '__test_nonce__',
      state: '__test_state__'
    },
    body: true,
    assertions() {
      it('should return 400', function() {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function() {
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
    assertions() {
      it('should return 400', function() {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function() {
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
    assertions() {
      it('should return 400', function() {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function() {
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
    assertions() {
      it('should return 400', function() {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function() {
        assert.match(this.response.body.err.message, /unexpected token/i);
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
      id_token: jwt.sign({sub: '__test_sub__'}, '__invalid_alg__')
    },
    assertions() {
      it('should return 400', function() {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function() {
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
      id_token: makeIdToken({sub: '__test_sub__'})
    },
    assertions() {
      it('should return 400', function() {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function() {
        assert.match(this.response.body.err.message, /missing required JWT property iss/i);
      });
    }
  }));

  describe('when nonce is missing from cookies', testCase({
    cookies: {
      state: '__test_state__',
      returnTo: '/return-to'
    },
    body: {
      state: '__test_state__',
      id_token: makeIdToken()
    },
    assertions() {
      it('should return the reason to the error handler', function() {
        assert.match(this.response.body.err.message, /nonce mismatch/i);
      });
    }
  }));

  describe('when id_token is valid', testCase({
    cookies: {
      _state: '__test_state__',
      _nonce: '__test_nonce__',
      _returnTo: '/return-to'
    },
    body: {
      state: '__test_state__',
      id_token: makeIdToken()
    },
    assertions() {
      it('should return 302', function() {
        assert.equal(this.response.statusCode, 302);
      });

      it('should redirect to the intended url', function() {
        assert.equal(this.response.headers['location'], '/return-to');
      });

      it('should contain the claims in the current session', function() {
        assert.ok(this.currentUser);
        assert.equal(this.currentUser.sub, '__test_sub__');
        assert.equal(this.currentUser.nickname, '__test_nickname__');
      });

      it('should strip validation claims from the ID tokens', function() {
        assert.notExists(this.currentUser.iat);
        assert.notExists(this.currentUser.iss);
        assert.notExists(this.currentUser.aud);
        assert.notExists(this.currentUser.exp);
        assert.notExists(this.currentUser.nonce);
      });

      it('should expose the user in the request', async function() {
        const res = await request.get('/user', {
          baseUrl: this.baseUrl,
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
    assertions() {
      it('should return 400', function() {
        assert.equal(this.response.statusCode, 400);
      });

      it('should return the reason to the error handler', function() {
        assert.equal(this.response.body.err.message, 'checks.state argument is missing');
      });
    }
  }));

  describe('uses custom callback handling', testCase({
    authOpts: {
      handleCallback: () => {
        throw new Error('__test_callback_error__');
      }
    },
    cookies: {
      _state: '__test_state__',
      _nonce: '__test_nonce__'
    },
    body: {
      state: '__test_state__',
      id_token: makeIdToken()
    },
    assertions() {
      it('throws an error from the custom handler', function() {
        assert.equal(this.response.body.err.message, '__test_callback_error__');
      });
    }
  }));

  describe('uses custom claim filtering', testCase({
    authOpts: {
      identityClaimFilter: []
    },
    cookies: {
      _state: '__test_state__',
      _nonce: '__test_nonce__'
    },
    body: {
      state: '__test_state__',
      id_token: makeIdToken()
    },
    assertions() {
      it('should have previously-stripped claims', function() {
        assert.equal(this.currentUser.iss, 'https://test.auth0.com/');
        assert.equal(this.currentUser.aud, clientID);
        assert.equal(this.currentUser.nonce, '__test_nonce__');
        assert.exists(this.currentUser.iat);
        assert.exists(this.currentUser.exp);
      });
    }
  }));

});

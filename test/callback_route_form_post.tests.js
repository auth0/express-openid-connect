const assert = require('chai').assert;
const jwt = require('jsonwebtoken');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

const expressOpenid = require('..');
const server = require('./fixture/server');
const cert = require('./fixture/cert');
const clientID = 'foobar';

function testCase(params) {
  return () => {
    const router = expressOpenid.auth({
      clientID: clientID,
      baseURL: 'https://myapp.com',
      issuerBaseURL: 'https://flosser.auth0.com',
      required: false
    });

    let baseUrl;

    const jar = request.jar();

    before(async function() {
      this.jar = jar;
      this.baseUrl = baseUrl = await server.create(router);
      await request.post({
        uri: '/session',
        baseUrl, jar,
        json: params.session
      });
    });

    before(async function() {
      this.response = await request.post('/callback', {
        baseUrl,
        jar,
        json: params.body
      });
    });

    before(async function() {
      this.currentSession = await request.get('/session', {
        baseUrl,
        jar,
        json: true,
      }).then(r => r.body);
    });

    params.assertions();
  };
}

//For the purpose of this test the fake SERVER returns the error message in the body directly
//production application should have an error middleware.
//http://expressjs.com/en/guide/error-handling.html


describe('callback routes response_type: id_token, response_mode: form_post', function() {
  describe('when body is empty', testCase({
    session: {
      nonce: '123',
      state: '123'
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

  describe("when state doesn't match", testCase({
    session: {
      nonce: '123',
      state: '123'
    },
    body: {
      nonce: '123',
      state: '456',
      id_token: 'sioua'
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
    session: {
      nonce: '123',
      state: '123'
    },
    body: {
      nonce: '123',
      state: '123',
      id_token: 'sioua'
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
    session: {
      nonce: '123',
      state: '123'
    },
    body: {
      nonce: '123',
      state: '123',
      id_token: jwt.sign({ foo: '123'}, 'f00')
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
    session: {
      nonce: '123',
      state: '123'
    },
    body: {
      nonce: '123',
      state: '123',
      id_token: jwt.sign({ foo: '123'}, cert.key, { algorithm: 'RS256' })
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

  describe('when id_token is valid', testCase({
    session: {
      state: '123',
      nonce: 'abcdefg',
      returnTo: '/foobar'
    },
    body: {
      nonce: '123',
      state: '123',
      id_token: jwt.sign({
        'nickname': 'jjjj',
        'name': 'Jeranio',
        'email': 'jjjj@example.com',
        'email_verified': true,
        'iss': 'https://flosser.auth0.com/',
        'sub': 'xasdas',
        'aud': clientID,
        'iat': Math.round(Date.now() / 1000),
        'exp': Math.round(Date.now() / 1000) + 60000,
        'nonce': 'abcdefg'
      }, cert.key, { algorithm: 'RS256', header: { kid: cert.kid } })
    },
    assertions() {
      it('should return 302', function() {
        assert.equal(this.response.statusCode, 302);
      });

      it('should redirect to the intended url', function() {
        assert.equal(this.response.headers['location'], '/foobar');
      });

      it('should contain the claims in the current session', function() {
        assert.ok(this.currentSession.openidTokens);
      });

      it('should expose the user in the request', async function() {
        const res = await request.get('/user', {
          baseUrl: this.baseUrl,
          json: true,
          jar: this.jar
        });
        assert.equal(res.body.nickname, 'jjjj');
      });
    }
  }));

});

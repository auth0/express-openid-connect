const assert = require('chai').assert;
const got = require('got');
const jwt = require('jsonwebtoken');
const expressOpenid = require('./..');
const server = require('./fixture/server');
const { CookieJar } = require('tough-cookie');
const cert = require('./fixture/cert');
const clientID = 'foobar';

function testCase(params) {
  return () => {
    const router = expressOpenid.routes({
      clientID: clientID,
      baseURL: 'https://myapp.com',
      issuerBaseURL: 'https://flosser.auth0.com',
    });

    let baseUrl;

    const cookieJar = new CookieJar();

    before(async function() {
      baseUrl = await server.create(router);
      await got.post('/session', {
        baseUrl,
        cookieJar,
        json: true,
        body: params.session
      });
    });

    before(async function() {
      this.response = await got.post('/callback', {
        baseUrl,
        cookieJar,
        json: true,
        throwHttpErrors: false,
        body: params.body
      });
    });

    before(async function() {
      this.currentSession = await got.get('/session', {
        baseUrl,
        cookieJar,
        json: true,
        throwHttpErrors: false,
      }).then(r => r.body);
    });

    params.assertions();
  };
}

describe('callback router', function() {
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
      it('should return 401', function() {
        assert.equal(this.response.statusCode, 401);
      });

      it('should return the reason to the error handler', function() {
        assert.equal(this.response.body.err.message, 'state mismatch');
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
      it('should return 401', function() {
        assert.equal(this.response.statusCode, 401);
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
      it('should return 401', function() {
        assert.equal(this.response.statusCode, 401);
      });

      it('should return the reason to the error handler', function() {
        assert.match(this.response.body.err.message, /unexpected algo/i);
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
      it('should return 401', function() {
        assert.equal(this.response.statusCode, 401);
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
        assert.equal(this.currentSession.user.name, 'Jeranio');
        assert.equal(this.currentSession.user.sub, 'xasdas');
      });
    }
  }));

});

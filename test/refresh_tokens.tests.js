const proxyquire = require('proxyquire');
const { assert } = require('chai');
const sinon = require('sinon');
const server = require('./fixture/server');
const protect = require('../middleware/requiresAuth');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

describe('refresh token', function() {
  describe('when the token is expired', function() {
    let baseUrl;

    let tokens = {
      refresh_token: 'the refresh token',
      access_token: 'the access token',
      id_token: 'the id token',
      expires_at: Math.floor(Date.now() / 1000) -5
    };

    let refreshStub = sinon.stub().returns({
      access_token: 'the new access token',
      id_token: 'the new id token',
      expires_at: Math.floor(Date.now() / 1000) + 1000
    });

    let protectedResp;

    const jar = request.jar();

    before(async function() {
      const getClientStub =  {
        get: () => {
          return {
            refresh: refreshStub
          };
        },
      };
      const routes = proxyquire('../middleware/auth', {
        '../lib/client': getClientStub,
        '../lib/context': proxyquire('../lib/context', {
          './client': getClientStub
        })
      })({
        clientID: '123',
        baseURL: 'https://myapp.com',
        issuerBaseURL: 'https://flosser.auth0.com',
        getUser: () => ({ sub: 123, email: 'j@example.com' }),
        required: false
      });

      baseUrl = await server.create(routes, protect());
      let req = request.defaults({ baseUrl, jar });

      await req.post({
        uri: '/session',
        json: {
          openidTokens: tokens
        }
      });

      protectedResp = (await req({ uri: '/protected', json: true })).body;

      tokens = (await req({ uri: '/session', json: true })).body.openidTokens;
    });

    it('should call refresh', function() {
      assert.ok(refreshStub.called);
    });

    it('should update the access_token in the session', function() {
      assert.equal(tokens.access_token, 'the new access token');
    });

    it('should update the id_token in the session', function() {
      assert.equal(tokens.id_token, 'the new id token');
    });

    it('should preserve the refresh_token in the session', function() {
      assert.equal(tokens.refresh_token, 'the refresh token');
    });

    it('should provide the new access_token in the req object', function() {
      assert.equal(protectedResp.access_token, 'the new access token');
    });
  });


});

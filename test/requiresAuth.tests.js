const { assert } = require('chai');
const server = require('./fixture/server');
const { auth, requiresAuth } = require('./..');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
  followRedirect: false
});

describe('requiresAuth middleware', function() {
  describe('when trying to access a protected route without being logged in', function() {
    let baseUrl;
    let response;

    before(async function() {
      const router = auth({
        appSessionSecret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://test.auth0.com',
        required: false
      });
      baseUrl = await server.create(router, requiresAuth());
      response = await request({ baseUrl, url: '/protected' });
    });

    it('should return a 302', function() {
      assert.equal(response.statusCode, 302);
    });
    it('should contain a location header to the issuer', function() {
      assert.include(response.headers.location, 'https://test.auth0.com');
    });
  });

  describe('when removing the auth middleware', function() {
    let baseUrl;
    let response;

    before(async function() {
      const router = (req, res, next) => next();
      baseUrl = await server.create(router, requiresAuth());
      response = await request({ baseUrl, url: '/protected' });
    });

    it('should return a 401', function() {
      assert.equal(response.statusCode, 401);
    });
  });

  describe('when requiring auth in a route', function() {
    let baseUrl;
    let response;

    before(async function() {
      const router = auth({
        appSessionSecret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://test.auth0.com',
        required: false,
        errorOnRequiredAuth: true
      });
      baseUrl = await server.create(router, requiresAuth());
      response = await request({ baseUrl, url: '/protected' });
    });

    it('should return a 401', function() {
      assert.equal(response.statusCode, 401);
    });
  });

});

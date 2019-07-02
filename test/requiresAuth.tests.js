const { assert } = require('chai');
const server = require('./fixture/server');
const { auth, requiresAuth } = require('./..');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
  followRedirect: false
});
const Keygrip = require('keygrip');

describe('requiresAuth middleware', function() {
  describe('when trying to access a protected route without being logged in', function() {
    let baseUrl;
    let response;

    before(async function() {
      const router = auth({
        clientID: '123',
        baseURL: 'https://myapp.com',
        issuerBaseURL: 'https://flosser.auth0.com',
        required: false
      });
      baseUrl = await server.create(router, requiresAuth());
      response = await request({ baseUrl, url: '/protected' });
    });

    it('should return a 302', function() {
      assert.equal(response.statusCode, 302);
    });
    it('should contain a location header to the issuer', function() {
      assert.include(response.headers.location, 'https://flosser.auth0.com');
    });
  });

  describe('when trying to access a protected route with expired token set', function() {
    let baseUrl;
    let response;

    before(async function() {
      const router = auth({
        clientID: '123',
        baseURL: 'https://myapp.com',
        issuerBaseURL: 'https://flosser.auth0.com',
        required: false
      });
      let cookie = Buffer.from(JSON.stringify({
        openidTokens: {
          expires_at: Math.floor(new Date(Date.now() - 24 * 3600 * 1000).getTime() / 1000),
          id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'
        } })).toString('base64');
      let hash = Keygrip(['blabla']).sign('tests=' + cookie);
      baseUrl = await server.create(router, requiresAuth());
      const jar = request.jar();
      jar.setCookie(`tests=${cookie}`, baseUrl);
      jar.setCookie(`tests.sig=${hash}`, baseUrl);
      response = await request({ jar, baseUrl, url: '/protected' });
    });

    it('should return a 302', function() {
      assert.equal(response.statusCode, 302);
    });
    it('should contain a location header to the issuer', function() {
      assert.include(response.headers.location, 'https://flosser.auth0.com');
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
        clientID: '123',
        baseURL: 'https://myapp.com',
        issuerBaseURL: 'https://flosser.auth0.com',
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

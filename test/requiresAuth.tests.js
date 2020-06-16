const { assert } = require('chai');
const server = require('./fixture/server');
const { auth, requiresAuth } = require('./..');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
  followRedirect: false
});

describe('requiresAuth middleware', function () {
  describe('when trying to access a protected route without being logged in', function () {
    let baseUrl;
    let response;

    before(async function () {
      const router = auth({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://op.example.com',
        authRequired: false
      });
      baseUrl = await server.create(router, requiresAuth());
      response = await request({ baseUrl, url: '/protected' });
    });

    it('should return a 302', function () {
      assert.equal(response.statusCode, 302);
    });
    it('should contain a location header to the issuer', function () {
      assert.include(response.headers.location, 'https://op.example.com');
    });
    it('should contain a location header with state containing return url', function () {
      const state = (new URL(response.headers.location)).searchParams.get('state');
      const decoded = Buffer.from(state, 'base64');
      const parsed = JSON.parse(decoded);
      assert.equal(parsed.returnTo, '/protected');
    });
  });

  describe('when removing the auth middleware', function () {
    let baseUrl;
    let response;

    before(async function () {
      const router = (req, res, next) => next();
      baseUrl = await server.create(router, requiresAuth());
      response = await request({ baseUrl, url: '/protected' });
    });

    it('should return a 401', function () {
      const body = JSON.parse(response.body);
      assert.equal(response.statusCode, 500);
      assert.ok(body.err);
      assert.equal(body.err.message, 'req.oidc is not found, did you include the auth middleware?');
    });
  });

  describe('when requiring auth in a route', function () {
    let baseUrl;
    let response;

    before(async function () {
      const router = auth({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://op.example.com',
        authRequired: false,
        errorOnRequiredAuth: true
      });
      baseUrl = await server.create(router, requiresAuth());
      response = await request({ baseUrl, url: '/protected' });
    });

    it('should return a 401', function () {
      assert.equal(response.statusCode, 401);
    });
  });
});

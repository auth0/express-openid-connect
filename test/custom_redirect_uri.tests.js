const assert = require('chai').assert;
const url = require('url');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

const expressOpenid = require('..');
const server = require('./fixture/server');
const filterRoute = (method, path) => {
  return r => r.route &&
              r.route.path === path &&
              r.route.methods[method.toLowerCase()];
};

describe('auth with redirectUriPath', function() {
  describe('default', () => {

    let baseUrl, router;

    before(async function() {
      router = expressOpenid.auth({
        appSessionSecret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://test.auth0.com',
        required: false,
        redirectUriPath: '/auth-finish'
      });
      baseUrl = await server.create(router);
    });

    it('should contain a callback route', function() {
      assert.ok(router.stack.some(filterRoute('POST', '/auth-finish')));
    });

    it('should have the correct redirect_uri parameter', async function() {
      const jar = request.jar();
      const res = await request.get('/login', { jar, baseUrl, followRedirect: false });
      assert.equal(res.statusCode, 302);
      const parsed = url.parse(res.headers.location, true);
      assert.equal(parsed.query.redirect_uri, 'https://example.org/auth-finish');
    });

  });

});

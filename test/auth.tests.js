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

const getCookieFromResponse = (res, cookieName) => {
  const cookieHeaders = res.headers['set-cookie'];

  const foundHeader = cookieHeaders.filter(header => header.substring(0,6) === cookieName + '=')[0];
  if (!foundHeader) {
    return false;
  }

  const cookieValuePart = foundHeader.split('; ')[0];
  if (!cookieValuePart) {
    return false;
  }

  return cookieValuePart.split('=')[1];
};

describe('auth', function() {
  describe('default', () => {

    let baseUrl, router;

    before(async function() {
      router = expressOpenid.auth({
        appSessionSecret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://test.auth0.com',
        required: false
      });
      baseUrl = await server.create(router);
    });

    it('should contain a login route', function() {
      assert.ok(router.stack.some(filterRoute('GET', '/login')));
    });

    it('should contain a logout route', function() {
      assert.ok(router.stack.some(filterRoute('GET', '/logout')));
    });

    it('should contain a callback route', function() {
      assert.ok(router.stack.some(filterRoute('POST', '/callback')));
    });

    it('should redirect to the authorize url properly on /login', async function() {
      const jar = request.jar();
      const res = await request.get('/login', { jar, baseUrl, followRedirect: false });
      assert.equal(res.statusCode, 302);

      const parsed = url.parse(res.headers.location, true);
      assert.equal(parsed.hostname, 'test.auth0.com');
      assert.equal(parsed.pathname, '/authorize');
      assert.equal(parsed.query.client_id, '__test_client_id__');
      assert.equal(parsed.query.scope, 'openid profile email');
      assert.equal(parsed.query.response_type, 'id_token');
      assert.equal(parsed.query.response_mode, 'form_post');
      assert.equal(parsed.query.redirect_uri, 'https://example.org/callback');
      assert.property(parsed.query, 'nonce');
      assert.property(parsed.query, 'state');

      const cookies = jar.getCookies(baseUrl + '/login');

      assert.equal(cookies.filter(cookie => cookie.key === '_nonce')[0].value, parsed.query.nonce);
      assert.equal(cookies.filter(cookie => cookie.key === '_state')[0].value, parsed.query.state);
    });

  });

  describe('implied response_mode', () => {
    describe('response_type=none', () => {
      let baseUrl, router;

      before(async function() {
        router = expressOpenid.auth({
          appSessionSecret: '__test_session_secret__',
          clientID: '__test_client_id__',
          baseURL: 'https://example.org',
          issuerBaseURL: 'https://test.auth0.com',
          authorizationParams: {
            response_mode: undefined,
            response_type: 'none',
          },
          required: false
        });
        baseUrl = await server.create(router);
      });

      it('should redirect to the authorize url properly on /login', async function() {
        const cookieJar = request.jar();
        const res = await request.get('/login', { cookieJar, baseUrl, followRedirect: false });
        assert.equal(res.statusCode, 302);

        const parsed = url.parse(res.headers.location, true);

        assert.equal(parsed.hostname, 'test.auth0.com');
        assert.equal(parsed.pathname, '/authorize');
        assert.equal(parsed.query.client_id, '__test_client_id__');
        assert.equal(parsed.query.scope, 'openid profile email');
        assert.equal(parsed.query.response_type, 'none');
        assert.equal(parsed.query.response_mode, undefined);
        assert.equal(parsed.query.redirect_uri, 'https://example.org/callback');
        assert.property(parsed.query, 'nonce');
        assert.property(parsed.query, 'state');
      });

      it('should contain a callback route', function() {
        assert.ok(router.stack.some(filterRoute('GET', '/callback')));
      });
    });

    describe('response_type=code', () => {
      let baseUrl;
      let router;

      before(async function() {
        router = expressOpenid.auth({
          appSessionSecret: '__test_session_secret__',
          clientID: '__test_client_id__',
          clientSecret: '__test_client_secret__',
          baseURL: 'https://example.org',
          issuerBaseURL: 'https://test.auth0.com',
          authorizationParams: {
            response_mode: undefined,
            response_type: 'code',
          }
        });
        baseUrl = await server.create(router);
      });


      it('should redirect to the authorize url properly on /login', async function() {
        const cookieJar = request.jar();
        const res = await request.get('/login', { cookieJar, baseUrl, followRedirect: false });
        assert.equal(res.statusCode, 302);

        const parsed = url.parse(res.headers.location, true);

        assert.equal(parsed.hostname, 'test.auth0.com');
        assert.equal(parsed.pathname, '/authorize');
        assert.equal(parsed.query.client_id, '__test_client_id__');
        assert.equal(parsed.query.scope, 'openid profile email');
        assert.equal(parsed.query.response_type, 'code');
        assert.equal(parsed.query.response_mode, undefined);
        assert.equal(parsed.query.redirect_uri, 'https://example.org/callback');
        assert.property(parsed.query, 'nonce');
        assert.property(parsed.query, 'state');
        assert.property(res.headers, 'set-cookie');

        assert.equal(getCookieFromResponse(res, 'nonce'), parsed.query.nonce);
        assert.equal(getCookieFromResponse(res, 'state'), parsed.query.state);
      });

      it('should contain a callback route', function() {
        assert.ok(router.stack.some(filterRoute('GET', '/callback')));
      });
    });

    describe('response_type=id_token', () => {
      let router;
      let baseUrl;

      before(async function() {
        router = expressOpenid.auth({
          appSessionSecret: '__test_session_secret__',
          clientID: '__test_client_id__',
          baseURL: 'https://example.org',
          issuerBaseURL: 'https://test.auth0.com',
          authorizationParams: {
            response_mode: undefined,
            response_type: 'id_token',
          }
        });
        baseUrl = await server.create(router);
      });

      it('should redirect to the authorize url properly on /login', async function() {
        const cookieJar = request.jar();
        const res = await request.get('/login', { cookieJar, baseUrl, followRedirect: false });
        assert.equal(res.statusCode, 302);

        const parsed = url.parse(res.headers.location, true);

        assert.equal(parsed.hostname, 'test.auth0.com');
        assert.equal(parsed.pathname, '/authorize');
        assert.equal(parsed.query.client_id, '__test_client_id__');
        assert.equal(parsed.query.scope, 'openid profile email');
        assert.equal(parsed.query.response_type, 'id_token');
        assert.equal(parsed.query.response_mode, undefined);
        assert.equal(parsed.query.redirect_uri, 'https://example.org/callback');
        assert.property(parsed.query, 'nonce');
        assert.property(parsed.query, 'state');
      });

      it('should contain the two callbacks route', function() {
        assert.ok(router.stack.some(filterRoute('GET', '/callback')));
      });

    });
  });

  describe('custom path values', () => {

    let baseUrl, router;

    before(async function() {
      router = expressOpenid.auth({
        appSessionSecret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://test.auth0.com',
        redirectUriPath: 'custom-callback',
        loginPath: 'custom-login',
        logoutPath: 'custom-logout',
      });
      baseUrl = await server.create(router);
    });

    it('should contain the custom login route', function() {
      assert.ok(router.stack.some(filterRoute('GET', '/custom-login')));
    });

    it('should contain the custom logout route', function() {
      assert.ok(router.stack.some(filterRoute('GET', '/custom-logout')));
    });

    it('should contain the custom callback route', function() {
      assert.ok(router.stack.some(filterRoute('POST', '/custom-callback')));
    });

    it('should redirect to the authorize url properly on /login', async function() {
      const jar = request.jar();
      const res = await request.get('/custom-login', { jar, baseUrl, followRedirect: false });
      assert.equal(res.statusCode, 302);

      const parsed = url.parse(res.headers.location, true);
      assert.equal(parsed.hostname, 'test.auth0.com');
      assert.equal(parsed.pathname, '/authorize');
      assert.equal(parsed.query.redirect_uri, 'https://example.org/custom-callback');
    });

  });
});

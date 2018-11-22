const assert = require('chai').assert;
const url = require('url');
const got = require('got');
const fs = require('fs');
const expressOpenid = require('./..');
const server = require('./fixture/server');
const { CookieJar } = require('tough-cookie');

describe('routes', function() {
  describe('default', () => {
    const router = expressOpenid.routes({
      clientID: '123',
      baseURL: 'https://myapp.com',
      issuerBaseURL: 'https://flosser.auth0.com',
    });

    let baseUrl;

    before(async function() {
      baseUrl = await server.create(router);
    });

    it('should contain two routes', function() {
      assert.equal(router.stack.length, 2);
    });

    it('should contain a login route', function() {
      const route = router.stack[0].route;
      assert.equal(route.path, '/login');
      assert.deepEqual(route.methods, { get: true });
    });

    it('should redirect to the authorize url properly on /login', async function() {
      const cookieJar = new CookieJar();
      const res = await got('/login', { cookieJar, baseUrl, followRedirect: false });
      assert.equal(res.statusCode, 302);

      const parsed = url.parse(res.headers.location, true);
      assert.equal(parsed.hostname, 'flosser.auth0.com');
      assert.equal(parsed.pathname, '/authorize');
      assert.equal(parsed.query.client_id, '123');

      assert.equal(parsed.query.scope, 'openid profile email');
      assert.equal(parsed.query.response_type, 'id_token');
      assert.equal(parsed.query.response_mode, 'form_post');
      assert.equal(parsed.query.redirect_uri, 'https://myapp.com/callback');
      assert.property(parsed.query, 'nonce');
      assert.property(parsed.query, 'state');

      const session = (await got('/session', { cookieJar, baseUrl, json: true })).body;
      assert.equal(session.nonce, parsed.query.nonce);
      assert.equal(session.state, parsed.query.state);
    });

    it('should contain a POST callback route', function() {
      const route = router.stack[1].route;
      assert.equal(route.path, '/callback');
      assert.deepEqual(route.methods, { post: true });
    });
  });

  describe('implied response_mode', () => {
    describe('response_type=none', () => {
      const router = expressOpenid.routes({
        clientID: '123',
        baseURL: 'https://myapp.com',
        issuerBaseURL: 'https://flosser.auth0.com',
        authorizationParams: {
          response_mode: undefined,
          response_type: 'none',
        }
      });

      let baseUrl;

      before(async function() {
        baseUrl = await server.create(router);
      });

      it('should contain two routes', function() {
        assert.equal(router.stack.length, 2);
      });

      it('should contain a login route', function() {
        const route = router.stack[0].route;
        assert.equal(route.path, '/login');
        assert.deepEqual(route.methods, { get: true });
      });

      it('should redirect to the authorize url properly on /login', async function() {
        const cookieJar = new CookieJar();
        const res = await got('/login', { cookieJar, baseUrl, followRedirect: false });
        assert.equal(res.statusCode, 302);

        const parsed = url.parse(res.headers.location, true);

        assert.equal(parsed.hostname, 'flosser.auth0.com');
        assert.equal(parsed.pathname, '/authorize');
        assert.equal(parsed.query.client_id, '123');
        assert.equal(parsed.query.scope, 'openid profile email');
        assert.equal(parsed.query.response_type, 'none');
        assert.equal(parsed.query.response_mode, undefined);
        assert.equal(parsed.query.redirect_uri, 'https://myapp.com/callback');
        assert.property(parsed.query, 'nonce');
        assert.property(parsed.query, 'state');
      });

      it('should contain a GET callback route', function() {
        const route = router.stack[1].route;
        assert.equal(route.path, '/callback');
        assert.deepEqual(route.methods, { get: true });
      });
    });

    describe('response_type=code', () => {
      const router = expressOpenid.routes({
        clientID: '123',
        clientSecret: '456',
        baseURL: 'https://myapp.com',
        issuerBaseURL: 'https://flosser.auth0.com',
        authorizationParams: {
          response_mode: undefined,
          response_type: 'code',
        }
      });

      let baseUrl;

      before(async function() {
        baseUrl = await server.create(router);
      });

      it('should contain two routes', function() {
        assert.equal(router.stack.length, 2);
      });

      it('should contain a login route', function() {
        const route = router.stack[0].route;
        assert.equal(route.path, '/login');
        assert.deepEqual(route.methods, { get: true });
      });

      it('should redirect to the authorize url properly on /login', async function() {
        const cookieJar = new CookieJar();
        const res = await got('/login', { cookieJar, baseUrl, followRedirect: false });
        assert.equal(res.statusCode, 302);

        const parsed = url.parse(res.headers.location, true);

        assert.equal(parsed.hostname, 'flosser.auth0.com');
        assert.equal(parsed.pathname, '/authorize');
        assert.equal(parsed.query.client_id, '123');
        assert.equal(parsed.query.scope, 'openid profile email');
        assert.equal(parsed.query.response_type, 'code');
        assert.equal(parsed.query.response_mode, undefined);
        assert.equal(parsed.query.redirect_uri, 'https://myapp.com/callback');
        assert.property(parsed.query, 'nonce');
        assert.property(parsed.query, 'state');
      });

      it('should contain a GET callback route', function() {
        const route = router.stack[1].route;
        assert.equal(route.path, '/callback');
        assert.deepEqual(route.methods, { get: true });
      });
    });

    describe('response_type=id_token', () => {
      const router = expressOpenid.routes({
        clientID: '123',
        baseURL: 'https://myapp.com',
        issuerBaseURL: 'https://flosser.auth0.com',
        authorizationParams: {
          response_mode: undefined,
          response_type: 'id_token',
        }
      });

      let baseUrl;

      before(async function() {
        baseUrl = await server.create(router);
      });

      it('should contain two routes', function() {
        assert.equal(router.stack.length, 3);
      });

      it('should contain a login route', function() {
        const route = router.stack[0].route;
        assert.equal(route.path, '/login');
        assert.deepEqual(route.methods, { get: true });
      });

      it('should redirect to the authorize url properly on /login', async function() {
        const cookieJar = new CookieJar();
        const res = await got('/login', { cookieJar, baseUrl, followRedirect: false });
        assert.equal(res.statusCode, 302);

        const parsed = url.parse(res.headers.location, true);

        assert.equal(parsed.hostname, 'flosser.auth0.com');
        assert.equal(parsed.pathname, '/authorize');
        assert.equal(parsed.query.client_id, '123');
        assert.equal(parsed.query.scope, 'openid profile email');
        assert.equal(parsed.query.response_type, 'id_token');
        assert.equal(parsed.query.response_mode, undefined);
        assert.equal(parsed.query.redirect_uri, 'https://myapp.com/callback');
        assert.property(parsed.query, 'nonce');
        assert.property(parsed.query, 'state');
      });

      it('should contain a GET (repost) and POST callback route', function() {
        let route = router.stack[1].route;
        assert.equal(route.path, '/callback');
        assert.deepEqual(route.methods, { post: true });
        route = router.stack[2].route;
        assert.equal(route.path, '/callback');
        assert.deepEqual(route.methods, { get: true });
      });

      it('should return an html on GET /callback', async function() {
        const cookieJar = new CookieJar();
        const res = await got('/callback', { cookieJar, baseUrl, followRedirect: false });
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers['content-type'], 'text/html; charset=utf-8');
        const expectedBody = fs.readFileSync(`${__dirname}/../views/repost.html`, 'utf-8');
        assert.equal(res.body, expectedBody);
      });

    });
  });
});

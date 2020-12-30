const assert = require('chai').assert;
const url = require('url');
const querystring = require('querystring');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});

const { decodeState } = require('../lib/hooks/getLoginState');

const { auth } = require('..');
const { create: createServer } = require('./fixture/server');

const filterRoute = (method, path) => {
  return (r) =>
    r.route && r.route.path === path && r.route.methods[method.toLowerCase()];
};

const fetchFromAuthCookie = (res, cookieName) => {
  const cookieHeaders = res.headers['set-cookie'];
  const authCookie = cookieHeaders.filter(
    (header) => header.split('=')[0] === 'auth_verification'
  )[0];

  if (!authCookie) {
    return false
  }

  const decodedAuthCookie = querystring.decode(authCookie);
  const cookieValuePart = decodedAuthCookie.auth_verification.split('; ')[0].split('.')[0];
  const authCookieParsed = JSON.parse(cookieValuePart);

  return authCookieParsed[cookieName];
};

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'https://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
};

describe('auth', () => {
  let server;
  const baseUrl = 'http://localhost:3000';

  afterEach(async () => {
    if (server) {
      server.close();
    }
  });

  it('should contain the default authentication routes', async () => {
    const router = auth(defaultConfig);
    server = await createServer(router);
    assert.ok(router.stack.some(filterRoute('GET', '/login')));
    assert.ok(router.stack.some(filterRoute('GET', '/logout')));
    assert.ok(router.stack.some(filterRoute('POST', '/callback')));
    assert.ok(router.stack.some(filterRoute('GET', '/callback')));
  });

  it('should contain custom authentication routes', async () => {
    const router = auth({
      ...defaultConfig,
      routes: {
        callback: 'custom-callback',
        login: 'custom-login',
        logout: 'custom-logout',
      },
    });
    server = await createServer(router);
    assert.ok(router.stack.some(filterRoute('GET', '/custom-login')));
    assert.ok(router.stack.some(filterRoute('GET', '/custom-logout')));
    assert.ok(router.stack.some(filterRoute('POST', '/custom-callback')));
    assert.ok(router.stack.some(filterRoute('GET', '/custom-callback')));
  });

  it('should redirect to the authorize url for /login', async () => {
    server = await createServer(auth(defaultConfig));
    const res = await request.get('/login', { baseUrl, followRedirect: false });
    assert.equal(res.statusCode, 302);

    const parsed = url.parse(res.headers.location, true);
    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.query.client_id, '__test_client_id__');
    assert.equal(parsed.query.scope, 'openid profile email');
    assert.equal(parsed.query.response_type, 'id_token');
    assert.equal(parsed.query.response_mode, 'form_post');
    assert.equal(parsed.query.redirect_uri, 'https://example.org/callback');
    assert.property(parsed.query, 'nonce');
    assert.property(parsed.query, 'state');

    assert.equal(fetchFromAuthCookie(res, 'nonce'), parsed.query.nonce);
    assert.equal(fetchFromAuthCookie(res, 'state'), parsed.query.state);
  });

  it('should redirect to the authorize url for any route if authRequired', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: true,
      })
    );
    const res = await request.get('/session', {
      baseUrl,
      followRedirect: false,
    });
    assert.equal(res.statusCode, 302);
  });

  it('should redirect to the authorize url for any route if attemptSilentLogin', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        attemptSilentLogin: true,
      })
    );
    const res = await request.get('/session', {
      baseUrl,
      followRedirect: false,
    });
    assert.equal(res.statusCode, 302);
  });

  it('should redirect to the authorize url for /login in code flow', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code',
        },
      })
    );
    const res = await request.get('/login', { baseUrl, followRedirect: false });
    assert.equal(res.statusCode, 302);

    const parsed = url.parse(res.headers.location, true);

    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.query.client_id, '__test_client_id__');
    assert.equal(parsed.query.scope, 'openid profile email');
    assert.equal(parsed.query.response_type, 'code');
    assert.equal(parsed.query.response_mode, undefined);
    assert.equal(parsed.query.redirect_uri, 'https://example.org/callback');
    assert.property(parsed.query, 'nonce');
    assert.property(parsed.query, 'state');
    assert.property(res.headers, 'set-cookie');

    assert.equal(fetchFromAuthCookie(res, 'nonce'), parsed.query.nonce);
    assert.equal(fetchFromAuthCookie(res, 'state'), parsed.query.state);
  });

  it('should redirect to the authorize url for /login in id_token flow', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authorizationParams: {
          response_type: 'id_token',
        },
      })
    );
    const res = await request.get('/login', { baseUrl, followRedirect: false });
    assert.equal(res.statusCode, 302);

    const parsed = url.parse(res.headers.location, true);

    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.query.client_id, '__test_client_id__');
    assert.equal(parsed.query.scope, 'openid profile email');
    assert.equal(parsed.query.response_type, 'id_token');
    assert.equal(parsed.query.response_mode, 'form_post');
    assert.equal(parsed.query.redirect_uri, 'https://example.org/callback');
    assert.property(parsed.query, 'nonce');
    assert.property(parsed.query, 'state');
  });

  it('should redirect to the authorize url for /login in hybrid flow', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      })
    );
    const res = await request.get('/login', { baseUrl, followRedirect: false });
    assert.equal(res.statusCode, 302);

    const parsed = url.parse(res.headers.location, true);

    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.query.client_id, '__test_client_id__');
    assert.equal(parsed.query.scope, 'openid profile email');
    assert.equal(parsed.query.response_type, 'code id_token');
    assert.equal(parsed.query.response_mode, 'form_post');
    assert.equal(parsed.query.redirect_uri, 'https://example.org/callback');
    assert.property(parsed.query, 'nonce');
    assert.property(parsed.query, 'state');
  });

  it('should redirect to the authorize url for custom login route', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        routes: {
          callback: 'custom-callback',
          login: 'custom-login',
          logout: 'custom-logout',
        },
      })
    );
    const res = await request.get('/custom-login', {
      baseUrl,
      followRedirect: false,
    });
    assert.equal(res.statusCode, 302);

    const parsed = url.parse(res.headers.location, true);
    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(
      parsed.query.redirect_uri,
      'https://example.org/custom-callback'
    );
  });

  it('should allow custom login route with additional login params', async () => {
    const router = auth({
      ...defaultConfig,
      routes: { login: false },
    });
    router.get('/login', (req, res) => {
      res.oidc.login({
        returnTo: 'https://example.org/custom-redirect',
        authorizationParams: {
          response_type: 'code',
          response_mode: 'query',
          scope: 'openid email',
        },
      });
    });
    server = await createServer(router);

    const res = await request.get('/login', { baseUrl, followRedirect: false });
    assert.equal(res.statusCode, 302);

    const parsed = url.parse(res.headers.location, true);

    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.query.scope, 'openid email');
    assert.equal(parsed.query.response_type, 'code');
    assert.equal(parsed.query.response_mode, 'query');
    assert.equal(parsed.query.redirect_uri, 'https://example.org/callback');
    assert.property(parsed.query, 'nonce');

    const decodedState = decodeState(parsed.query.state);

    assert.equal(decodedState.returnTo, 'https://example.org/custom-redirect');
  });

  it('should not allow removing openid from scope', async function () {
    const router = auth({ ...defaultConfig, routes: { login: false } });
    router.get('/login', (req, res) => {
      res.oidc.login({
        authorizationParams: {
          scope: 'email',
        },
      });
    });
    server = await createServer(router);

    const cookieJar = request.jar();
    const res = await request.get('/login', {
      cookieJar,
      baseUrl,
      json: true,
      followRedirect: false,
    });
    assert.equal(res.statusCode, 500);
    assert.equal(res.body.err.message, 'scope should contain "openid"');
  });

  it('should not allow an invalid response_type', async function () {
    const router = auth({ ...defaultConfig, routes: { login: false } });
    router.get('/login', (req, res) => {
      res.oidc.login({
        authorizationParams: {
          response_type: 'invalid',
        },
      });
    });
    server = await createServer(router);

    const cookieJar = request.jar();
    const res = await request.get('/login', {
      cookieJar,
      baseUrl,
      json: true,
      followRedirect: false,
    });
    assert.equal(res.statusCode, 500);
    assert.equal(
      res.body.err.message,
      'response_type should be one of id_token, code id_token, code'
    );
  });

  it('should use a custom state builder', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        getLoginState: (req, opts) => {
          return {
            returnTo: opts.returnTo + '/custom-page',
            customProp: '__test_custom_prop__',
          };
        },
      })
    );
    const res = await request.get('/login', { baseUrl, followRedirect: false });
    assert.equal(res.statusCode, 302);

    const parsed = url.parse(res.headers.location, true);
    const decodedState = decodeState(parsed.query.state);

    assert.equal(decodedState.returnTo, 'https://example.org/custom-page');
    assert.equal(decodedState.customProp, '__test_custom_prop__');
  });

  it('should use PKCE when response_type includes code', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      })
    );
    const res = await request.get('/login', { baseUrl, followRedirect: false });
    assert.equal(res.statusCode, 302);

    const parsed = url.parse(res.headers.location, true);

    assert.isDefined(parsed.query.code_challenge);
    assert.equal(parsed.query.code_challenge_method, 'S256');

    assert.isDefined(fetchFromAuthCookie(res, 'code_verifier'));
  });
});

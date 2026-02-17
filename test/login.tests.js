const assert = require('chai').assert;
const url = require('url');
const querystring = require('querystring');
const nock = require('nock');
const sinon = require('sinon');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});

const { decodeState } = require('../lib/hooks/getLoginState');

const { auth } = require('..');
const { create: createServer } = require('./fixture/server');
const { resetIssuerManager } = require('../lib/issuerManager');
const wellKnown = require('./fixture/well-known.json');
const certs = require('./fixture/cert');

const filterRoute = (method, path) => {
  return (r) =>
    r.route && r.route.path === path && r.route.methods[method.toLowerCase()];
};

const fetchAuthCookie = (res, txnCookieName) => {
  txnCookieName = txnCookieName || 'auth_verification';
  const cookieHeaders = res.headers['set-cookie'];
  return cookieHeaders.filter(
    (header) => header.split('=')[0] === txnCookieName,
  )[0];
};

const fetchFromAuthCookie = (res, cookieName, txnCookieName) => {
  txnCookieName = txnCookieName || 'auth_verification';
  const authCookie = fetchAuthCookie(res, txnCookieName);

  if (!authCookie) {
    return false;
  }

  const decodedAuthCookie = querystring.decode(authCookie);
  const cookieWithAttributes = decodedAuthCookie[txnCookieName].split('; ')[0];
  // The cookie format is: JSON_VALUE.SIGNATURE
  // Use lastIndexOf to find the signature separator since JSON value may contain dots (e.g., in URLs)
  const lastDotIndex = cookieWithAttributes.lastIndexOf('.');
  const cookieValuePart = cookieWithAttributes.substring(0, lastDotIndex);
  const authCookieParsed = JSON.parse(cookieValuePart);

  return authCookieParsed[cookieName];
};

// Helper to parse entire auth cookie object (used for MCD tests)
const parseAuthCookie = (res, txnCookieName) => {
  txnCookieName = txnCookieName || 'auth_verification';
  const authCookie = fetchAuthCookie(res, txnCookieName);

  if (!authCookie) {
    return null;
  }

  const decodedAuthCookie = querystring.decode(authCookie);
  const cookieWithAttributes = decodedAuthCookie[txnCookieName].split('; ')[0];
  const lastDotIndex = cookieWithAttributes.lastIndexOf('.');
  const cookieValuePart = cookieWithAttributes.substring(0, lastDotIndex);
  return JSON.parse(cookieValuePart);
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

  it('should redirect to the authorize url for /login when txn cookie name is custom', async () => {
    let customTxnCookieName = 'CustomTxnCookie';

    server = await createServer(
      auth({
        ...defaultConfig,
        transactionCookie: { name: customTxnCookieName },
      }),
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

    assert.equal(
      fetchFromAuthCookie(res, 'nonce', customTxnCookieName),
      parsed.query.nonce,
    );
    assert.equal(
      fetchFromAuthCookie(res, 'state', customTxnCookieName),
      parsed.query.state,
    );
  });

  it('should redirect to the authorize url for any route if authRequired', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: true,
      }),
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
      }),
    );
    const res = await request.get('/session', {
      baseUrl,
      followRedirect: false,
    });
    assert.equal(res.statusCode, 302);
  });

  it('should redirect to the authorize url for any route with custom txn name if attemptSilentLogin ', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        attemptSilentLogin: true,
        transactionCookie: { name: 'CustomTxnCookie' },
      }),
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
      }),
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

  it('should redirect to the authorize url for /login in code flow with custom txn cookie', async () => {
    let customTxnCookieName = 'CustomTxnCookie';
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code',
        },
        transactionCookie: { name: customTxnCookieName },
      }),
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

    assert.equal(
      fetchFromAuthCookie(res, 'nonce', customTxnCookieName),
      parsed.query.nonce,
    );
    assert.equal(
      fetchFromAuthCookie(res, 'state', customTxnCookieName),
      parsed.query.state,
    );
  });

  it('should redirect to the authorize url for /login in id_token flow', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authorizationParams: {
          response_type: 'id_token',
        },
      }),
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
      }),
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
      }),
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
      'https://example.org/custom-callback',
    );
  });

  it('should redirect to the authorize url when pushed authorize requests enabled', async () => {
    nock(defaultConfig.issuerBaseURL)
      .post('/oauth/par', {
        client_id: '__test_client_id__',
        client_secret: 'test-client-secret',
        nonce: /.+/,
        redirect_uri: 'https://example.org/callback',
        response_mode: 'form_post',
        response_type: 'id_token',
        scope: 'openid profile email',
        state: /.+/,
      })
      .reply(201, { request_uri: 'foo', expires_in: 100 });

    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: 'test-client-secret',
        pushedAuthorizationRequests: true,
        clientAuthMethod: 'client_secret_post',
      }),
    );
    const res = await request.get('/login', {
      baseUrl,
      followRedirect: false,
    });
    assert.equal(res.statusCode, 302);

    const parsed = url.parse(res.headers.location, true);
    assert.equal(parsed.query.request_uri, 'foo');
    assert.equal(parsed.query.client_id, '__test_client_id__');
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
    const router = auth({
      ...defaultConfig,
      routes: { login: false },
    });
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
      'response_type should be one of id_token, code id_token, code',
    );
  });

  it('should not allow an invalid response_type when txn cookie name custom', async function () {
    const router = auth({
      ...defaultConfig,
      routes: { login: false },
      transactionCookie: { name: 'CustomTxnCookie' },
    });
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
      'response_type should be one of id_token, code id_token, code',
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
      }),
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
      }),
    );
    const res = await request.get('/login', { baseUrl, followRedirect: false });
    assert.equal(res.statusCode, 302);

    const parsed = url.parse(res.headers.location, true);

    assert.isDefined(parsed.query.code_challenge);
    assert.equal(parsed.query.code_challenge_method, 'S256');

    assert.isDefined(fetchFromAuthCookie(res, 'code_verifier'));
  });

  it('should respect session.cookie.sameSite when transaction.sameSite is not set and response_mode is not form_post', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_mode: 'query',
          response_type: 'code',
        },
        session: {
          cookie: {
            sameSite: 'Strict',
          },
        },
      }),
    );
    const res = await request.get('/login', { baseUrl, followRedirect: false });
    assert.equal(res.statusCode, 302);

    assert.include(fetchAuthCookie(res), 'SameSite=Strict');
  });

  it('should respect transactionCookie.sameSite when response_mode is not form_post', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        transactionCookie: {
          sameSite: 'Strict',
        },
        authorizationParams: {
          response_mode: 'query',
          response_type: 'code',
        },
      }),
    );
    const res = await request.get('/login', { baseUrl, followRedirect: false });
    assert.equal(res.statusCode, 302);

    assert.include(fetchAuthCookie(res), 'SameSite=Strict');
  });

  it('should overwrite SameSite to None when response_mode is form_post', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        transactionCookie: {
          sameSite: 'Strict',
        },
      }),
    );
    const res = await request.get('/login', { baseUrl, followRedirect: false });
    assert.equal(res.statusCode, 302);

    assert.include(fetchAuthCookie(res), 'SameSite=None');
  });

  it('should pass discovery errors to the express mw', async () => {
    nock('https://example.com')
      .get('/.well-known/openid-configuration')
      .reply(500);
    nock('https://example.com')
      .get('/.well-known/oauth-authorization-server')
      .reply(500);

    server = await createServer(
      auth({
        ...defaultConfig,
        issuerBaseURL: 'https://example.com',
      }),
    );
    const res = await request.get('/login', {
      baseUrl,
      followRedirect: false,
      json: true,
    });
    assert.equal(res.statusCode, 500);
    assert.match(
      res.body.err.message,
      /^Issuer.discover\(\) failed/,
      'Should get error json from server error middleware',
    );
  });
});

describe('auth - MCD (Multiple Custom Domains)', () => {
  let server;
  const baseUrl = 'http://localhost:3000';

  beforeEach(() => {
    // Mock OIDC discovery for various tenant issuers used in MCD tests
    const tenants = [
      'tenant',
      'tenant-a',
      'tenant-b',
      'default',
      'sync-tenant',
      'context-test',
      'cached-tenant',
      'test-tenant',
    ];

    tenants.forEach((tenant) => {
      nock(`https://${tenant}.auth0.com`)
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, {
          ...wellKnown,
          issuer: `https://${tenant}.auth0.com`,
          authorization_endpoint: `https://${tenant}.auth0.com/authorize`,
          token_endpoint: `https://${tenant}.auth0.com/oauth/token`,
          userinfo_endpoint: `https://${tenant}.auth0.com/userinfo`,
        });

      nock(`https://${tenant}.auth0.com`)
        .persist()
        .get('/.well-known/jwks.json')
        .reply(200, certs.jwks);
    });
  });

  afterEach(async () => {
    if (server) {
      server.close();
    }
    nock.cleanAll();
    resetIssuerManager();
  });

  describe('Dynamic issuer resolution', () => {
    it('should resolve issuer from function and store origin_issuer', async () => {
      const issuerResolverFn = sinon
        .stub()
        .resolves('https://tenant-a.auth0.com');

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
      };

      server = await createServer(auth(config));
      const res = await request.get('/login', {
        baseUrl,
        followRedirect: false,
        headers: {
          host: 'tenant-a.example.org',
        },
      });

      assert.equal(res.statusCode, 302);

      // Verify resolver was called
      assert.ok(issuerResolverFn.calledOnce);
      const callContext = issuerResolverFn.firstCall.args[0];
      assert.ok(callContext.req);

      // Verify redirect to correct issuer
      const parsed = url.parse(res.headers.location, true);
      assert.equal(parsed.hostname, 'tenant-a.auth0.com');
      assert.equal(parsed.pathname, '/authorize');

      // Verify origin_issuer is stored in transaction cookie
      const authCookieData = parseAuthCookie(res);
      assert.ok(authCookieData);
      assert.equal(authCookieData.origin_issuer, 'https://tenant-a.auth0.com');
      assert.property(authCookieData, 'nonce');
      assert.property(authCookieData, 'state');
    });

    it('should resolve different issuers for different requests', async () => {
      const issuerResolverFn = async (context) => {
        const hostname = context.req.headers.host || context.req.hostname;
        if (hostname.includes('tenant-a')) {
          return 'https://tenant-a.auth0.com';
        } else if (hostname.includes('tenant-b')) {
          return 'https://tenant-b.auth0.com';
        }
        return 'https://default.auth0.com';
      };

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
      };

      server = await createServer(auth(config));

      // Request 1: tenant-a
      const res1 = await request.get('/login', {
        baseUrl,
        followRedirect: false,
        headers: {
          host: 'tenant-a.example.org',
        },
      });

      const parsed1 = url.parse(res1.headers.location, true);
      assert.equal(parsed1.hostname, 'tenant-a.auth0.com');

      const authCookie1 = parseAuthCookie(res1);
      assert.equal(authCookie1.origin_issuer, 'https://tenant-a.auth0.com');

      // Request 2: tenant-b
      const res2 = await request.get('/login', {
        baseUrl,
        followRedirect: false,
        headers: {
          host: 'tenant-b.example.org',
        },
      });

      const parsed2 = url.parse(res2.headers.location, true);
      assert.equal(parsed2.hostname, 'tenant-b.auth0.com');

      const authCookie2 = parseAuthCookie(res2);
      assert.equal(authCookie2.origin_issuer, 'https://tenant-b.auth0.com');
    });

    it('should handle sync issuer resolver functions', async () => {
      const issuerResolverFn = () => 'https://sync-tenant.auth0.com';

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
      };

      server = await createServer(auth(config));
      const res = await request.get('/login', {
        baseUrl,
        followRedirect: false,
      });

      assert.equal(res.statusCode, 302);

      const parsed = url.parse(res.headers.location, true);
      assert.equal(parsed.hostname, 'sync-tenant.auth0.com');

      const authCookieData = parseAuthCookie(res);
      assert.equal(
        authCookieData.origin_issuer,
        'https://sync-tenant.auth0.com',
      );
    });

    it('should pass correct context to resolver function', async () => {
      const issuerResolverFn = sinon
        .stub()
        .resolves('https://context-test.auth0.com');

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
      };

      server = await createServer(auth(config));
      const res = await request.get('/login?foo=bar', {
        baseUrl,
        followRedirect: false,
        headers: {
          host: 'custom-host.example.org',
          'x-custom-header': 'test-value',
        },
      });

      assert.equal(res.statusCode, 302);

      // Verify context structure
      assert.ok(issuerResolverFn.calledOnce);
      const context = issuerResolverFn.firstCall.args[0];

      assert.ok(context.req, 'context should have req');

      // Verify request headers are accessible
      assert.equal(context.req.headers['x-custom-header'], 'test-value');
      assert.equal(context.req.headers.host, 'custom-host.example.org');

      // Verify URL info is accessible from req
      assert.include(context.req.originalUrl || context.req.url, '/login');
    });

    it('should handle resolver errors gracefully', async () => {
      const issuerResolverFn = async () => {
        throw new Error('Database connection failed');
      };

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
      };

      server = await createServer(auth(config));
      const res = await request.get('/login', {
        baseUrl,
        followRedirect: false,
      });

      // Should return error response
      assert.equal(res.statusCode, 500);
      assert.include(res.body, 'Failed to resolve issuer');
    });

    it('should cache issuer clients per issuer URL', async () => {
      let callCount = 0;
      const issuerResolverFn = async () => {
        callCount++;
        return 'https://cached-tenant.auth0.com';
      };

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
      };

      server = await createServer(auth(config));

      // First request
      const res1 = await request.get('/login', {
        baseUrl,
        followRedirect: false,
      });
      assert.equal(res1.statusCode, 302);

      // Second request - should use cached client
      const res2 = await request.get('/login', {
        baseUrl,
        followRedirect: false,
      });
      assert.equal(res2.statusCode, 302);

      // Resolver should be called twice (once per request)
      // But OIDC discovery should be cached
      assert.equal(callCount, 2);
    });
  });

  describe('Transaction state with origin_issuer', () => {
    it('should include origin_issuer in authVerification for static issuer', async () => {
      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://tenant.auth0.com',
        authRequired: false,
      };

      server = await createServer(auth(config));
      const res = await request.get('/login', {
        baseUrl,
        followRedirect: false,
      });

      const authCookieData = parseAuthCookie(res);
      assert.ok(authCookieData);
      assert.equal(authCookieData.origin_issuer, 'https://tenant.auth0.com');
    });

    it('should include all required fields in authVerification for code flow', async () => {
      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: () => 'https://test-tenant.auth0.com',
        authRequired: false,
        authorizationParams: {
          response_type: 'code',
          scope: 'openid profile email',
        },
        clientSecret: '__test_client_secret__',
      };

      server = await createServer(auth(config));
      const res = await request.get('/login', {
        baseUrl,
        followRedirect: false,
      });

      const authCookieData = parseAuthCookie(res);
      assert.ok(authCookieData);

      // Verify standard fields
      assert.property(authCookieData, 'nonce');
      assert.property(authCookieData, 'state');
      assert.property(authCookieData, 'code_verifier'); // PKCE for code flow

      // Verify MCD field
      assert.property(authCookieData, 'origin_issuer');
      assert.equal(
        authCookieData.origin_issuer,
        'https://test-tenant.auth0.com',
      );
    });
  });
});

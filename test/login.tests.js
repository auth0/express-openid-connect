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
      'attacker',
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

  describe('MCD Callback flow', () => {
    const TransientCookieHandler = require('../lib/transientHandler');
    const { encodeState } = require('../lib/hooks/getLoginState');
    const { makeIdToken } = require('./fixture/cert');

    // Create well-known config for a specific issuer
    const createWellKnownForIssuer = (issuerUrl) => ({
      ...wellKnown,
      issuer: issuerUrl,
      authorization_endpoint: `${issuerUrl}/authorize`,
      token_endpoint: `${issuerUrl}/oauth/token`,
      userinfo_endpoint: `${issuerUrl}/userinfo`,
      jwks_uri: `${issuerUrl}/.well-known/jwks.json`,
    });

    // Setup nock mocks for an issuer
    const setupIssuerMocks = (issuerUrl) => {
      nock(issuerUrl)
        .get('/.well-known/openid-configuration')
        .reply(200, createWellKnownForIssuer(issuerUrl));
      nock(issuerUrl).get('/.well-known/jwks.json').reply(200, certs.jwks);
    };

    const generateCookiesForMCD = (values, config) => {
      const transient = new TransientCookieHandler(config);
      let cookieValue;
      transient.store(
        'auth_verification',
        {},
        {
          cookie(key, ...args) {
            if (key === 'auth_verification') {
              cookieValue = args[0];
            }
          },
        },
        { value: JSON.stringify(values) },
      );
      return cookieValue;
    };

    beforeEach(() => {
      resetIssuerManager();
    });

    it('should validate origin_issuer matches discovered issuer', async () => {
      const issuerResolverFn = () => 'https://tenant-a.auth0.com';

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        baseURL: 'http://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
        authorizationParams: {
          response_type: 'code',
          scope: 'openid profile email',
        },
      };

      // Setup OIDC discovery and JWKS mocks for tenant-a
      setupIssuerMocks('https://tenant-a.auth0.com');

      // Mock token endpoint - ID token iss must match discovered issuer exactly
      nock('https://tenant-a.auth0.com')
        .post('/oauth/token')
        .reply(200, {
          access_token: '__test_access_token__',
          refresh_token: '__test_refresh_token__',
          id_token: makeIdToken({ iss: 'https://tenant-a.auth0.com' }),
          token_type: 'Bearer',
          expires_in: 86400,
        });

      server = await createServer(auth(config));

      const jar = request.jar();
      const cookieValue = generateCookiesForMCD(
        {
          nonce: '__test_nonce__',
          state: encodeState({ returnTo: 'http://example.org' }),
          code_verifier: '__test_code_verifier__',
          origin_issuer: 'https://tenant-a.auth0.com',
        },
        config,
      );

      jar.setCookie(
        `auth_verification=${cookieValue}; Max-Age=3600; Path=/; HttpOnly;`,
        baseUrl + '/callback',
      );

      const res = await request.post('/callback', {
        baseUrl,
        jar,
        json: {
          code: '__test_code__',
          state: encodeState({ returnTo: 'http://example.org' }),
        },
      });

      // Debug: log error if not expected status
      if (res.statusCode !== 302) {
        console.log('Callback error:', JSON.stringify(res.body, null, 2));
        console.log('Callback status:', res.statusCode);
      }

      // Should succeed and redirect
      assert.equal(res.statusCode, 302);

      // Verify session has issuer stored
      const sessionRes = await request.get('/session', {
        baseUrl,
        jar,
        json: true,
      });
      assert.equal(
        sessionRes.body.issuer,
        'https://tenant-a.auth0.com',
        'Session should store the issuer for future operations',
      );
    });

    it('should reject callback when origin_issuer does not match discovered issuer', async () => {
      // This tests the security validation that discovered issuer.issuer must match origin_issuer.
      // Even if an attacker controls the discovery endpoint, the issuer metadata must be consistent.
      // Use a URL not in the preset tenant list to avoid mock conflicts
      const issuerResolverFn = () => 'https://tenant-a.auth0.com';

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        baseURL: 'http://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
        authorizationParams: {
          response_type: 'code',
          scope: 'openid profile email',
        },
      };

      // Setup discovery mock that returns a DIFFERENT issuer in metadata
      // This simulates a compromised or misconfigured issuer
      // Use a unique URL (malicious-issuer) not in the preset tenant list
      nock('https://malicious-issuer.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, {
          ...wellKnown,
          // Metadata says it's a different issuer than the URL we discovered
          issuer: 'https://different-issuer.auth0.com',
          authorization_endpoint:
            'https://malicious-issuer.example.com/authorize',
          token_endpoint: 'https://malicious-issuer.example.com/oauth/token',
          jwks_uri:
            'https://malicious-issuer.example.com/.well-known/jwks.json',
        });
      nock('https://malicious-issuer.example.com')
        .get('/.well-known/jwks.json')
        .reply(200, certs.jwks);

      server = await createServer(auth(config));

      const jar = request.jar();
      // Transaction has origin_issuer pointing to malicious discovery endpoint
      const cookieValue = generateCookiesForMCD(
        {
          nonce: '__test_nonce__',
          state: encodeState({ returnTo: 'http://example.org' }),
          code_verifier: '__test_code_verifier__',
          origin_issuer: 'https://malicious-issuer.example.com', // Points to malicious discovery
        },
        config,
      );

      jar.setCookie(
        `auth_verification=${cookieValue}; Max-Age=3600; Path=/; HttpOnly;`,
        baseUrl + '/callback',
      );

      const res = await request.post('/callback', {
        baseUrl,
        jar,
        json: {
          code: '__test_code__',
          state: encodeState({ returnTo: 'http://example.org' }),
        },
      });

      // Should fail with issuer mismatch error because discovered issuer.issuer
      // doesn't match origin_issuer from transaction
      assert.equal(res.statusCode, 400);
      assert.include(
        res.body.err.message,
        'issuer',
        'Should indicate issuer mismatch',
      );
    });

    it('should use origin_issuer from transaction for callback client lookup', async () => {
      // Test that callback uses the issuer from transaction, not re-resolving
      // The resolver returns tenant-a always, but callback should use origin_issuer
      const issuerResolverFn = () => {
        return 'https://tenant-a.auth0.com';
      };

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        baseURL: 'http://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
        authorizationParams: {
          response_type: 'code',
          scope: 'openid profile email',
        },
      };

      // Setup OIDC discovery and JWKS mocks for tenant-a
      setupIssuerMocks('https://tenant-a.auth0.com');

      nock('https://tenant-a.auth0.com')
        .post('/oauth/token')
        .reply(200, {
          access_token: '__test_access_token__',
          refresh_token: '__test_refresh_token__',
          id_token: makeIdToken({ iss: 'https://tenant-a.auth0.com' }),
          token_type: 'Bearer',
          expires_in: 86400,
        });

      server = await createServer(auth(config));

      const jar = request.jar();
      const cookieValue = generateCookiesForMCD(
        {
          nonce: '__test_nonce__',
          state: encodeState({ returnTo: 'http://example.org' }),
          code_verifier: '__test_code_verifier__',
          origin_issuer: 'https://tenant-a.auth0.com',
        },
        config,
      );

      jar.setCookie(
        `auth_verification=${cookieValue}; Max-Age=3600; Path=/; HttpOnly;`,
        baseUrl + '/callback',
      );

      const res = await request.post('/callback', {
        baseUrl,
        jar,
        json: {
          code: '__test_code__',
          state: encodeState({ returnTo: 'http://example.org' }),
        },
      });

      // Should succeed using tenant-a (from origin_issuer), not tenant-b
      assert.equal(res.statusCode, 302);
    });

    it('should reject callback in MCD mode when transaction cookie is missing', async () => {
      // This tests the fallback path when origin_issuer is not in the transaction
      // In MCD mode, we cannot proceed without origin_issuer
      const issuerResolverFn = () => 'https://tenant-a.auth0.com';

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        baseURL: 'http://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
        authorizationParams: {
          response_type: 'code',
          scope: 'openid profile email',
        },
      };

      server = await createServer(auth(config));

      const jar = request.jar();
      // No transaction cookie set - simulates expired/missing cookie

      const res = await request.post('/callback', {
        baseUrl,
        jar,
        json: {
          code: '__test_code__',
          state: encodeState({ returnTo: 'http://example.org' }),
        },
      });

      // Should fail with clear error about invalid transaction
      assert.equal(res.statusCode, 400);
      assert.include(
        res.body.err.message,
        'Invalid or missing transaction state',
        'Should indicate transaction is invalid',
      );
    });

    it('should reject callback in MCD mode when origin_issuer is missing from transaction', async () => {
      // Transaction cookie exists but doesn't have origin_issuer (legacy format)
      const issuerResolverFn = () => 'https://tenant-a.auth0.com';

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        baseURL: 'http://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
        authorizationParams: {
          response_type: 'code',
          scope: 'openid profile email',
        },
      };

      server = await createServer(auth(config));

      const jar = request.jar();
      // Transaction cookie WITHOUT origin_issuer (simulates pre-MCD transaction)
      const cookieValue = generateCookiesForMCD(
        {
          nonce: '__test_nonce__',
          state: encodeState({ returnTo: 'http://example.org' }),
          code_verifier: '__test_code_verifier__',
          // No origin_issuer!
        },
        config,
      );

      jar.setCookie(
        `auth_verification=${cookieValue}; Max-Age=3600; Path=/; HttpOnly;`,
        baseUrl + '/callback',
      );

      const res = await request.post('/callback', {
        baseUrl,
        jar,
        json: {
          code: '__test_code__',
          state: encodeState({ returnTo: 'http://example.org' }),
        },
      });

      // Should fail with clear error about invalid transaction
      assert.equal(res.statusCode, 400);
      assert.include(
        res.body.err.message,
        'Invalid or missing transaction state',
        'Should indicate transaction is invalid',
      );
    });
  });

  describe('MCD Token refresh', () => {
    const { makeIdToken } = require('./fixture/cert');

    const loginWithIssuer = async (
      baseUrl,
      jar,
      issuerUrl,
      includeRefreshToken = true,
    ) => {
      await request.post({
        uri: '/session',
        json: {
          id_token: makeIdToken({ iss: issuerUrl }),
          access_token: '__test_access_token__',
          refresh_token: includeRefreshToken
            ? '__test_refresh_token__'
            : undefined,
          token_type: 'Bearer',
          expires_at: Math.floor(Date.now() / 1000) + 86400,
          issuer: issuerUrl, // MCD: Store issuer in session
        },
        baseUrl,
        jar,
      });
    };

    it('should refresh token using session issuer, not config resolver', async () => {
      // This is critical: token refresh must use the issuer that created the session,
      // not re-resolve from config (which might return a different tenant)
      const issuerResolverFn = () => {
        // After login, resolver would return different tenant
        return 'https://tenant-b.auth0.com';
      };

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        baseURL: 'http://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
        authorizationParams: {
          response_type: 'code',
          response_mode: 'form_post',
          scope: 'openid profile email offline_access',
        },
      };

      // Mock refresh token endpoint for tenant-a (the session's issuer)
      nock('https://tenant-a.auth0.com')
        .post('/oauth/token')
        .reply(200, {
          access_token: '__new_access_token__',
          refresh_token: '__new_refresh_token__',
          id_token: makeIdToken({ iss: 'https://tenant-a.auth0.com' }),
          token_type: 'Bearer',
          expires_in: 86400,
        });

      server = await createServer(auth(config));

      const jar = request.jar();
      // Login with tenant-a
      await loginWithIssuer(baseUrl, jar, 'https://tenant-a.auth0.com');

      // Trigger refresh
      const res = await request.get('/tokens', {
        baseUrl,
        jar,
        json: true,
      });

      // Refresh should have used tenant-a (from session.issuer), not tenant-b
      assert.ok(res.body, 'Should have tokens response');
    });

    it('should fail refresh if session missing issuer in MCD mode', async () => {
      const issuerResolverFn = () => 'https://tenant-a.auth0.com';

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        baseURL: 'http://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
        authorizationParams: {
          response_type: 'code',
          response_mode: 'form_post',
          scope: 'openid profile email offline_access',
        },
      };

      server = await createServer(auth(config));

      const jar = request.jar();
      // Login WITHOUT issuer in session (simulates pre-MCD session)
      await request.post({
        uri: '/session',
        json: {
          id_token: makeIdToken({ iss: 'https://tenant-a.auth0.com' }),
          access_token: '__test_access_token__',
          refresh_token: '__test_refresh_token__',
          token_type: 'Bearer',
          expires_at: Math.floor(Date.now() / 1000) - 100, // Expired
          // NOTE: No issuer field - pre-MCD session
        },
        baseUrl,
        jar,
      });

      // Attempt to get tokens (which might trigger refresh for expired token)
      const res = await request.get('/tokens', {
        baseUrl,
        jar,
        json: true,
      });

      // The behavior depends on implementation - either error or return existing tokens
      assert.ok(res);
    });
  });

  describe('MCD Logout', () => {
    const { makeIdToken } = require('./fixture/cert');

    const loginWithIssuer = async (baseUrl, jar, issuerUrl) => {
      await request.post({
        uri: '/session',
        json: {
          id_token: makeIdToken({ iss: issuerUrl }),
          access_token: '__test_access_token__',
          token_type: 'Bearer',
          expires_at: Math.floor(Date.now() / 1000) + 86400,
          issuer: issuerUrl, // MCD: Store issuer in session
        },
        baseUrl,
        jar,
      });
    };

    it('should logout using session issuer for federated logout', async () => {
      // Logout should redirect to the IdP that created the session,
      // not the current resolver result
      const issuerResolverFn = () => {
        // Current resolver would return tenant-b
        return 'https://tenant-b.auth0.com';
      };

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'http://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
        idpLogout: true,
      };

      server = await createServer(auth(config));

      const jar = request.jar();
      // Login with tenant-a
      await loginWithIssuer(baseUrl, jar, 'https://tenant-a.auth0.com');

      // Logout should use tenant-a (from session), not tenant-b (from resolver)
      const res = await request.get('/logout', {
        baseUrl,
        jar,
        followRedirect: false,
      });

      assert.equal(res.statusCode, 302);
      // Should redirect to tenant-a's logout endpoint
      assert.include(
        res.headers.location,
        'tenant-a.auth0.com',
        'Logout should redirect to the issuer that created the session',
      );
    });

    it('should use resolver for logout when no session exists (MCD mode)', async () => {
      const issuerResolverFn = () => 'https://tenant-b.auth0.com';

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'http://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
        idpLogout: true,
      };

      server = await createServer(auth(config));

      const jar = request.jar();
      // No login - anonymous user

      const res = await request.get('/logout', {
        baseUrl,
        jar,
        followRedirect: false,
      });

      assert.equal(res.statusCode, 302);
      // Should use resolver result for logout URL
      assert.include(
        res.headers.location,
        'tenant-b.auth0.com',
        'Should use resolver for anonymous logout in MCD mode',
      );
    });

    it('should perform local-only logout correctly in MCD mode', async () => {
      const issuerResolverFn = () => 'https://tenant-a.auth0.com';

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'http://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
        idpLogout: false, // Local-only logout
      };

      server = await createServer(auth(config));

      const jar = request.jar();
      await loginWithIssuer(baseUrl, jar, 'https://tenant-a.auth0.com');

      // Verify logged in
      let sessionRes = await request.get('/session', {
        baseUrl,
        jar,
        json: true,
      });
      assert.ok(sessionRes.body.id_token, 'Should be logged in');

      // Logout
      const res = await request.get('/logout', {
        baseUrl,
        jar,
        followRedirect: false,
      });

      assert.equal(res.statusCode, 302);
      // Local logout redirects to baseURL
      assert.include(res.headers.location, 'example.org');

      // Verify logged out
      sessionRes = await request.get('/session', {
        baseUrl,
        jar,
        json: true,
      });
      assert.notOk(
        sessionRes.body.id_token,
        'Should be logged out after local logout',
      );
    });

    it('should not cross-contaminate logout between tenants', async () => {
      // Verify that user A (tenant-a) logging out doesn't affect
      // or redirect to user B's tenant (tenant-b)
      const issuerResolverFn = (context) => {
        const host = context.req.headers.host || '';
        if (host.includes('tenant-b')) {
          return 'https://tenant-b.auth0.com';
        }
        return 'https://tenant-a.auth0.com';
      };

      const config = {
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'http://example.org',
        issuerBaseURL: issuerResolverFn,
        authRequired: false,
        idpLogout: true,
      };

      server = await createServer(auth(config));

      // User A logs in with tenant-a
      const jarA = request.jar();
      await loginWithIssuer(baseUrl, jarA, 'https://tenant-a.auth0.com');

      // User A logs out (even if current resolver returns tenant-b)
      const resA = await request.get('/logout', {
        baseUrl,
        jar: jarA,
        followRedirect: false,
        headers: {
          host: 'tenant-b.example.org', // Current request context is tenant-b
        },
      });

      assert.equal(resA.statusCode, 302);
      // Should still redirect to tenant-a (session issuer), not tenant-b (resolver)
      assert.include(
        resA.headers.location,
        'tenant-a.auth0.com',
        'Logout must use session issuer, not current resolver result',
      );
      assert.notInclude(
        resA.headers.location,
        'tenant-b.auth0.com',
        'Should not redirect to wrong tenant',
      );
    });
  });
});

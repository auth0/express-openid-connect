const { assert } = require('chai');
const nock = require('nock');
const onLogin = require('../lib/hooks/backchannelLogout/onLogIn');
const { get: getConfig } = require('../lib/config');
const { create: createServer } = require('./fixture/server');
const { makeIdToken, makeLogoutToken } = require('./fixture/cert');
const { auth } = require('./..');
const getRedisStore = require('./fixture/store');
const {
  getIssuerManager,
  resetIssuerManager,
} = require('../lib/issuerManager');

const baseUrl = 'http://localhost:3000';

const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
  baseUrl,
  json: true,
});

const login = async (idToken) => {
  const jar = request.jar();
  await request.post({
    uri: '/session',
    json: {
      id_token: idToken || makeIdToken(),
    },
    jar,
  });

  const session = (await request.get({ uri: '/session', jar })).body;
  return { jar, session };
};

describe('back-channel logout', async () => {
  let server;
  let client;
  let store;
  let config;

  beforeEach(() => {
    ({ client, store } = getRedisStore());
    config = {
      clientID: '__test_client_id__',
      baseURL: 'http://example.org',
      issuerBaseURL: 'https://op.example.com',
      secret: '__test_session_secret__',
      authRequired: false,
      backchannelLogout: { store },
    };
  });

  afterEach(async () => {
    if (server) {
      server.close();
    }
    if (client) {
      await new Promise((resolve) => client.flushall(resolve));
      await new Promise((resolve) => client.quit(resolve));
    }
  });

  it('should only handle post requests', async () => {
    server = await createServer(auth(config));

    for (const method of ['get', 'put', 'patch', 'delete']) {
      const res = await request('/backchannel-logout', {
        method,
      });
      assert.equal(res.statusCode, 404);
    }
  });

  it('should require a logout token', async () => {
    server = await createServer(auth(config));

    const res = await request.post('/backchannel-logout');
    assert.equal(res.statusCode, 400);
    assert.deepEqual(res.body, {
      error: 'invalid_request',
      error_description: 'Missing logout_token',
    });
  });

  it('should not cache the response', async () => {
    server = await createServer(auth(config));

    const res = await request.post('/backchannel-logout');
    assert.equal(res.headers['cache-control'], 'no-store');
  });

  it('should accept and store a valid logout_token', async () => {
    server = await createServer(auth(config));

    const res = await request.post('/backchannel-logout', {
      form: {
        logout_token: makeLogoutToken({ sid: 'foo' }),
      },
    });
    assert.equal(res.statusCode, 204);
    const payload = await client.asyncGet('https://op.example.com/|foo');
    assert.ok(payload);
  });

  it('should accept and store a valid logout_token signed with HS256', async () => {
    server = await createServer(auth(config));

    const res = await request.post('/backchannel-logout', {
      form: {
        logout_token: makeLogoutToken({
          sid: 'foo',
          secret: config.clientSecret,
        }),
      },
    });
    assert.equal(res.statusCode, 204);
    const payload = await client.asyncGet('https://op.example.com/|foo');
    assert.ok(payload);
  });

  it('should require a sid or a sub', async () => {
    server = await createServer(auth(config));

    const res = await request.post('/backchannel-logout', {
      form: {
        logout_token: makeLogoutToken(),
      },
    });
    assert.equal(res.statusCode, 400);
  });

  it('should set a maxAge based on rolling expiry', async () => {
    server = await createServer(
      auth({ ...config, session: { rollingDuration: 999 } }),
    );

    const res = await request.post('/backchannel-logout', {
      form: {
        logout_token: makeLogoutToken({ sid: 'foo' }),
      },
    });
    assert.equal(res.statusCode, 204);
    const { cookie } = await client.asyncGet('https://op.example.com/|foo');
    assert.equal(cookie.maxAge, 999 * 1000);
    const ttl = await client.asyncTtl('https://op.example.com/|foo');
    assert.closeTo(ttl, 999, 5);
  });

  it('should set a maxAge based on absolute expiry', async () => {
    server = await createServer(
      auth({ ...config, session: { absoluteDuration: 999, rolling: false } }),
    );

    const res = await request.post('/backchannel-logout', {
      form: {
        logout_token: makeLogoutToken({ sid: 'foo' }),
      },
    });
    assert.equal(res.statusCode, 204);
    const { cookie } = await client.asyncGet('https://op.example.com/|foo');
    assert.equal(cookie.maxAge, 999 * 1000);
    const ttl = await client.asyncTtl('https://op.example.com/|foo');
    assert.closeTo(ttl, 999, 5);
  });

  it('should fail if storing the token fails', async () => {
    server = await createServer(
      auth({
        ...config,
        backchannelLogout: {
          ...config.backchannelLogout,
          onLogoutToken() {
            throw new Error('storage failure');
          },
        },
      }),
    );

    const res = await request.post('/backchannel-logout', {
      form: {
        logout_token: makeLogoutToken({ sid: 'foo' }),
      },
    });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'application_error');
  });

  it('should log sid out on subsequent requests', async () => {
    server = await createServer(auth(config));
    const { jar } = await login(makeIdToken({ sid: '__foo_sid__' }));
    let body;
    ({ body } = await request.get('/session', {
      jar,
    }));
    assert.isNotEmpty(body);
    assert.isNotEmpty(jar.getCookies(baseUrl));

    const res = await request.post('/backchannel-logout', {
      baseUrl,
      form: {
        logout_token: makeLogoutToken({ sid: '__foo_sid__' }),
      },
    });
    assert.equal(res.statusCode, 204);
    const payload = await client.asyncGet(
      'https://op.example.com/|__foo_sid__',
    );
    assert.ok(payload);
    ({ body } = await request.get('/session', {
      jar,
    }));
    assert.isEmpty(jar.getCookies(baseUrl));
    assert.isUndefined(body);
  });

  it('should log sub out on subsequent requests', async () => {
    server = await createServer(auth(config));
    const { jar } = await login(makeIdToken({ sub: '__foo_sub__' }));
    let body;
    ({ body } = await request.get('/session', {
      jar,
    }));
    assert.isNotEmpty(body);
    assert.isNotEmpty(jar.getCookies(baseUrl));

    const res = await request.post('/backchannel-logout', {
      baseUrl,
      form: {
        logout_token: makeLogoutToken({ sub: '__foo_sub__' }),
      },
    });
    assert.equal(res.statusCode, 204);
    const payload = await client.asyncGet(
      'https://op.example.com/|__foo_sub__',
    );
    assert.ok(payload);
    ({ body } = await request.get('/session', {
      jar,
    }));
    assert.isEmpty(jar.getCookies(baseUrl));
    assert.isUndefined(body);
  });

  it('should not log sub out if login is after back-channel logout', async () => {
    server = await createServer(auth(config));

    const { jar } = await login(makeIdToken({ sub: '__foo_sub__' }));

    const res = await request.post('/backchannel-logout', {
      baseUrl,
      form: {
        logout_token: makeLogoutToken({ sub: '__foo_sub__' }),
      },
    });
    assert.equal(res.statusCode, 204);
    let payload = await client.asyncGet('https://op.example.com/|__foo_sub__');
    assert.ok(payload);

    await onLogin(
      { oidc: { idTokenClaims: { sub: '__foo_sub__' } } },
      getConfig(config),
    );
    payload = await client.asyncGet('https://op.example.com/|__foo_sub__');
    assert.notOk(payload);

    const { body } = await request.get('/session', {
      jar,
    });
    assert.isNotEmpty(jar.getCookies(baseUrl));
    assert.isNotEmpty(body);
  });

  it('should handle failures to get logout token', async () => {
    server = await createServer(
      auth({
        ...config,
        backchannelLogout: {
          ...config.backchannelLogout,
          isLoggedOut() {
            throw new Error('storage failure');
          },
        },
      }),
    );
    const { jar } = await login(makeIdToken({ sid: '__foo_sid__' }));
    let body;
    ({ body } = await request.get('/session', {
      jar,
    }));
    assert.deepEqual(body, { err: { message: 'storage failure' } });
  });
});

describe('back-channel logout with MCD (Multiple Custom Domains)', () => {
  let server;
  let client;
  let store;
  const wellKnown = require('./fixture/well-known.json');
  const certs = require('./fixture/cert');

  beforeEach(() => {
    resetIssuerManager();
    ({ client, store } = getRedisStore());

    // Setup nock for MCD issuers
    ['tenant-a', 'tenant-b'].forEach((tenant) => {
      nock(`https://${tenant}.auth0.com`)
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, {
          ...wellKnown,
          issuer: `https://${tenant}.auth0.com`,
        });

      nock(`https://${tenant}.auth0.com`)
        .persist()
        .get('/.well-known/jwks.json')
        .reply(200, certs.jwks);
    });
  });

  afterEach(async () => {
    nock.cleanAll();
    resetIssuerManager();
    if (server) {
      server.close();
    }
    if (client) {
      await new Promise((resolve) => client.flushall(resolve));
      await new Promise((resolve) => client.quit(resolve));
    }
  });

  const mcdConfig = {
    clientID: '__test_client_id__',
    baseURL: 'http://example.org',
    issuerBaseURL: ({ req }) => {
      // Resolve issuer based on subdomain
      const host = req.get('host') || 'tenant-a.example.org';
      if (host.includes('tenant-b')) {
        return 'https://tenant-b.auth0.com';
      }
      return 'https://tenant-a.auth0.com';
    },
    secret: '__test_session_secret__',
    authRequired: false,
    backchannelLogout: null, // Will be set in each test
  };

  it('should reject backchannel logout from unknown issuer (SSRF prevention)', async () => {
    server = await createServer(
      auth({
        ...mcdConfig,
        backchannelLogout: { store },
      }),
    );

    // Create a logout token with an unknown issuer
    const maliciousToken = makeLogoutToken({
      sid: 'foo',
      iss: 'https://attacker.example.com',
    });

    const res = await request.post('/backchannel-logout', {
      form: {
        logout_token: maliciousToken,
      },
    });

    assert.equal(res.statusCode, 400);
    assert.deepEqual(res.body, {
      error: 'invalid_request',
      error_description: 'Unknown issuer',
    });
  });

  it('should accept backchannel logout from known issuer in MCD mode', async () => {
    server = await createServer(
      auth({
        ...mcdConfig,
        backchannelLogout: { store },
      }),
    );

    // First, "warm up" the cache by getting a client for the issuer
    // This simulates a user having logged in via this issuer
    const issuerManager = getIssuerManager();
    await issuerManager.getClient('https://tenant-a.auth0.com', {
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      idTokenSigningAlg: 'RS256',
      clientAuthMethod: 'client_secret_basic',
      clockTolerance: 60,
      httpTimeout: 5000,
      enableTelemetry: false,
      discoveryCacheMaxAge: 300000,
      idpLogout: false,
      authorizationParams: {
        response_type: 'id_token',
        scope: 'openid profile email',
      },
    });

    // Now the issuer is "known" - backchannel logout should work
    const logoutToken = makeLogoutToken({
      sid: 'foo',
      iss: 'https://tenant-a.auth0.com',
    });

    const res = await request.post('/backchannel-logout', {
      form: {
        logout_token: logoutToken,
      },
    });

    assert.equal(res.statusCode, 204);
  });

  it('should reject invalid JWT format in MCD mode', async () => {
    server = await createServer(
      auth({
        ...mcdConfig,
        backchannelLogout: { store },
      }),
    );

    const res = await request.post('/backchannel-logout', {
      form: {
        logout_token: 'not.a.valid.jwt.token',
      },
    });

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'invalid_request');
    assert.equal(res.body.error_description, 'Invalid logout_token format');
  });

  it('should reject logout token with missing iss claim in MCD mode', async () => {
    server = await createServer(
      auth({
        ...mcdConfig,
        backchannelLogout: { store },
      }),
    );

    // Create a token without iss claim
    const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString(
      'base64url',
    );
    const payload = Buffer.from(
      JSON.stringify({ sid: 'foo', aud: '__test_client_id__' }),
    ).toString('base64url');
    const tokenWithoutIss = `${header}.${payload}.fake_signature`;

    const res = await request.post('/backchannel-logout', {
      form: {
        logout_token: tokenWithoutIss,
      },
    });

    assert.equal(res.statusCode, 400);
    assert.deepEqual(res.body, {
      error: 'invalid_request',
      error_description: 'logout_token missing iss claim',
    });
  });

  it('should reject logout token with invalid payload in MCD mode', async () => {
    server = await createServer(
      auth({
        ...mcdConfig,
        backchannelLogout: { store },
      }),
    );

    // Create a token with invalid base64 payload
    const tokenWithBadPayload = 'header.!!!invalid_base64!!!.signature';

    const res = await request.post('/backchannel-logout', {
      form: {
        logout_token: tokenWithBadPayload,
      },
    });

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'invalid_request');
    assert.equal(res.body.error_description, 'Invalid logout_token payload');
  });
});

const { assert } = require('chai');
const onLogin = require('../lib/hooks/backchannelLogout/onLogIn');
const { get: getConfig } = require('../lib/config');
const { create: createServer } = require('./fixture/server');
const { makeIdToken, makeLogoutToken } = require('./fixture/cert');
const { auth } = require('./..');
const getRedisStore = require('./fixture/store');

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
      {
        oidc: {
          idTokenClaims: { sub: '__foo_sub__', iss: 'https://op.example.com/' },
        },
      },
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

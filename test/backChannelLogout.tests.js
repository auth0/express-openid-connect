const { assert } = require('chai');
const { create: createServer } = require('./fixture/server');
const { makeIdToken, makeLogoutToken } = require('./fixture/cert');
const { auth } = require('./..');
const getRedisStore = require('./fixture/store');
const sinon = require('sinon');

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
      backChannelLogout: true,
      backChannelLogoutStore: store,
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
      const res = await request('/back-channel-logout', {
        method,
      });
      assert.equal(res.statusCode, 404);
    }
  });

  it('should require a logout token', async () => {
    server = await createServer(auth(config));

    const res = await request.post('/back-channel-logout');
    assert.equal(res.statusCode, 400);
    assert.deepEqual(res.body, {
      error: 'invalid_request',
      error_description: 'Missing logout_token',
    });
  });

  it('should not cache the response', async () => {
    server = await createServer(auth(config));

    const res = await request.post('/back-channel-logout');
    assert.equal(res.headers['cache-control'], 'no-store');
  });

  it('should accept and store a valid logout_token', async () => {
    server = await createServer(auth(config));

    const res = await request.post('/back-channel-logout', {
      form: {
        logout_token: makeLogoutToken({ sid: 'foo' }),
      },
    });
    assert.equal(res.statusCode, 204);
    const { token } = await client.asyncGet('https://op.example.com/|foo');
    assert.equal(token.sid, 'foo');
  });

  it('should accept and store a valid logout_token signed with HS256', async () => {
    server = await createServer(auth(config));

    const res = await request.post('/back-channel-logout', {
      form: {
        logout_token: makeLogoutToken({
          sid: 'foo',
          secret: config.clientSecret,
        }),
      },
    });
    assert.equal(res.statusCode, 204);
    const { token } = await client.asyncGet('https://op.example.com/|foo');
    assert.equal(token.sid, 'foo');
  });

  it('should require a sid or a sub', async () => {
    server = await createServer(auth(config));

    const res = await request.post('/back-channel-logout', {
      form: {
        logout_token: makeLogoutToken(),
      },
    });
    assert.equal(res.statusCode, 400);
  });

  it('default implementation should require a sid', async () => {
    server = await createServer(auth(config));

    const res = await request.post('/back-channel-logout', {
      form: {
        logout_token: makeLogoutToken({ sub: 'foo' }),
      },
    });
    assert.equal(res.statusCode, 400);
  });

  it('should set a maxAge based on rolling expiry', async () => {
    server = await createServer(
      auth({ ...config, session: { rollingDuration: 999 } })
    );

    const res = await request.post('/back-channel-logout', {
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
      auth({ ...config, session: { absoluteDuration: 999, rolling: false } })
    );

    const res = await request.post('/back-channel-logout', {
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
        storeLogoutToken() {
          throw new Error('storage failure');
        },
      })
    );

    const res = await request.post('/back-channel-logout', {
      form: {
        logout_token: makeLogoutToken({ sid: 'foo' }),
      },
    });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'application_error');
  });

  it('should log user out on subsequent requests', async () => {
    server = await createServer(auth(config));
    const { jar } = await login(makeIdToken({ sid: '__foo_sid__' }));
    let body;
    ({ body } = await request.get('/session', {
      jar,
    }));
    assert.isNotEmpty(body);
    assert.isNotEmpty(jar.getCookies(baseUrl));

    const res = await request.post('/back-channel-logout', {
      baseUrl,
      form: {
        logout_token: makeLogoutToken({ sid: '__foo_sid__' }),
      },
    });
    assert.equal(res.statusCode, 204);
    const { token } = await client.asyncGet(
      'https://op.example.com/|__foo_sid__'
    );
    assert.equal(token.sid, '__foo_sid__');
    ({ body } = await request.get('/session', {
      jar,
    }));
    assert.isEmpty(jar.getCookies(baseUrl));
    assert.isUndefined(body);
  });

  it('should not log user out if login is after back-channel logout', async () => {
    const clock = sinon.useFakeTimers({ toFake: ['Date'], now: 60 * 1000 });
    server = await createServer(auth(config));

    const res = await request.post('/back-channel-logout', {
      baseUrl,
      form: {
        logout_token: makeLogoutToken({ sid: '__foo_sid__' }),
      },
    });
    assert.equal(res.statusCode, 204);
    const { token, cookie } = await client.asyncGet(
      'https://op.example.com/|__foo_sid__'
    );
    assert.equal(token.sid, '__foo_sid__');
    assert.equal(token.iat, 60);
    const day = 24 * 60 * 60 * 1000;
    assert.equal(cookie.expires, day + 60 * 1000);
    clock.tick(60 * 1000);

    const { jar } = await login(makeIdToken({ sid: '__foo_sid__' }));
    let body;
    ({ body } = await request.get('/tokens', {
      jar,
    }));
    assert.isNotEmpty(body);
    assert.equal(body.idTokenClaims.iat, 120);
    assert.isNotEmpty(jar.getCookies(baseUrl));

    ({ body } = await request.get('/session', {
      jar,
    }));
    assert.isNotEmpty(jar.getCookies(baseUrl));
    assert.isNotEmpty(body);
    clock.restore();
  });

  it('should handle failures to get logout token', async () => {
    server = await createServer(
      auth({
        ...config,
        getLogoutToken() {
          throw new Error('storage failure');
        },
      })
    );
    const { jar } = await login(makeIdToken({ sid: '__foo_sid__' }));
    let body;
    ({ body } = await request.get('/session', {
      jar,
    }));
    assert.deepEqual(body, { err: { message: 'storage failure' } });
  });
});

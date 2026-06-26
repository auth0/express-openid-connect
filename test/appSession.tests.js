const assert = require('chai').assert;
const crypto = require('crypto');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});
const sinon = require('sinon');

const appSession = require('../lib/appSession');
const { encrypted } = require('./fixture/sessionEncryption');
const { makeIdToken } = require('./fixture/cert');
const { get: getConfig } = require('../lib/config');
const { create: createServer } = require('./fixture/server');

const defaultConfig = {
  clientID: '__test_client_id__',
  clientSecret: '__test_client_secret__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'http://example.org',
  secret: '__test_secret__',
  errorOnRequiredAuth: true,
};

const login = async (claims) => {
  const jar = request.jar();
  await request.post('/session', {
    baseUrl,
    jar,
    json: {
      id_token: makeIdToken(claims),
    },
  });
  return jar;
};

const baseUrl = 'http://localhost:3000';

const HR_MS = 60 * 60 * 1000;

describe('appSession', () => {
  let server;

  afterEach(() => {
    if (server) {
      server.close();
    }
  });

  it('should not create a session when there are no cookies', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const res = await request.get('/session', { baseUrl, json: true });
    assert.isEmpty(res.body);
  });

  it('should not error for malformed sessions', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const res = await request.get('/session', {
      baseUrl,
      json: true,
      headers: {
        cookie: 'appSession=__invalid_identity__',
      },
    });
    assert.equal(res.statusCode, 200);
    assert.isEmpty(res.body);
  });

  it('should not error with JWEDecryptionFailed when using old secrets', async () => {
    server = await createServer(
      appSession(
        getConfig({
          ...defaultConfig,
          secret: 'another secret',
        }),
      ),
    );
    const res = await request.get('/session', {
      baseUrl,
      json: true,
      headers: {
        cookie: `appSession=${encrypted}`,
      },
    });
    assert.equal(res.statusCode, 200);
    assert.isEmpty(res.body);
  });

  it('should get an existing session', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const res = await request.get('/session', {
      baseUrl,
      json: true,
      headers: {
        cookie: `appSession=${encrypted}`,
      },
    });
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.sub, '__test_sub__');
  });

  it('should chunk and accept chunked cookies over 4kb', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const jar = request.jar();
    const random = crypto.randomBytes(4000).toString('base64');
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        sub: '__test_sub__',
        random,
      },
    });
    assert.deepEqual(
      jar.getCookies(baseUrl).map(({ key }) => key),
      ['appSession.0', 'appSession.1'],
    );
    const res = await request.get('/session', { baseUrl, json: true, jar });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, {
      sub: '__test_sub__',
      random,
    });
  });

  it('should limit total cookie size to 4096 Bytes', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const jar = request.jar();

    await request.post('session', {
      baseUrl,
      jar,
      json: {
        sub: '__test_sub__',
        random: crypto.randomBytes(8000).toString('base64'),
      },
    });

    const cookies = jar
      .getCookies(baseUrl)
      .reduce(
        (obj, value) => Object.assign(obj, { [value.key]: value + '' }),
        {},
      );

    assert.exists(cookies);
    assert.equal(cookies['appSession.0'].length, 4096);
    assert.equal(cookies['appSession.1'].length, 4096);
    assert.equal(cookies['appSession.2'].length, 4096);
    assert.isTrue(cookies['appSession.3'].length <= 4096);
  });

  it('should limit total cookie size to 4096 Bytes with custom path', async () => {
    const path =
      '/some-really-really-really-really-really-really-really-really-really-really-really-really-really-long-path';
    server = await createServer(
      appSession(
        getConfig({ ...defaultConfig, session: { cookie: { path } } }),
      ),
    );
    const jar = request.jar();

    await request.post('session', {
      baseUrl,
      jar,
      json: {
        sub: '__test_sub__',
        random: crypto.randomBytes(8000).toString('base64'),
      },
    });

    const cookies = jar
      .getCookies(`${baseUrl}${path}`)
      .reduce(
        (obj, value) => Object.assign(obj, { [value.key]: value + '' }),
        {},
      );

    assert.exists(cookies);
    assert.equal(cookies['appSession.0'].length, 4096);
    assert.equal(cookies['appSession.1'].length, 4096);
    assert.equal(cookies['appSession.2'].length, 4096);
    assert.isTrue(cookies['appSession.3'].length <= 4096);
  });

  it('should clean up single cookie when switching to chunked', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const jar = request.jar();
    jar.setCookie(`appSession=foo`, baseUrl);

    const firstCookies = jar
      .getCookies(baseUrl)
      .reduce(
        (obj, value) => Object.assign(obj, { [value.key]: value + '' }),
        {},
      );
    assert.property(firstCookies, 'appSession');

    await request.post('session', {
      baseUrl,
      jar,
      json: {
        sub: '__test_sub__',
        random: crypto.randomBytes(8000).toString('base64'),
      },
    });

    const cookies = jar
      .getCookies(baseUrl)
      .reduce(
        (obj, value) => Object.assign(obj, { [value.key]: value + '' }),
        {},
      );

    assert.property(cookies, 'appSession.0');
    assert.notProperty(cookies, 'appSession');
  });

  it('should clean up chunked cookies when switching to single cookie', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const jar = request.jar();
    jar.setCookie(`appSession.0=foo`, baseUrl);
    jar.setCookie(`appSession.1=foo`, baseUrl);

    const firstCookies = jar
      .getCookies(baseUrl)
      .reduce(
        (obj, value) => Object.assign(obj, { [value.key]: value + '' }),
        {},
      );
    assert.property(firstCookies, 'appSession.0');
    assert.property(firstCookies, 'appSession.1');

    await request.post('session', {
      baseUrl,
      jar,
      json: {
        sub: '__test_sub__',
      },
    });

    const cookies = jar
      .getCookies(baseUrl)
      .reduce(
        (obj, value) => Object.assign(obj, { [value.key]: value + '' }),
        {},
      );

    assert.property(cookies, 'appSession');
    assert.notProperty(cookies, 'appSession.0');
  });

  it('should handle unordered chunked cookies', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const jar = request.jar();
    const random = crypto.randomBytes(4000).toString('base64');
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        sub: '__test_sub__',
        random,
      },
    });
    const newJar = request.jar();
    jar
      .getCookies(baseUrl)
      .reverse()
      .forEach(({ key, value }) =>
        newJar.setCookie(`${key}=${value}`, baseUrl),
      );
    assert.deepEqual(
      newJar.getCookies(baseUrl).map(({ key }) => key),
      ['appSession.1', 'appSession.0'],
    );
    const res = await request.get('/session', {
      baseUrl,
      json: true,
      jar: newJar,
    });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, {
      sub: '__test_sub__',
      random,
    });
  });

  it('should not throw for malformed cookie chunks', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const jar = request.jar();
    jar.setCookie('appSession.0=foo', baseUrl);
    jar.setCookie('appSession.1=bar', baseUrl);
    const res = await request.get('/session', { baseUrl, json: true, jar });
    assert.equal(res.statusCode, 200);
  });

  it('should set the default cookie options over http', async () => {
    server = await createServer(
      appSession(
        getConfig({ ...defaultConfig, baseURL: 'http://example.org' }),
      ),
    );
    const jar = request.jar();
    await request.get('/session', {
      baseUrl,
      json: true,
      jar,
      headers: {
        cookie: `appSession=${encrypted}`,
      },
    });
    const [cookie] = jar.getCookies(baseUrl);
    assert.deepInclude(cookie, {
      key: 'appSession',
      domain: 'localhost',
      path: '/',
      httpOnly: true,
      extensions: ['SameSite=Lax'],
    });
    const expDate = new Date(cookie.expires);
    const now = Date.now();
    assert.approximately(Math.floor((expDate - now) / 1000), 86400, 5);
  });

  it('should set the default cookie options over https', async () => {
    server = await createServer(
      appSession(
        getConfig({ ...defaultConfig, baseURL: 'https://example.org' }),
      ),
    );
    const jar = request.jar();
    await request.get('/session', {
      baseUrl,
      json: true,
      jar,
      headers: {
        cookie: `appSession=${encrypted}`,
      },
    });
    // Secure cookies not set over http
    assert.isEmpty(jar.getCookies(baseUrl));
  });

  it('should set the custom cookie options', async () => {
    server = await createServer(
      appSession(
        getConfig({
          ...defaultConfig,
          session: {
            cookie: {
              httpOnly: false,
              sameSite: 'Strict',
            },
          },
        }),
      ),
    );
    const jar = request.jar();
    await request.get('/session', {
      baseUrl,
      json: true,
      jar,
      headers: {
        cookie: `appSession=${encrypted}`,
      },
    });
    const [cookie] = jar.getCookies(baseUrl);
    assert.deepInclude(cookie, {
      key: 'appSession',
      httpOnly: false,
      extensions: ['SameSite=Strict'],
    });
  });

  it('should disregard custom id generation without a custom store', async () => {
    server = await createServer(
      appSession(
        getConfig({
          ...defaultConfig,
          session: {
            genid: () => {
              throw 'this should not be called';
            }, //consider using chai-spies
          },
        }),
      ),
    );
    const jar = request.jar();
    const res = await request.get('/session', {
      baseUrl,
      json: true,
      jar,
      headers: {
        cookie: `appSession=${encrypted}`,
      },
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.sub, '__test_sub__');
  });

  it('should use a custom cookie name', async () => {
    server = await createServer(
      appSession(
        getConfig({
          ...defaultConfig,
          session: { name: 'customName' },
        }),
      ),
    );
    const jar = request.jar();
    const res = await request.get('/session', {
      baseUrl,
      json: true,
      jar,
      headers: {
        cookie: `customName=${encrypted}`,
      },
    });
    const [cookie] = jar.getCookies(baseUrl);
    assert.equal(res.statusCode, 200);
    assert.equal(cookie.key, 'customName');
  });

  it('should set an ephemeral cookie', async () => {
    server = await createServer(
      appSession(
        getConfig({
          ...defaultConfig,
          session: { cookie: { transient: true } },
        }),
      ),
    );
    const jar = request.jar();
    const res = await request.get('/session', {
      baseUrl,
      json: true,
      jar,
      headers: {
        cookie: `appSession=${encrypted}`,
      },
    });
    const [cookie] = jar.getCookies(baseUrl);
    assert.equal(res.statusCode, 200);
    assert.isFalse(cookie.hasOwnProperty('expires'));
  });

  it('should not throw for expired cookies', async () => {
    const twoWeeks = 2 * 7 * 24 * 60 * 60 * 1000;
    const clock = sinon.useFakeTimers({
      now: Date.now(),
      toFake: ['Date'],
    });
    server = await createServer(appSession(getConfig(defaultConfig)));
    const jar = request.jar();
    clock.tick(twoWeeks);
    const res = await request.get('/session', {
      baseUrl,
      json: true,
      jar,
      headers: {
        cookie: `appSession=${encrypted}`,
      },
    });
    assert.equal(res.statusCode, 200);
    clock.restore();
  });

  it('should write session cookie even when headers are flushed before res.end()', async () => {
    /*
     * Session cookie is now written via on-headers (fires at writeHead time), so it is
     * set correctly regardless of whether the response is buffered or streamed.
     * Scenarios covered: res.write(), res.flushHeaders(), res.writeHead(), res.sendFile(),
     * res.download(), or stream.pipe(res).
     */
    server = await createServer((req, res) => {
      appSession(getConfig(defaultConfig))(req, res, () => {
        // Modify the session so setCookie would normally write a cookie
        Object.assign(req.appSession, { sub: '__test_sub__' });
        // Flush headers before res.end() — simulates streaming SSR and similar patterns
        res.write('chunk');
        res.end();
      });
    });
    const res = await request.get('/session', { baseUrl });
    // on-headers fires at writeHead time, so the session cookie must be set
    assert.property(res.headers, 'set-cookie');
  });

  it('should throw for duplicate mw', async () => {
    server = await createServer((req, res, next) => {
      req.appSession = {};
      appSession(getConfig(defaultConfig))(req, res, next);
    });
    const res = await request.get('/session', { baseUrl, json: true });
    assert.equal(res.statusCode, 500);
    assert.equal(
      res.body.err.message,
      'req[appSession] is already set, did you run this middleware twice?',
    );
  });

  it('should throw for reassigning session', async () => {
    server = await createServer((req, res, next) => {
      appSession(getConfig(defaultConfig))(req, res, () => {
        try {
          req.appSession = {};
          next();
        } catch (e) {
          next(e);
        }
      });
    });
    const res = await request.get('/session', { baseUrl, json: true });
    assert.equal(res.statusCode, 500);
    assert.equal(res.body.err.message, 'session object cannot be reassigned');
  });

  it('should not throw for reassigining session to empty', async () => {
    server = await createServer((req, res, next) => {
      appSession(getConfig(defaultConfig))(req, res, () => {
        req.appSession = null;
        req.appSession = undefined;
        next();
      });
    });
    const res = await request.get('/session', { baseUrl, json: true });
    assert.equal(res.statusCode, 200);
  });

  it('should expire after 24hrs of inactivity by default', async () => {
    const clock = sinon.useFakeTimers({ toFake: ['Date'] });
    server = await createServer(appSession(getConfig(defaultConfig)));
    const jar = await login({ sub: '__test_sub__' });
    let res = await request.get('/session', { baseUrl, jar, json: true });
    assert.isNotEmpty(res.body);
    clock.tick(23 * HR_MS);
    res = await request.get('/session', { baseUrl, jar, json: true });
    assert.isNotEmpty(res.body);
    clock.tick(25 * HR_MS);
    res = await request.get('/session', { baseUrl, jar, json: true });
    assert.isEmpty(res.body);
    clock.restore();
  });

  it('should expire after 7days regardless of activity by default', async () => {
    const clock = sinon.useFakeTimers({ toFake: ['Date'] });
    server = await createServer(appSession(getConfig(defaultConfig)));
    const jar = await login({ sub: '__test_sub__' });
    let days = 7;
    while (days--) {
      clock.tick(23 * HR_MS);
      let res = await request.get('/session', { baseUrl, jar, json: true });
      assert.isNotEmpty(res.body);
    }
    clock.tick(8 * HR_MS);
    let res = await request.get('/session', { baseUrl, jar, json: true });
    assert.isEmpty(res.body);
    clock.restore();
  });

  it('should expire only after defined absoluteDuration', async () => {
    const clock = sinon.useFakeTimers({ toFake: ['Date'] });
    server = await createServer(
      appSession(
        getConfig({
          ...defaultConfig,
          session: {
            rolling: false,
            absoluteDuration: 10 * 60 * 60,
          },
        }),
      ),
    );
    const jar = await login({ sub: '__test_sub__' });
    clock.tick(9 * HR_MS);
    let res = await request.get('/session', { baseUrl, jar, json: true });
    assert.isNotEmpty(res.body);
    clock.tick(2 * HR_MS);
    res = await request.get('/session', { baseUrl, jar, json: true });
    assert.isEmpty(res.body);
    clock.restore();
  });

  it('should expire only after defined rollingDuration period of inactivty', async () => {
    const clock = sinon.useFakeTimers({ toFake: ['Date'] });
    server = await createServer(
      appSession(
        getConfig({
          ...defaultConfig,
          session: {
            rolling: true,
            rollingDuration: 24 * 60 * 60,
            absoluteDuration: false,
          },
        }),
      ),
    );
    const jar = await login({ sub: '__test_sub__' });
    let days = 30;
    while (days--) {
      clock.tick(23 * HR_MS);
      let res = await request.get('/session', { baseUrl, jar, json: true });
      assert.isNotEmpty(res.body);
    }
    clock.tick(25 * HR_MS);
    let res = await request.get('/session', { baseUrl, jar, json: true });
    assert.isEmpty(res.body);
    clock.restore();
  });

  describe('session_expiry (IPSIE)', () => {
    it('should expire the session when sessionExpiresAt ceiling is reached', async () => {
      const clock = sinon.useFakeTimers({ toFake: ['Date'] });
      server = await createServer(appSession(getConfig(defaultConfig)));

      // Login with a sessionExpiresAt 2 hours from now
      const jar = request.jar();
      const sessionExpiresAt = Math.floor(Date.now() / 1000) + 2 * 60 * 60;
      await request.post('/session', {
        baseUrl,
        jar,
        json: { sub: '__test_sub__', sessionExpiresAt },
      });

      // Before ceiling: session is valid
      let res = await request.get('/session', { baseUrl, jar, json: true });
      assert.isNotEmpty(res.body);

      // Tick past the ceiling
      clock.tick(3 * HR_MS);
      res = await request.get('/session', { baseUrl, jar, json: true });
      assert.isEmpty(res.body);

      clock.restore();
    });

    it('should not expire the session when ceiling is in the future', async () => {
      server = await createServer(appSession(getConfig(defaultConfig)));
      const jar = request.jar();
      const sessionExpiresAt = Math.floor(Date.now() / 1000) + 8 * 60 * 60;
      await request.post('/session', {
        baseUrl,
        jar,
        json: { sub: '__test_sub__', sessionExpiresAt },
      });

      const res = await request.get('/session', { baseUrl, jar, json: true });
      assert.isNotEmpty(res.body);
      assert.equal(res.body.sessionExpiresAt, sessionExpiresAt);
    });

    it('should not affect sessions without sessionExpiresAt (non-breaking)', async () => {
      const clock = sinon.useFakeTimers({ toFake: ['Date'] });
      server = await createServer(appSession(getConfig(defaultConfig)));
      const jar = await login({ sub: '__test_sub__' });

      // Advance well within rolling duration — no sessionExpiresAt, should still be valid
      clock.tick(23 * HR_MS);
      const res = await request.get('/session', { baseUrl, jar, json: true });
      assert.isNotEmpty(res.body);

      clock.restore();
    });

    it('should cap the cookie maxAge at sessionExpiresAt when it is sooner than absoluteDuration', async () => {
      server = await createServer(
        appSession(
          getConfig({
            ...defaultConfig,
            session: {
              rolling: false,
              absoluteDuration: 7 * 24 * 60 * 60, // 7 days
            },
          }),
        ),
      );

      const jar = request.jar();
      const sessionExpiresAt = Math.floor(Date.now() / 1000) + 2 * 60 * 60; // 2 hours
      await request.post('/session', {
        baseUrl,
        jar,
        json: { sub: '__test_sub__', sessionExpiresAt },
      });

      await request.get('/session', { baseUrl, jar, json: true });
      const [cookie] = jar.getCookies(baseUrl);
      const expDate = new Date(cookie.expires);
      const expSeconds = Math.floor(expDate.getTime() / 1000);

      // Cookie should expire at sessionExpiresAt (2 hours), not at absoluteDuration (7 days)
      assert.approximately(expSeconds, sessionExpiresAt, 5);
    });
  });
});

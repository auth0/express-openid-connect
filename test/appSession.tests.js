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

  describe('MCD: Domain Migration Support', () => {
    const { resetIssuerManager } = require('../lib/issuerManager');

    beforeEach(() => {
      resetIssuerManager();
    });

    afterEach(() => {
      resetIssuerManager();
    });

    it('should accept session with issuer in MCD mode', async () => {
      // Session has issuer - should be accepted (bound to original issuer)
      const mcdConfig = {
        ...defaultConfig,
        issuerBaseURL: () => 'https://tenant-a.auth0.com',
      };
      server = await createServer(appSession(getConfig(mcdConfig)));

      // Create session with issuer
      const jar = request.jar();
      await request.post('/session', {
        baseUrl,
        jar,
        json: {
          sub: '__test_sub__',
          issuer: 'https://tenant-a.auth0.com',
        },
      });

      // Session should be valid - has issuer field
      const res = await request.get('/session', { baseUrl, jar, json: true });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body.sub, '__test_sub__');
      assert.equal(res.body.issuer, 'https://tenant-a.auth0.com');
    });

    it('should accept session bound to different issuer in MCD mode (no cross-issuer validation)', async () => {
      // RFC: Sessions remain bound to their original issuer
      // A session created with tenant-b should be accepted even when resolver returns tenant-a
      const mcdConfig = {
        ...defaultConfig,
        issuerBaseURL: () => 'https://tenant-a.auth0.com', // Resolver returns tenant-a
      };
      server = await createServer(appSession(getConfig(mcdConfig)));

      // Create session bound to tenant-b (different from resolver)
      const jar = request.jar();
      await request.post('/session', {
        baseUrl,
        jar,
        json: {
          sub: '__test_sub__',
          issuer: 'https://tenant-b.auth0.com', // Different issuer - should still be accepted
        },
      });

      // Session should be accepted - it has a valid issuer (bound to original issuer)
      const res = await request.get('/session', { baseUrl, jar, json: true });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body.sub, '__test_sub__');
      assert.equal(res.body.issuer, 'https://tenant-b.auth0.com'); // Still bound to tenant-b
    });

    it('should reject session without issuer field in MCD mode', async () => {
      // MCD mode with session missing issuer (pre-MCD legacy session)
      const mcdConfig = {
        ...defaultConfig,
        issuerBaseURL: () => 'https://tenant-a.auth0.com',
      };
      server = await createServer(appSession(getConfig(mcdConfig)));

      // Create session WITHOUT issuer field (simulates pre-MCD session)
      const jar = request.jar();
      await request.post('/session', {
        baseUrl,
        jar,
        json: {
          sub: '__test_sub__',
          // No issuer field!
        },
      });

      // Session should be rejected in MCD mode - missing issuer
      const res = await request.get('/session', { baseUrl, jar, json: true });
      assert.equal(res.statusCode, 200);
      assert.isEmpty(res.body); // Session cleared
    });

    it('should accept session without issuer in static mode', async () => {
      // Static issuerBaseURL - should work without issuer field
      server = await createServer(appSession(getConfig(defaultConfig)));

      // Create session without issuer field
      const jar = request.jar();
      await request.post('/session', {
        baseUrl,
        jar,
        json: {
          sub: '__test_sub__',
          // No issuer field - should work in static mode
        },
      });

      // Session should be valid - static mode doesn't require issuer
      const res = await request.get('/session', { baseUrl, jar, json: true });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body.sub, '__test_sub__');
    });

    it('should work with async issuer resolver', async () => {
      // Async resolver function
      const mcdConfig = {
        ...defaultConfig,
        issuerBaseURL: async () => {
          // Simulate async database lookup
          await new Promise((resolve) => setTimeout(resolve, 10));
          return 'https://tenant-a.auth0.com';
        },
      };
      server = await createServer(appSession(getConfig(mcdConfig)));

      // Create session with issuer
      const jar = request.jar();
      await request.post('/session', {
        baseUrl,
        jar,
        json: {
          sub: '__test_sub__',
          issuer: 'https://tenant-a.auth0.com',
        },
      });

      // Session should be valid
      const res = await request.get('/session', { baseUrl, jar, json: true });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body.sub, '__test_sub__');
    });

    it('should keep session bound to original issuer when switching domains', async () => {
      // RFC: existing session remain bound to original issuer
      // new session will be created with different issuer (when user re-authenticates)
      let currentTenant = 'tenant-a';
      const mcdConfig = {
        ...defaultConfig,
        issuerBaseURL: () => `https://${currentTenant}.auth0.com`,
      };
      server = await createServer(appSession(getConfig(mcdConfig)));

      // Create session as tenant-a
      const jar = request.jar();
      await request.post('/session', {
        baseUrl,
        jar,
        json: {
          sub: '__tenant_a_user__',
          issuer: 'https://tenant-a.auth0.com',
        },
      });

      // Verify session works for tenant-a
      let res = await request.get('/session', { baseUrl, jar, json: true });
      assert.equal(res.body.sub, '__tenant_a_user__');
      assert.equal(res.body.issuer, 'https://tenant-a.auth0.com');

      // Now switch resolver to tenant-b (simulating user visiting different domain)
      currentTenant = 'tenant-b';

      // Session should STILL be accepted - bound to original issuer (tenant-a)
      res = await request.get('/session', { baseUrl, jar, json: true });
      assert.equal(res.body.sub, '__tenant_a_user__');
      assert.equal(res.body.issuer, 'https://tenant-a.auth0.com'); // Still bound to tenant-a
    });
  });
});

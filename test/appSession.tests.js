const assert = require('chai').assert;
const crypto = require('crypto');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

const appSession = require('../lib/appSession');
const sessionEncryption = require('./fixture/sessionEncryption');
const { get: getConfig } = require('../lib/config');
const { create: createServer } = require('./fixture/server');

const defaultConfig = {
  clientID: '__test_client_id__',
  clientSecret: '__test_client_secret__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org',
  secret: '__test_secret__',
};

const baseUrl = 'http://localhost:3000';

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
    const res = await request.get('/session', { baseUrl, json: true, headers: {
      cookie: 'appSession=__invalid_identity__'
    }});
    assert.equal(res.statusCode, 200);
    assert.isEmpty(res.body);
  });

  it('should not error with JWEDecryptionFailed when using old secrets', async () => {
    server = await createServer(appSession(getConfig({
      ...defaultConfig,
      secret: 'another secret'
    })));
    const res = await request.get('/session', { baseUrl, json: true, headers: {
      cookie: `appSession=${sessionEncryption.encrypted}`
    }});
    assert.equal(res.statusCode, 200);
    assert.isEmpty(res.body);
  });

  it('should get an existing session', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const res = await request.get('/session', { baseUrl, json: true, headers: {
      cookie: `appSession=${sessionEncryption.encrypted}`
    }});
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.sub, '__test_sub__');
  });

  it('should chunk and accept chunked cookies over 4kb', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const jar = request.jar();
    const random = crypto.randomBytes(4000).toString('base64');
    jar.setCookie(`appSession=${sessionEncryption.encrypt({
      sub: '__test_sub__',
      random
    })}`, baseUrl);
    const res = await request.get('/session', { baseUrl, json: true, jar });
    jar.setCookie(`appSession=;expires=${new Date(0)}`, baseUrl);
    const cookieString = jar.getCookieString(baseUrl);
    const cookies = jar.getCookies(baseUrl);
    assert.lengthOf(cookies, 2);
    assert.match(cookieString, /appSession\.0=.+; ?appSession\.1=.+/);
    const res2 = await request.get('/session', { baseUrl, json: true, jar });
    assert.equal(res2.statusCode, 200);
    assert.deepEqual(res.body, {
      sub: '__test_sub__',
      random
    });
  });

  it('should set the default cookie options', async () => {
    server = await createServer(appSession(getConfig(defaultConfig)));
    const jar = request.jar();
    await request.get('/session', { baseUrl, json: true, jar, headers: {
      cookie: `appSession=${sessionEncryption.encrypted}`
    }});
    const [ cookie ] = jar.getCookies(baseUrl);
    assert.deepInclude(cookie, {
      key: 'appSession',
      domain: 'localhost',
      path: '/',
      httpOnly: true,
      extensions: [
        'SameSite=Lax'
      ]
    });
    const expDate = new Date(cookie.expires);
    const now = Date.now();
    assert.approximately(Math.floor((expDate - now) / 1000), 86400, 5);
  });

  it('should set the custom cookie options', async () => {
    server = await createServer(appSession(getConfig({
      ...defaultConfig,
      session: {
        cookie: {
          httpOnly: false,
          sameSite: 'Strict'
        }
      }
    })));
    const jar = request.jar();
    await request.get('/session', { baseUrl, json: true, jar, headers: {
      cookie: `appSession=${sessionEncryption.encrypted}`
    }});
    const [ cookie ] = jar.getCookies(baseUrl);
    assert.deepInclude(cookie, {
      key: 'appSession',
      httpOnly: false,
      extensions: [
        'SameSite=Strict'
      ]
    });
  });

  it('should use a custom cookie name', async () => {
    server = await createServer(appSession(getConfig({
      ...defaultConfig,
      session: { name: 'customName' }
    })));
    const jar = request.jar();
    const res = await request.get('/session', { baseUrl, json: true, jar, headers: {
      cookie: `customName=${sessionEncryption.encrypted}`
    }});
    const [ cookie ] = jar.getCookies(baseUrl);
    assert.equal(res.statusCode, 200);
    assert.equal(cookie.key, 'customName');
  });

  it('should set an ephemeral cookie', async () => {
    server = await createServer(appSession(getConfig({
      ...defaultConfig,
      session: { cookie: { transient: true } }
    })));
    const jar = request.jar();
    const res = await request.get('/session', { baseUrl, json: true, jar, headers: {
      cookie: `appSession=${sessionEncryption.encrypted}`
    }});
    const [ cookie ] = jar.getCookies(baseUrl);
    assert.equal(res.statusCode, 200);
    assert.isFalse(cookie.hasOwnProperty('expires'));
  });

});

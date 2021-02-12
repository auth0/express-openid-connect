const { promisify } = require('util');
const assert = require('chai').assert;
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});

const appSession = require('../lib/appSession');
const { get: getConfig } = require('../lib/config');
const { create: createServer } = require('./fixture/server');
const redis = require('redis-mock');
const RedisStore = require('connect-redis')({ Store: class Store {} });

const defaultConfig = {
  clientID: '__test_client_id__',
  clientSecret: '__test_client_secret__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'http://example.org',
  secret: '__test_secret__',
  errorOnRequiredAuth: true,
};

const sessionData = () => {
  const epoch = () => (Date.now() / 1000) | 0;
  const epochNow = epoch();
  const weekInSeconds = 7 * 24 * 60 * 60;

  return JSON.stringify({
    header: {
      uat: epochNow,
      iat: epochNow,
      exp: epochNow + weekInSeconds,
    },
    data: { sub: '__test_sub__' },
  });
};

const login = async (claims) => {
  const jar = request.jar();
  await request.post('/session', {
    baseUrl,
    jar,
    json: claims,
  });
  return jar;
};

const baseUrl = 'http://localhost:3000';

describe('appSession custom store', () => {
  let server;
  let redisClient;

  const setup = async (config) => {
    redisClient = redis.createClient();
    const store = new RedisStore({ client: redisClient, prefix: '' });
    redisClient.asyncSet = promisify(redisClient.set).bind(redisClient);
    redisClient.asyncGet = promisify(redisClient.set).bind(redisClient);

    const conf = getConfig({
      ...defaultConfig,
      sessionStore: store,
      ...config,
    });

    server = await createServer(appSession(conf));
  };

  afterEach(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    if (redisClient) {
      await new Promise((resolve) => redisClient.quit(resolve));
    }
  });

  it('should not create a session when there are no cookies', async () => {
    await setup();
    const res = await request.get('/session', { baseUrl, json: true });
    assert.isEmpty(res.body);
  });

  it('should not error for non existent sessions', async () => {
    await setup();
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

  it('should get an existing session', async () => {
    await setup();
    await redisClient.asyncSet('foo', sessionData());
    const jar = request.jar();
    const res = await request.get('/session', {
      baseUrl,
      jar,
      json: true,
      headers: {
        cookie: `appSession=foo`,
      },
    });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { sub: '__test_sub__' });
    const [cookie] = jar.getCookies(baseUrl);
    assert.deepInclude(cookie, {
      key: 'appSession',
      value: 'foo',
    });
  });

  it('should get a new session', async () => {
    await setup();
    const jar = await login({ sub: '__foo_user__' });
    const res = await request.get('/session', {
      baseUrl,
      jar,
      json: true,
    });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { sub: '__foo_user__' });
  });

  it('should destroy an existing session', async () => {
    await setup({ idpLogout: false });
    await redisClient.asyncSet('foo', sessionData());
    const jar = request.jar();
    const res = await request.get('/session', {
      baseUrl,
      jar,
      json: true,
      headers: {
        cookie: `appSession=foo`,
      },
    });
    assert.deepEqual(res.body, { sub: '__test_sub__' });
    await request.post('/session', {
      baseUrl,
      jar,
      json: {},
    });
    const loggedOutRes = await request.get('/session', {
      baseUrl,
      jar,
      json: true,
    });
    assert.isEmpty(loggedOutRes.body);
    assert.isEmpty(jar.getCookies(baseUrl));
  });
});

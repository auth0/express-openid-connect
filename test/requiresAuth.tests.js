const { assert } = require('chai');
const sinon = require('sinon');
const { create: createServer } = require('./fixture/server');
const { makeIdToken } = require('./fixture/cert');
const {
  auth,
  requiresAuth,
  claimEquals,
  claimIncludes,
  claimCheck,
} = require('./..');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
  followRedirect: false,
});

const baseUrl = 'http://localhost:3000';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
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

describe('requiresAuth', () => {
  let server;

  afterEach(async () => {
    if (server) {
      server.close();
    }
  });

  it('should allow logged in users to visit a protected route', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      requiresAuth()
    );
    const jar = await login();
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 200);
  });

  it('should ask anonymous user to login when visiting a protected route', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      requiresAuth()
    );
    const response = await request({ baseUrl, url: '/protected' });
    const state = new URL(response.headers.location).searchParams.get('state');
    const decoded = Buffer.from(state, 'base64');
    const parsed = JSON.parse(decoded);

    assert.equal(response.statusCode, 302);
    assert.include(response.headers.location, 'https://op.example.com');
    assert.equal(parsed.returnTo, '/protected');
  });

  it("should 401 for anonymous users who don't accept html", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      requiresAuth()
    );
    const response = await request({ baseUrl, url: '/protected', json: true });
    assert.equal(response.statusCode, 401);
  });

  it('should return 401 when anonymous user visits a protected route', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      requiresAuth()
    );
    const response = await request({ baseUrl, url: '/protected' });

    assert.equal(response.statusCode, 401);
  });

  it("should throw when there's no auth middleware", async () => {
    server = await createServer(null, requiresAuth());
    const {
      body: { err },
    } = await request({ baseUrl, url: '/protected', json: true });
    assert.equal(
      err.message,
      'req.oidc is not found, did you include the auth middleware?'
    );
  });

  it('should allow logged in users with the right claim', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimEquals('foo', 'bar')
    );
    const jar = await login({ foo: 'bar' });
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 200);
  });

  it("should return 401 when logged in user doesn't have the right value for claim", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimEquals('foo', 'bar')
    );
    const jar = await login({ foo: 'baz' });
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 401);
  });

  it("should return 401 when logged in user doesn't have the claim", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimEquals('baz', 'bar')
    );
    const jar = await login({ foo: 'bar' });
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 401);
  });

  it("should return 401 when anonymous user doesn't have the right claim", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimEquals('foo', 'bar')
    );
    const response = await request({ baseUrl, url: '/protected' });

    assert.equal(response.statusCode, 401);
  });

  it('should throw when claim is not a string', () => {
    assert.throws(
      () => claimEquals(true, 'bar'),
      TypeError,
      '"claim" must be a string'
    );
  });

  it('should throw when claim value is a non primitive', () => {
    assert.throws(
      () => claimEquals('foo', { bar: 1 }),
      TypeError,
      '"expected" must be a string, number, boolean or null'
    );
  });

  it('should allow logged in users with all of the requested claims', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz')
    );
    const jar = await login({ foo: ['baz', 'bar'] });
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 200);
  });

  it('should return 401 for logged with some of the requested claims', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz', 'qux')
    );
    const jar = await login({ foo: 'baz bar' });
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 401);
  });

  it('should accept claim values as a space separated list', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz')
    );
    const jar = await login({ foo: 'baz bar' });
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 200);
  });

  it("should not accept claim values that aren't a string or array", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz')
    );
    const jar = await login({ foo: { bar: 'baz' } });
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 401);
  });

  it('should throw when claim value for checking many claims is a non primitive', () => {
    assert.throws(
      () => claimIncludes(false, 'bar'),
      TypeError,
      '"claim" must be a string'
    );
  });

  it("should return 401 when checking multiple claims and the user doesn't have the claim", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz')
    );
    const jar = await login({ bar: 'bar baz' });
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 401);
  });

  it('should return 401 when checking many claims with anonymous user', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz')
    );
    const response = await request({ baseUrl, url: '/protected' });

    assert.equal(response.statusCode, 401);
  });

  it("should throw when custom claim check doesn't get a function", async () => {
    assert.throws(
      () => claimCheck(null),
      TypeError,
      '"claimCheck" expects a function'
    );
  });

  it('should allow user when custom claim check returns truthy', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimCheck(() => true)
    );
    const jar = await login();
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 200);
  });

  it('should not allow user when custom claim check returns falsey', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimCheck(() => false)
    );
    const jar = await login();
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 401);
  });

  it('should make the token claims available to custom check', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimCheck((req, claims) => claims.foo === 'some_claim')
    );
    const jar = await login({ foo: 'some_claim' });
    const response = await request({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 200);
  });

  it('should not allow anonymous users to check custom claims', async () => {
    const checkSpy = sinon.spy();
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimCheck(checkSpy)
    );
    const response = await request({ baseUrl, url: '/protected' });

    assert.equal(response.statusCode, 401);
    sinon.assert.notCalled(checkSpy);
  });

  it('should collapse leading slashes on returnTo', async () => {
    server = await createServer(auth(defaultConfig));
    const payloads = ['//google.com', '///google.com', '//google.com'];
    for (const payload of payloads) {
      const response = await request({ url: `${baseUrl}${payload}` });
      const state = new URL(response.headers.location).searchParams.get(
        'state'
      );
      const decoded = Buffer.from(state, 'base64');
      const parsed = JSON.parse(decoded);

      assert.equal(response.statusCode, 302);
      assert.include(response.headers.location, 'https://op.example.com');
      assert.equal(parsed.returnTo, '/google.com');
    }
  });
});

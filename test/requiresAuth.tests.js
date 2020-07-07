const { assert } = require('chai');
const { create: createServer } = require('./fixture/server');
const { auth, requiresAuth } = require('./..');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
  followRedirect: false
});

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'https://example.org',
  issuerBaseURL: 'https://op.example.com',
};

describe('requiresAuth', () => {

  let server;
  const baseUrl = 'http://localhost:3000';

  afterEach(async () => {
    if (server) {
      server.close();
    }
  });

  it('should ask anonymous user to login when visiting a protected route', async () => {
    server = await createServer(auth({
      ...defaultConfig,
      authRequired: false
    }), requiresAuth());
    const response = await request({ baseUrl, url: '/protected' });
    const state = (new URL(response.headers.location)).searchParams.get('state');
    const decoded = Buffer.from(state, 'base64');
    const parsed = JSON.parse(decoded);

    assert.equal(response.statusCode, 302);
    assert.include(response.headers.location, 'https://op.example.com');
    assert.equal(parsed.returnTo, '/protected');
  });

  it('should return 401 when anonymous user visits a protected route', async () => {
    server = await createServer(auth({
      ...defaultConfig,
      authRequired: false,
      errorOnRequiredAuth: true
    }), requiresAuth());
    const response = await request({ baseUrl, url: '/protected' });

    assert.equal(response.statusCode, 401);
  });

  it('should throw when no auth middleware', async () => {
    server = await createServer(null, requiresAuth());
    const { body: { err } } = await request({ baseUrl, url: '/protected', json: true });
    assert.equal(err.message, 'req.oidc is not found, did you include the auth middleware?');
  });
});

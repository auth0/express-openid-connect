const { assert } = require('chai').use(require('chai-as-promised'));
const nock = require('nock');
const { get: getConfig } = require('../../lib/config');
const { requestToken, logout } = require('../../lib/anonymousSession/client');
const { AnonymousSessionError } = require('../../lib/anonymousSession/errors');
const pkg = require('../../package.json');

const baseConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org',
  authRequired: false,
};

const tokenResponse = {
  access_token: '__test_access_token__',
  session_token: '__test_session_token__',
  token_type: 'Bearer',
  expires_in: 604800,
  session_expires_in: 2592000,
};

describe('anonymousSession client', () => {
  describe('requestToken', () => {
    it('creates a new session (no session_token) and returns the token set', async () => {
      const config = getConfig(baseConfig);
      let capturedBody;
      nock('https://op.example.com')
        .post('/anonymous/token', (body) => {
          capturedBody = body;
          return true;
        })
        .reply(200, tokenResponse);

      const result = await requestToken(config, {
        audience: 'https://api.example.com',
        scope: 'read:cart',
        metadata: { cart_id: 'cart_123' },
      });

      assert.deepEqual(result, tokenResponse);
      assert.equal(capturedBody.audience, 'https://api.example.com');
      assert.equal(capturedBody.scope, 'read:cart');
      assert.deepEqual(capturedBody.metadata, { cart_id: 'cart_123' });
      assert.notProperty(capturedBody, 'session_token');
    });

    it('renews with an existing session_token and omits metadata', async () => {
      const config = getConfig(baseConfig);
      let capturedBody;
      nock('https://op.example.com')
        .post('/anonymous/token', (body) => {
          capturedBody = body;
          return true;
        })
        .reply(200, { ...tokenResponse, session_token: undefined });

      const result = await requestToken(config, {
        session_token: '__existing_session_token__',
      });

      assert.equal(result.access_token, '__test_access_token__');
      assert.equal(capturedBody.session_token, '__existing_session_token__');
    });

    it('sends the default headers (User-Agent + Auth0-Client telemetry)', async () => {
      const config = getConfig(baseConfig);
      let headers;
      nock('https://op.example.com')
        .post('/anonymous/token')
        .reply(200, function () {
          headers = this.req.headers;
          return tokenResponse;
        });

      await requestToken(config, {});

      assert.equal(
        headers['user-agent'],
        `express-openid-connect/${pkg.version}`,
      );
      assert.exists(headers['auth0-client']);
    });

    it('omits the Auth0-Client header when telemetry is disabled', async () => {
      const config = getConfig({ ...baseConfig, enableTelemetry: false });
      let headers;
      nock('https://op.example.com')
        .post('/anonymous/token')
        .reply(200, function () {
          headers = this.req.headers;
          return tokenResponse;
        });

      await requestToken(config, {});

      assert.notExists(headers['auth0-client']);
    });

    it('sends Basic client authentication for a confidential client', async () => {
      const config = getConfig({
        ...baseConfig,
        clientSecret: '__test_client_secret__',
        clientAuthMethod: 'client_secret_basic',
      });
      let headers;
      nock('https://op.example.com')
        .post('/anonymous/token')
        .reply(200, function () {
          headers = this.req.headers;
          return tokenResponse;
        });

      await requestToken(config, {});

      const expected =
        'Basic ' +
        Buffer.from('__test_client_id__:__test_client_secret__').toString(
          'base64',
        );
      assert.equal(headers['authorization'], expected);
    });

    it('sends client_id in the body for a public client', async () => {
      const config = getConfig(baseConfig);
      let capturedBody;
      nock('https://op.example.com')
        .post('/anonymous/token', (body) => {
          capturedBody = body;
          return true;
        })
        .reply(200, tokenResponse);

      await requestToken(config, {});

      assert.equal(capturedBody.client_id, '__test_client_id__');
    });

    it('throws AnonymousSessionError with the error code on a 4xx', async () => {
      const config = getConfig(baseConfig);
      nock('https://op.example.com').post('/anonymous/token').reply(400, {
        error: 'metadata_too_large',
        error_description: 'Attempted to grow metadata over 1kB limit',
      });

      const err = await requestToken(config, {}).then(
        () => null,
        (e) => e,
      );

      assert.instanceOf(err, AnonymousSessionError);
      assert.equal(err.code, 'metadata_too_large');
      assert.equal(err.statusCode, 400);
    });

    it('throws AnonymousSessionError with server_error on a 500', async () => {
      const config = getConfig(baseConfig);
      nock('https://op.example.com')
        .post('/anonymous/token')
        .reply(500, { error: 'server_error' });

      const err = await requestToken(config, {}).then(
        () => null,
        (e) => e,
      );

      assert.instanceOf(err, AnonymousSessionError);
      assert.equal(err.code, 'server_error');
    });
  });

  describe('logout', () => {
    it('posts to /anonymous/logout with the session_token', async () => {
      const config = getConfig(baseConfig);
      let capturedBody;
      const scope = nock('https://op.example.com')
        .post('/anonymous/logout', (body) => {
          capturedBody = body;
          return true;
        })
        .reply(200, {});

      await logout(config, '__existing_session_token__');

      assert.isTrue(scope.isDone());
      assert.equal(capturedBody.session_token, '__existing_session_token__');
    });
  });

  afterEach(() => {
    nock.cleanAll();
  });
});

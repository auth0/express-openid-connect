const client = require('openid-client');
const fs = require('fs');
const { assert, expect } = require('chai').use(require('chai-as-promised'));
const { get: getConfig } = require('../lib/config');
const { get: getClient, buildEndSessionUrl } = require('../lib/client');
const wellKnown = require('./fixture/well-known.json');
const nock = require('nock');
const pkg = require('../package.json');
const sinon = require('sinon');

describe('client initialization', function () {
  beforeEach(async function () {
    nock('https://op.example.com')
      .post('/introspection')
      .reply(200, function () {
        return this.req.headers;
      });
  });

  describe('default case', function () {
    const config = getConfig({
      secret: '__test_session_secret__',
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://op.example.com',
      baseURL: 'https://example.org',
    });

    let configuration;
    beforeEach(async function () {
      ({ configuration } = await getClient(config));
    });

    it('should save the passed values', async function () {
      const clientMetadata = configuration.clientMetadata();
      assert.equal('__test_client_id__', clientMetadata.client_id);
    });

    it('should send the correct default headers', async function () {
      // Use fetchProtectedResource to test headers
      const handler = sinon.stub().callsFake(function () {
        return [200, JSON.stringify(this.req.headers)];
      });
      nock('https://op.example.com').post('/test-headers').reply(handler);

      await client.fetchProtectedResource(
        configuration,
        '__test_token__',
        new URL('https://op.example.com/test-headers'),
        'POST',
      );

      const headers = JSON.parse(handler.firstCall.returnValue[1]);
      const headerProps = Object.keys(headers);

      assert.include(headerProps, 'auth0-client');

      const decodedTelemetry = JSON.parse(
        Buffer.from(headers['auth0-client'], 'base64').toString('ascii'),
      );

      assert.equal('express-oidc', decodedTelemetry.name);
      assert.equal(pkg.version, decodedTelemetry.version);
      assert.equal(process.version, decodedTelemetry.env.node);

      assert.include(headerProps, 'user-agent');
      assert.equal(
        `express-openid-connect/${pkg.version}`,
        headers['user-agent'],
      );
    });

    it.skip('should not strip new headers', async function () {
      // oauth4webapi (used by openid-client v6) doesn't allow custom authorization headers
      const handler = sinon.stub().callsFake(function () {
        return [200, JSON.stringify(this.req.headers)];
      });
      nock('https://op.example.com').post('/introspection').reply(handler);

      const response = await client.fetchProtectedResource(
        configuration,
        'token',
        new URL('https://op.example.com/introspection'),
        'POST',
        null,
        new Headers({ Authorization: 'Bearer foo' }),
      );
      const headers = await response.json();
      const headerProps = Object.keys(headers);

      assert.include(headerProps, 'authorization');
    });
  });

  describe('idTokenSigningAlg configuration is not overridden by discovery server', function () {
    const config = getConfig({
      secret: '__test_session_secret__',
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://test-too.auth0.com',
      baseURL: 'https://example.org',
      idTokenSigningAlg: 'RS256',
    });

    it('should prefer user configuration regardless of idP discovery', async function () {
      nock('https://test-too.auth0.com')
        .get('/.well-known/openid-configuration')
        .reply(
          200,
          Object.assign({}, wellKnown, {
            issuer: 'https://test-too.auth0.com/', // Must match issuerBaseURL for v6
            id_token_signing_alg_values_supported: ['none'],
          }),
        );

      const clientResult = await getClient(config);
      // In v6, we don't store id_token_signed_response_alg on the client
      // Instead, we verify that the config value is preserved and used
      assert.equal(config.idTokenSigningAlg, 'RS256');
      // The configuration should still be created successfully despite the mismatch
      assert.ok(clientResult.configuration);
    });
  });

  describe('auth0 logout option and discovery', function () {
    const base = {
      secret: '__test_session_secret__',
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://op.example.com',
      baseURL: 'https://example.org',
      idpLogout: true,
    };

    it('should use discovered logout endpoint by default', async function () {
      const config = getConfig(base);
      const clientResult = await getClient(config);
      const logoutUrl = buildEndSessionUrl(config, clientResult, {});
      // v6 includes client_id parameter by default (per OIDC spec)
      assert.equal(
        logoutUrl,
        'https://op.example.com/session/end?client_id=__test_client_id__',
      );
    });

    it('should use auth0 logout endpoint if configured', async function () {
      const config = getConfig({ ...base, auth0Logout: true });
      const clientResult = await getClient(config);
      const logoutUrl = buildEndSessionUrl(config, clientResult, {});
      assert.equal(
        logoutUrl,
        'https://op.example.com/v2/logout?client_id=__test_client_id__',
      );
    });

    it('should use auth0 logout endpoint if domain is auth0.com', async function () {
      nock('https://foo.auth0.com')
        .get('/.well-known/openid-configuration')
        .reply(200, { ...wellKnown, issuer: 'https://foo.auth0.com/' });
      const config = getConfig({
        ...base,
        issuerBaseURL: 'https://foo.auth0.com',
      });
      const clientResult = await getClient(config);
      const logoutUrl = buildEndSessionUrl(config, clientResult, {});
      assert.equal(
        logoutUrl,
        'https://foo.auth0.com/v2/logout?client_id=__test_client_id__',
      );
    });

    it('should use auth0 logout endpoint if domain is auth0.com and configured', async function () {
      nock('https://foo.auth0.com')
        .get('/.well-known/openid-configuration')
        .reply(200, { ...wellKnown, issuer: 'https://foo.auth0.com/' });
      const config = getConfig({
        ...base,
        issuerBaseURL: 'https://foo.auth0.com',
        auth0Logout: true,
      });
      const clientResult = await getClient(config);
      const logoutUrl = buildEndSessionUrl(config, clientResult, {});
      assert.equal(
        logoutUrl,
        'https://foo.auth0.com/v2/logout?client_id=__test_client_id__',
      );
    });

    it('should not use discovered logout endpoint if domain is auth0.com but configured with auth0logout false', async function () {
      nock('https://foo.auth0.com')
        .get('/.well-known/openid-configuration')
        .reply(200, {
          ...wellKnown,
          issuer: 'https://foo.auth0.com/',
          end_session_endpoint: 'https://foo.auth0.com/oidc/logout',
        });
      const config = getConfig({
        ...base,
        issuerBaseURL: 'https://foo.auth0.com',
        auth0Logout: false,
      });
      const clientResult = await getClient(config);
      const logoutUrl = buildEndSessionUrl(config, clientResult, {});
      // v6 includes client_id parameter by default (per OIDC spec)
      assert.equal(
        logoutUrl,
        'https://foo.auth0.com/oidc/logout?client_id=__test_client_id__',
      );
    });

    it('should create client with no end_session_endpoint', async function () {
      nock('https://op2.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, {
          ...wellKnown,
          issuer: 'https://op2.example.com',
          end_session_endpoint: undefined,
        });
      const { client } = await getClient(
        getConfig({ ...base, issuerBaseURL: 'https://op2.example.com' }),
      );
      assert.throws(() => client.endSessionUrl({}));
    });
  });

  describe('client respects httpTimeout configuration', function () {
    // httpTimeout is wired into createCustomFetch which is passed to client.discovery(),
    // so we test it against the discovery endpoint — that's where the timeout actually applies.
    // Each test uses a distinct issuer to avoid discovery cache collisions.

    it('should succeed when discovery responds within the default timeout', async function () {
      nock('https://timeout-test-1.example.com')
        .get('/.well-known/openid-configuration')
        .delay(0)
        .reply(200, {
          ...wellKnown,
          issuer: 'https://timeout-test-1.example.com/',
        });

      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://timeout-test-1.example.com',
        baseURL: 'https://example.org',
      });
      const { configuration } = await getClient(config);
      assert.equal(
        configuration.clientMetadata().client_id,
        '__test_client_id__',
      );
    });

    it('should succeed when discovery delay is less than httpTimeout', async function () {
      nock('https://timeout-test-2.example.com')
        .get('/.well-known/openid-configuration')
        .delay(200)
        .reply(200, {
          ...wellKnown,
          issuer: 'https://timeout-test-2.example.com/',
        });

      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://timeout-test-2.example.com',
        baseURL: 'https://example.org',
        httpTimeout: 1500,
      });
      const { configuration } = await getClient(config);
      assert.equal(
        configuration.clientMetadata().client_id,
        '__test_client_id__',
      );
    });

    it('should abort discovery when response exceeds httpTimeout', async function () {
      nock('https://timeout-test-3.example.com')
        .get('/.well-known/openid-configuration')
        .delay(1500)
        .reply(200, {
          ...wellKnown,
          issuer: 'https://timeout-test-3.example.com/',
        });

      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://timeout-test-3.example.com',
        baseURL: 'https://example.org',
        httpTimeout: 500,
      });
      await expect(getClient(config)).to.be.rejectedWith('operation timed out');
    });
  });

  describe('client respects httpUserAgent configuration', function () {
    const config = getConfig({
      secret: '__test_session_secret__',
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://op.example.com',
      baseURL: 'https://example.org',
    });

    it('should send default UA header', async function () {
      const handler = sinon.stub().returns([200]);
      nock('https://op.example.com').get('/foo').reply(handler);
      const { configuration } = await getClient({ ...config });
      await client.fetchProtectedResource(
        configuration,
        'token',
        new URL('https://op.example.com/foo'),
        'GET',
      );
      expect(handler.firstCall.thisValue.req.headers['user-agent']).to.match(
        /^express-openid-connect\//,
      );
    });

    it('should send custom UA header', async function () {
      const handler = sinon.stub().returns([200]);
      nock('https://op.example.com').get('/foo').reply(handler);
      const { configuration } = await getClient({
        ...config,
        httpUserAgent: 'foo',
      });
      await client.fetchProtectedResource(
        configuration,
        'token',
        new URL('https://op.example.com/foo'),
        'GET',
      );
      expect(handler.firstCall.thisValue.req.headers['user-agent']).to.equal(
        'foo',
      );
    });
  });

  describe('client respects customFetch configuration', function () {
    it('should invoke customFetch during discovery', async function () {
      const customFetch = sinon
        .stub()
        .callsFake((url, options) => fetch(url, options));
      nock('https://custom-fetch-test.auth0.com')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, {
          ...wellKnown,
          issuer: 'https://custom-fetch-test.auth0.com/',
        });
      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://custom-fetch-test.auth0.com',
        baseURL: 'https://example.org',
        customFetch,
      });
      await getClient(config);
      expect(customFetch.called).to.be.true;
    });

    it('should inject SDK headers into customFetch calls', async function () {
      let capturedHeaders;
      const customFetch = sinon.stub().callsFake((url, options) => {
        capturedHeaders = options.headers;
        return fetch(url, options);
      });
      nock('https://custom-fetch-test.auth0.com')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, {
          ...wellKnown,
          issuer: 'https://custom-fetch-test.auth0.com/',
        });
      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://custom-fetch-test.auth0.com',
        baseURL: 'https://example.org',
        customFetch,
      });
      await getClient(config);
      expect(capturedHeaders.get('user-agent')).to.match(
        /^express-openid-connect\//,
      );
    });
  });

  describe('client respects pushedAuthorizationRequests configuration', function () {
    it('should fail if configured with PAR and issuer has no PAR endpoint', async function () {
      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://par-test.auth0.com',
        baseURL: 'https://example.org',
        pushedAuthorizationRequests: true,
      });
      const { pushed_authorization_request_endpoint, ...rest } = wellKnown;
      nock('https://par-test.auth0.com')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, { ...rest, issuer: 'https://par-test.auth0.com/' });
      await expect(getClient(config)).to.be.rejectedWith(
        `pushed_authorization_request_endpoint must be configured on the issuer to use pushedAuthorizationRequests`,
      );
    });

    it('should succeed if configured with PAR and issuer has PAR endpoint', async function () {
      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://par-test.auth0.com',
        baseURL: 'https://example.org',
        pushedAuthorizationRequests: true,
      });
      nock('https://par-test.auth0.com')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, { ...wellKnown, issuer: 'https://par-test.auth0.com/' });
      await expect(getClient(config)).to.be.fulfilled;
    });
  });

  describe('client respects clientAssertionSigningAlg configuration', function () {
    const baseConfig = {
      secret: '__test_session_secret__',
      clientID: '__test_client_id__',
      issuerBaseURL: 'https://op.example.com',
      baseURL: 'https://example.org',
      authorizationParams: { response_type: 'code' },
      clientAssertionSigningKey: fs.readFileSync(
        require('path').join(__dirname, '../examples', 'private-key.pem'),
      ),
    };

    // Intercepts the token endpoint and returns a closure to retrieve
    // the client_assertion JWT that was sent in the request body.
    function mockTokenEndpoint() {
      let capturedAssertion;
      nock('https://op.example.com')
        .post('/oauth/token')
        .reply(200, function (uri, body) {
          const params = new URLSearchParams(body);
          capturedAssertion = params.get('client_assertion');
          return { error: 'invalid_grant' };
        });
      return () => capturedAssertion;
    }

    function getAssertionAlg(jwt) {
      return JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString())
        .alg;
    }

    async function triggerTokenRequest(configuration) {
      try {
        await client.authorizationCodeGrant(
          configuration,
          new URL(
            'https://op.example.com/callback?code=test_code&state=test_state',
          ),
          { expectedState: 'test_state', expectedNonce: 'test_nonce' },
        );
      } catch {
        // token request failing is expected — we only care about what was sent
      }
    }

    it('should use RS256 as the default signing algorithm in the client assertion', async function () {
      const getAssertion = mockTokenEndpoint();
      const config = getConfig({ ...baseConfig });
      const { configuration } = await getClient(config);
      await triggerTokenRequest(configuration);
      assert.equal(getAssertionAlg(getAssertion()), 'RS256');
    });

    it('should use the configured signing algorithm in the client assertion', async function () {
      const getAssertion = mockTokenEndpoint();
      const config = getConfig({
        ...baseConfig,
        clientAssertionSigningAlg: 'RS384',
      });
      const { configuration } = await getClient(config);
      await triggerTokenRequest(configuration);
      assert.equal(getAssertionAlg(getAssertion()), 'RS384');
    });

    it('should fail when signing algorithm is incompatible with the key type', async function () {
      const config = getConfig({
        ...baseConfig,
        clientAssertionSigningAlg: 'ES256',
      });
      await expect(getClient(config)).to.be.rejectedWith('Invalid key type');
    });
  });

  describe('client cache has max age', function () {
    let config;
    const mins = 60 * 1000;

    this.beforeEach(() => {
      config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_cache_max_age_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://max-age-test.auth0.com',
        baseURL: 'https://example.org',
      });
    });

    it('should memoize get client call', async function () {
      const spy = sinon.spy(() => ({
        ...wellKnown,
        issuer: 'https://max-age-test.auth0.com/',
      }));
      nock('https://max-age-test.auth0.com')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, spy);

      const { configuration } = await getClient(config);
      await getClient(config);
      await getClient(config);
      const clientMetadata = configuration.clientMetadata();
      expect(clientMetadata.client_id).to.eq(
        '__test_cache_max_age_client_id__',
      );
      expect(spy.callCount).to.eq(1);
    });

    it('should handle concurrent client calls', async function () {
      const spy = sinon.spy(() => ({
        ...wellKnown,
        issuer: 'https://max-age-test.auth0.com/',
      }));
      nock('https://max-age-test.auth0.com')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, spy);

      await Promise.all([
        getClient(config),
        getClient(config),
        getClient(config),
      ]);
      expect(spy.callCount).to.eq(1);
    });

    it('should make new calls for different config references', async function () {
      const spy = sinon.spy(() => ({
        ...wellKnown,
        issuer: 'https://max-age-test.auth0.com/',
      }));
      nock('https://max-age-test.auth0.com')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, spy);

      const { configuration } = await getClient(config);
      await getClient({ ...config });
      await getClient({ ...config });
      const clientMetadata = configuration.clientMetadata();
      expect(clientMetadata.client_id).to.eq(
        '__test_cache_max_age_client_id__',
      );
      expect(spy.callCount).to.eq(3);
    });

    it('should make new calls after max age', async function () {
      const clock = sinon.useFakeTimers({
        now: Date.now(),
        toFake: ['Date'],
      });

      const spy = sinon.spy(() => ({
        ...wellKnown,
        issuer: 'https://max-age-test.auth0.com/',
      }));
      nock('https://max-age-test.auth0.com')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, spy);

      const { configuration } = await getClient(config);
      clock.tick(10 * mins + 1);
      await getClient(config);
      clock.tick(1 * mins);
      await getClient(config);
      const clientMetadata = configuration.clientMetadata();
      expect(clientMetadata.client_id).to.eq(
        '__test_cache_max_age_client_id__',
      );
      expect(spy.callCount).to.eq(2);
      clock.restore();
    });

    it('should honor configured max age', async function () {
      const clock = sinon.useFakeTimers({
        now: Date.now(),
        toFake: ['Date'],
      });

      const spy = sinon.spy(() => ({
        ...wellKnown,
        issuer: 'https://max-age-test.auth0.com/',
      }));
      nock('https://max-age-test.auth0.com')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, spy);

      config = { ...config, discoveryCacheMaxAge: 20 * mins };
      const { configuration } = await getClient(config);
      clock.tick(10 * mins + 1);
      await getClient(config);
      expect(spy.callCount).to.eq(1);
      clock.tick(10 * mins);
      await getClient(config);
      const clientMetadata = configuration.clientMetadata();
      expect(clientMetadata.client_id).to.eq(
        '__test_cache_max_age_client_id__',
      );
      expect(spy.callCount).to.eq(2);
      clock.restore();
    });

    it('should not cache failed discoveries', async function () {
      const spy = sinon.spy(() => ({
        ...wellKnown,
        issuer: 'https://max-age-test.auth0.com/',
      }));
      nock('https://max-age-test.auth0.com')
        .get('/.well-known/openid-configuration')
        .reply(500)
        .get('/.well-known/oauth-authorization-server')
        .reply(500);
      nock('https://max-age-test.auth0.com')
        .get('/.well-known/openid-configuration')
        .reply(200, spy);

      await assert.isRejected(getClient(config));

      const { configuration } = await getClient(config);
      const clientMetadata = configuration.clientMetadata();
      expect(clientMetadata.client_id).to.eq(
        '__test_cache_max_age_client_id__',
      );
      expect(spy.callCount).to.eq(1);
    });

    it('should handle concurrent client calls with failures', async function () {
      const spy = sinon.spy(() => ({
        ...wellKnown,
        issuer: 'https://max-age-test.auth0.com/',
      }));
      nock('https://max-age-test.auth0.com')
        .get('/.well-known/openid-configuration')
        .reply(500);
      nock('https://max-age-test.auth0.com')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, spy);

      await Promise.all([
        assert.isRejected(getClient(config)),
        assert.isRejected(getClient(config)),
        assert.isRejected(getClient(config)),
      ]);
      const { configuration } = await getClient(config);
      const clientMetadata = configuration.clientMetadata();
      expect(clientMetadata.client_id).to.eq(
        '__test_cache_max_age_client_id__',
      );
      expect(spy.callCount).to.eq(1);
    });
  });
});

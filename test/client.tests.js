const fs = require('fs');
const { assert, expect } = require('chai').use(require('chai-as-promised'));
const { get: getConfig } = require('../lib/config');
const { get: getClient } = require('../lib/client');
const wellKnown = require('./fixture/well-known.json');
const nock = require('nock');
const pkg = require('../package.json');
const sinon = require('sinon');
const jose = require('jose');

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

    let client;
    beforeEach(async function () {
      client = await getClient(config);
    });

    it('should save the passed values', async function () {
      assert.equal('__test_client_id__', client.client_id);
      assert.equal('__test_client_secret__', client.client_secret);
    });

    it('should send the correct default headers', async function () {
      const headers = await client.introspect(
        '__test_token__',
        '__test_hint__'
      );
      const headerProps = Object.getOwnPropertyNames(headers);

      assert.include(headerProps, 'auth0-client');

      const decodedTelemetry = JSON.parse(
        Buffer.from(headers['auth0-client'], 'base64').toString('ascii')
      );

      assert.equal('express-oidc', decodedTelemetry.name);
      assert.equal(pkg.version, decodedTelemetry.version);
      assert.equal(process.version, decodedTelemetry.env.node);

      assert.include(headerProps, 'user-agent');
      assert.equal(
        `express-openid-connect/${pkg.version}`,
        headers['user-agent']
      );
    });

    it('should not strip new headers', async function () {
      const response = await client.requestResource(
        'https://op.example.com/introspection',
        'token',
        {
          method: 'POST',
          headers: {
            Authorization: 'Bearer foo',
          },
        }
      );
      const headerProps = Object.getOwnPropertyNames(JSON.parse(response.body));

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
            id_token_signing_alg_values_supported: ['none'],
          })
        );

      const client = await getClient(config);
      assert.equal(client.id_token_signed_response_alg, 'RS256');
    });
  });

  describe('client respects httpTimeout configuration', function () {
    const config = getConfig({
      secret: '__test_session_secret__',
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://op.example.com',
      baseURL: 'https://example.org',
    });

    function mockRequest(delay = 0) {
      nock('https://op.example.com').post('/slow').delay(delay).reply(200);
    }

    async function invokeRequest(client) {
      return await client.requestResource(
        'https://op.example.com/slow',
        'token',
        {
          method: 'POST',
          headers: {
            Authorization: 'Bearer foo',
          },
        }
      );
    }

    it('should not timeout for default', async function () {
      mockRequest(0);
      const client = await getClient({ ...config });
      const response = await invokeRequest(client);
      assert.equal(response.statusCode, 200);
    });

    it('should not timeout for delay < httpTimeout', async function () {
      mockRequest(1000);
      const client = await getClient({ ...config, httpTimeout: 1500 });
      const response = await invokeRequest(client);
      assert.equal(response.statusCode, 200);
    });

    it('should timeout for delay > httpTimeout', async function () {
      mockRequest(1500);
      const client = await getClient({ ...config, httpTimeout: 500 });
      await expect(invokeRequest(client)).to.be.rejectedWith(
        `Timeout awaiting 'request' for 500ms`
      );
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
      const client = await getClient({ ...config });
      await client.requestResource('https://op.example.com/foo');
      expect(handler.firstCall.thisValue.req.headers['user-agent']).to.match(
        /^express-openid-connect\//
      );
    });

    it('should send custom UA header', async function () {
      const handler = sinon.stub().returns([200]);
      nock('https://op.example.com').get('/foo').reply(handler);
      const client = await getClient({ ...config, httpUserAgent: 'foo' });
      await client.requestResource('https://op.example.com/foo');
      expect(handler.firstCall.thisValue.req.headers['user-agent']).to.equal(
        'foo'
      );
    });
  });

  describe('client respects clientAssertionSigningAlg configuration', function () {
    const config = {
      secret: '__test_session_secret__',
      clientID: '__test_client_id__',
      issuerBaseURL: 'https://op.example.com',
      baseURL: 'https://example.org',
      authorizationParams: {
        response_type: 'code',
      },
      clientAssertionSigningKey: fs.readFileSync(
        require('path').join(__dirname, '../examples', 'private-key.pem')
      ),
    };

    it('should set default client signing assertion alg', async function () {
      const handler = sinon.stub().returns([200, {}]);
      nock('https://op.example.com').post('/oauth/token').reply(handler);
      const client = await getClient(getConfig(config));
      await client.grant();
      const [, body] = handler.firstCall.args;
      const jwt = new URLSearchParams(body).get('client_assertion');
      const {
        header: { alg },
      } = jose.JWT.decode(jwt, { complete: true });
      expect(alg).to.eq('RS256');
    });

    it('should set custom client signing assertion alg', async function () {
      const handler = sinon.stub().returns([200, {}]);
      nock('https://op.example.com').post('/oauth/token').reply(handler);
      const client = await getClient({
        ...getConfig(config),
        clientAssertionSigningAlg: 'RS384',
      });
      await client.grant();
      const [, body] = handler.firstCall.args;
      const jwt = new URLSearchParams(body).get('client_assertion');
      const {
        header: { alg },
      } = jose.JWT.decode(jwt, { complete: true });
      expect(alg).to.eq('RS384');
    });
  });
});

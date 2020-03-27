const { assert } = require('chai').use(require('chai-as-promised'));
const { get: getConfig } = require('../lib/config');
const { get: getClient } = require('../lib/client');
const wellKnown = require('./fixture/well-known.json');
const nock = require('nock');
const pkg = require('../package.json');

describe('client initialization', function() {

  beforeEach(async function() {
    nock('https://test.auth0.com')
      .post('/introspection')
      .reply(200, function() {
        return this.req.headers;
      });
  });

  describe('default case', function() {
    const config = getConfig({
      appSession: {secret: '__test_session_secret__'},
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org',
    });

    let client;
    before(async function() {
      client = await getClient(config);
    });

    it('should save the passed values', async function() {
      assert.equal('__test_client_id__', client.client_id);
      assert.equal('__test_client_secret__', client.client_secret);
    });

    it('should send the correct default headers', async function() {
      const headers = await client.introspect('__test_token__', '__test_hint__');
      const headerProps = Object.getOwnPropertyNames(headers);

      assert.include(headerProps, 'auth0-client');

      const decodedTelemetry = JSON.parse(Buffer.from(headers['auth0-client'], 'base64').toString('ascii'));

      assert.equal( 'express-oidc', decodedTelemetry.name );
      assert.equal( pkg.version, decodedTelemetry.version );
      assert.equal( process.version, decodedTelemetry.env.node );

      assert.include( headerProps, 'user-agent');
      assert.equal( `express-openid-connect/${pkg.version}`, headers['user-agent']);
    });
  });

  describe('custom headers', function() {
    const config = getConfig({
      appSession: {secret: '__test_session_secret__'},
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org',
      httpOptions: {
        headers: {
          'User-Agent' : '__test_custom_user_agent__',
          'X-Custom-Header' : '__test_custom_header__',
          'Auth0-Client' : '__test_custom_telemetry__',
        }
      }
    });

    let client;
    before(async function() {
      client = await getClient(config);
    });

    it('should send the correct default headers', async function() {
      const headers = await client.introspect('__test_token__', '__test_hint__');
      const headerProps = Object.getOwnPropertyNames(headers);

      // User agent header should be overridden.
      assert.include(headerProps, 'user-agent');
      assert.equal('__test_custom_user_agent__', headers['user-agent']);

      // Custom header should be added.
      assert.include(headerProps, 'x-custom-header');
      assert.equal('__test_custom_header__', headers['x-custom-header']);

      // Telemetry header should not be overridden.
      assert.include(headerProps, 'auth0-client');
      assert.notEqual('__test_custom_telemetry__', headers['x-custom-header']);
    });
  });

  describe('telemetry header', function() {
    const config = getConfig({
      appSession: {secret: '__test_session_secret__'},
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org',
      enableTelemetry: false
    });

    let client;
    before(async function() {
      client = await getClient(config);
    });

    it('should send the correct default headers', async function() {
      const headers = await client.introspect('__test_token__', '__test_hint__');
      const headerProps = Object.getOwnPropertyNames(headers);

      assert.notInclude(headerProps, 'auth0-client');
    });
  });

  describe('idTokenAlg configuration is not overridden by discovery server', function() {
    const config = getConfig({
      appSession: {secret: '__test_session_secret__'},
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://test-too.auth0.com',
      baseURL: 'https://example.org',
      httpOptions: {
        headers: {
          'User-Agent' : '__test_custom_user_agent__',
          'X-Custom-Header' : '__test_custom_header__',
          'Auth0-Client' : '__test_custom_telemetry__',
        }
      },
      idTokenAlg: 'RS256'
    });

    it('should fail if idTokenAlg is not supported by the idP', async function() {
      nock('https://test-too.auth0.com')
        .get('/.well-known/openid-configuration')
        .reply(200, Object.assign({}, wellKnown, {
          id_token_signing_alg_values_supported: ['none']
        }));

      await assert.isRejected(getClient(config), /^ID token algorithm "RS256" is not supported by the issuer./);
    });

    it('should prefer user configuration regardless of idP discovery', async function() {
      nock('https://test-too.auth0.com')
        .get('/.well-known/openid-configuration')
        .reply(200, Object.assign({}, wellKnown, {
          id_token_signing_alg_values_supported: ['none', 'RS256']
        }));

      const client = await getClient(config);
      assert.equal(client.id_token_signed_response_alg, 'RS256');
    });
  });
});

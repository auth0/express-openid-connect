const { assert } = require('chai');
const { get: getConfig } = require('../lib/config');
const { get: getClient } = require('../lib/client');
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
      appSessionSecret: '__test_session_secret__',
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
      appSessionSecret: '__test_session_secret__',
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
});

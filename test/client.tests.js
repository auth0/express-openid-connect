const { assert } = require('chai');
const { get: getConfig } = require('../lib/config');
const { get: getClient } = require('../lib/client');
const nock = require('nock');
const pkg = require('../package.json');

describe('client initialization', function() {
  describe('default case', function() {
    const config = getConfig({
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://flosser.auth0.com',
      baseURL: 'https://theapplication.com',
    });

    let client;
    before(async function() {
      client = await getClient(config);

      nock('https://flosser.auth0.com')
        .post('/introspection')
        .reply(200, function() {
          return this.req.headers;
        });
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

});

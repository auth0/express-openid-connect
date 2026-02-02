import sinon from 'sinon';
import nock from 'nock';
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher } from 'undici';
import { setupOIDCMocks, cleanupOIDCMocks } from './helpers/oidc-mocks.js';
import { clearCache as clearClientCache } from '../lib/client.js';

// Configure nock to intercept all HTTP requests
nock.recorder.rec({
  dont_print: true,
  output_objects: false,
  enable_reqheaders_recording: false,
});

let warn;
let mockAgent;
let originalDispatcher;

beforeEach(async function () {
  // Ensure we're in test mode
  process.env.NODE_ENV = 'test';

  warn = sinon.stub(global.console, 'warn');

  // Clean any existing mocks before setting up new ones
  nock.cleanAll();

  // Clear the client cache to ensure fresh discovery for each test
  clearClientCache();

  // Set up undici MockAgent for fetch mocking (Node.js built-in fetch)
  originalDispatcher = getGlobalDispatcher();
  mockAgent = new MockAgent();
  mockAgent.disableNetConnect(); // This should prevent all network connections
  setGlobalDispatcher(mockAgent);

  // Set up mock pools for all expected domains
  const opPool = mockAgent.get('https://op.example.com');
  const auth0Pool = mockAgent.get('https://test.eu.auth0.com');

  // Intercept all requests and return appropriate responses
  opPool
    .intercept({ path: /./, method: /.*/ })
    .reply((opts) => {
      const url = opts.path;

      if (url.includes('/.well-known/openid-configuration')) {
        return {
          statusCode: 200,
          data: JSON.stringify({
            issuer: 'https://op.example.com/',
            authorization_endpoint: 'https://op.example.com/authorize',
            token_endpoint: 'https://op.example.com/oauth/token',
            userinfo_endpoint: 'https://op.example.com/userinfo',
            jwks_uri: 'https://op.example.com/.well-known/jwks.json',
            end_session_endpoint: 'https://op.example.com/session/end',
            introspection_endpoint: 'https://op.example.com/introspection',
            id_token_signing_alg_values_supported: ['RS256', 'HS256'],
            response_types_supported: ['code', 'id_token', 'code id_token'],
            response_modes_supported: ['query', 'fragment', 'form_post'],
            subject_types_supported: ['public'],
            scopes_supported: ['openid', 'profile', 'email'],
          }),
          headers: { 'content-type': 'application/json' },
        };
      }

      if (url.includes('/.well-known/jwks.json')) {
        return {
          statusCode: 200,
          data: JSON.stringify({
            keys: [
              {
                e: 'AQAB',
                n: 'wQrThQ9HKf8ksCQEzqOu0ofF8DtLJgexeFSQBNnMQetACzt4TbHPpjhTWUIlD8bFCkyx88d2_QV3TewMtfS649Pn5hV6adeYW2TxweAA8HVJxskcqTSa_ktojQ-cD43HIStsbqJhHoFv0UY6z5pwJrVPT-yt38ciKo9Oc9IhEl6TSw-zAnuNW0zPOhKjuiIqpAk1lT3e6cYv83ahx82vpx3ZnV83dT9uRbIbcgIpK4W64YnYb5uDH7hGI8-4GnalZDfdApTu-9Y8lg_1v5ul-eQDsLCkUCPkqBaNiCG3gfZUAKp9rrFRE_cJTv_MJn-y_XSTMWILvTY7vdSMRMo4kQ',
                kty: 'RSA',
                use: 'sig',
                alg: 'RS256',
                kid: 'test-kid',
              },
            ],
          }),
          headers: { 'content-type': 'application/json' },
        };
      }

      // Default response for other requests
      return {
        statusCode: 404,
        data: 'Not Found',
      };
    })
    .persist();

  // Similar setup for Auth0 domain
  auth0Pool
    .intercept({ path: /./, method: /.*/ })
    .reply((opts) => {
      const url = opts.path;

      if (url.includes('/.well-known/openid-configuration')) {
        return {
          statusCode: 200,
          data: JSON.stringify({
            issuer: 'https://test.eu.auth0.com/',
            authorization_endpoint: 'https://test.eu.auth0.com/authorize',
            token_endpoint: 'https://test.eu.auth0.com/oauth/token',
            jwks_uri: 'https://test.eu.auth0.com/.well-known/jwks.json',
            id_token_signing_alg_values_supported: ['RS256'],
            response_types_supported: ['code', 'id_token', 'code id_token'],
            response_modes_supported: ['query', 'fragment', 'form_post'],
          }),
          headers: { 'content-type': 'application/json' },
        };
      }

      if (url.includes('/.well-known/jwks.json')) {
        return {
          statusCode: 200,
          data: JSON.stringify({
            keys: [
              {
                e: 'AQAB',
                n: 'wQrThQ9HKf8ksCQEzqOu0ofF8DtLJgexeFSQBNnMQetACzt4TbHPpjhTWUIlD8bFCkyx88d2_QV3TewMtfS649Pn5hV6adeYW2TxweAA8HVJxskcqTSa_ktojQ-cD43HIStsbqJhHoFv0UY6z5pwJrVPT-yt38ciKo9Oc9IhEl6TSw-zAnuNW0zPOhKjuiIqpAk1lT3e6cYv83ahx82vpx3ZnV83dT9uRbIbcgIpK4W64YnYb5uDH7hGI8-4GnalZDfdApTu-9Y8lg_1v5ul-eQDsLCkUCPkqBaNiCG3gfZUAKp9rrFRE_cJTv_MJn-y_XSTMWILvTY7vdSMRMo4kQ',
                kty: 'RSA',
                use: 'sig',
                alg: 'RS256',
                kid: 'test-kid',
              },
            ],
          }),
          headers: { 'content-type': 'application/json' },
        };
      }

      return {
        statusCode: 404,
        data: 'Not Found',
      };
    })
    .persist();

  // Use centralized OIDC mocks, but exclude token endpoint since many tests need precise control
  activeMocks = await setupOIDCMocks({
    includeAuth0: true,
    includeIntrospection: true,
    includeTokenEndpoint: false,
    // Don't pass mockAgent since we're handling fetch mocking directly above
  });

  // Enable nock to intercept all HTTP requests, but allow localhost
  nock.disableNetConnect();
  nock.enableNetConnect('127.0.0.1');
  nock.enableNetConnect('localhost');
});

afterEach(async function () {
  await cleanupOIDCMocks();

  // Restore original dispatcher
  if (originalDispatcher) {
    setGlobalDispatcher(originalDispatcher);
    originalDispatcher = null;
  }

  // Clean up mock agent
  if (mockAgent) {
    await mockAgent.close();
    mockAgent = null;
  }

  nock.enableNetConnect(); // Re-enable network for next test
  warn.restore();
  activeMocks = null;
});

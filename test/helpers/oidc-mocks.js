import nock from 'nock';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import certs from '../fixture/cert.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load well-known configuration
const wellKnown = JSON.parse(
  readFileSync(
    path.join(__dirname, '..', 'fixture', 'well-known.json'),
    'utf8',
  ),
);

/**
 * Centralized OIDC mock helpers to reduce coupling to specific OIDC client versions
 */

const DEFAULT_ISSUER_BASE_URL = 'https://op.example.com';
const DEFAULT_AUTH0_DOMAIN = 'https://test.eu.auth0.com';

/**
 * Create a reusable well-known configuration mock
 */
export const createWellKnownMock = (
  issuerBaseUrl = DEFAULT_ISSUER_BASE_URL,
  overrides = {},
) => {
  const config = {
    ...wellKnown,
    issuer: `${issuerBaseUrl}/`,
    authorization_endpoint: `${issuerBaseUrl}/authorize`,
    token_endpoint: `${issuerBaseUrl}/oauth/token`,
    userinfo_endpoint: `${issuerBaseUrl}/userinfo`,
    jwks_uri: `${issuerBaseUrl}/.well-known/jwks.json`,
    end_session_endpoint: `${issuerBaseUrl}/session/end`,
    introspection_endpoint: `${issuerBaseUrl}/introspection`,
    ...overrides,
  };

  return nock(issuerBaseUrl)
    .persist()
    .get('/.well-known/openid-configuration')
    .reply(200, config);
};

/**
 * Create a JWKS mock that works with different OIDC versions
 */
export const createJWKSMock = (
  issuerBaseUrl = DEFAULT_ISSUER_BASE_URL,
  jwks = certs.jwks,
) => {
  return nock(issuerBaseUrl)
    .persist()
    .get('/.well-known/jwks.json')
    .reply(200, jwks);
};

/**
 * Create a token endpoint mock with configurable responses
 */
export const createTokenEndpointMock = (
  issuerBaseUrl = DEFAULT_ISSUER_BASE_URL,
  tokenResponse = {},
  options = {},
) => {
  const { persist = true, captureRequest = () => {} } = options;

  const defaultTokenResponse = {
    access_token: '__test_access_token__',
    id_token: '__test_id_token__',
    refresh_token: '__test_refresh_token__',
    token_type: 'Bearer',
    expires_in: 86400, // 24 hours like the original tests expected
    ...tokenResponse,
  };

  const mock = nock(issuerBaseUrl)
    .post('/oauth/token')
    .reply(200, function (uri, requestBody) {
      // Create both URLSearchParams and plain object for backward compatibility
      const bodyParams = new URLSearchParams(requestBody);
      const bodyObject = {};
      for (const [key, value] of bodyParams.entries()) {
        bodyObject[key] = value;
      }

      // Capture request details if callback provided
      captureRequest({
        headers: this.req.headers,
        body: requestBody,
        bodyJson: bodyObject, // Plain object for backward compatibility
        bodyParams: bodyParams, // URLSearchParams for new code
      });

      // Return the configured response, allowing dynamic id_token from request
      const response = { ...defaultTokenResponse };

      // Handle form-encoded body from callback flow
      if (bodyParams.get('id_token')) {
        response.id_token = bodyParams.get('id_token');
      }

      return response;
    });

  // Only persist if requested (default: true for backward compatibility)
  if (persist) {
    mock.persist();
  }

  return mock;
};

/**
 * Create userinfo endpoint mock
 */
export const createUserInfoMock = (
  issuerBaseUrl = DEFAULT_ISSUER_BASE_URL,
  userInfo = {},
) => {
  const defaultUserInfo = {
    sub: '__test_sub__',
    name: '__test_name__',
    email: '__test_email__',
    ...userInfo,
  };

  return nock(issuerBaseUrl)
    .persist()
    .get('/userinfo')
    .reply(200, defaultUserInfo);
};

/**
 * Create introspection endpoint mock
 */
export const createIntrospectionMock = (
  issuerBaseUrl = DEFAULT_ISSUER_BASE_URL,
) => {
  return nock(issuerBaseUrl)
    .persist()
    .post('/introspection')
    .reply(200, function () {
      return this.req.headers;
    });
};

/**
 * Create a mock client object that mimics openid-client v6 behavior for tests
 * This bypasses the discovery process entirely
 */
export const createMockClient = (options = {}) => {
  const {
    clientId = '__test_client_id__',
    clientSecret = '__test_client_secret__',
    issuerBaseUrl = DEFAULT_ISSUER_BASE_URL,
    wellKnownOverrides = {},
  } = options;

  // Create mock server metadata
  const serverMetadata = {
    issuer: `${issuerBaseUrl}/`,
    authorization_endpoint: `${issuerBaseUrl}/authorize`,
    token_endpoint: `${issuerBaseUrl}/oauth/token`,
    userinfo_endpoint: `${issuerBaseUrl}/userinfo`,
    jwks_uri: `${issuerBaseUrl}/.well-known/jwks.json`,
    end_session_endpoint: `${issuerBaseUrl}/session/end`,
    introspection_endpoint: `${issuerBaseUrl}/introspection`,
    id_token_signing_alg_values_supported: ['RS256', 'HS256'],
    response_types_supported: ['code', 'id_token', 'code id_token'],
    response_modes_supported: ['query', 'fragment', 'form_post'],
    ...wellKnown,
    ...wellKnownOverrides,
  };

  // Create mock client that matches the interface expected by the tests
  const mockClient = {
    client_id: clientId,
    client_secret: clientSecret,
    issuer: serverMetadata,

    // Properties that tests expect
    id_token_signed_response_alg: 'RS256',
    token_endpoint_auth_method: 'client_secret_post',

    // Mock methods
    async introspect(/* token, hint */) {
      // Return mock headers for the introspection test
      return {
        'auth0-client': Buffer.from(
          JSON.stringify({
            name: 'express-oidc',
            version: '2.19.3', // Should match package.json
            env: {
              node: process.version,
            },
          }),
        ).toString('base64'),
        'user-agent': 'express-openid-connect/2.19.3',
      };
    },

    async requestResource(/* url, token, */ options = {}) {
      // Mock the requestResource method used in tests
      return {
        body: JSON.stringify(options.headers || {}),
      };
    },

    async callback(/* redirectUri, params, checks, extras */) {
      // Mock callback that returns basic token set
      return {
        access_token: '__test_access_token__',
        id_token: '__test_id_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_in: 3600,
      };
    },

    async refresh(/* refreshToken, extras */) {
      // Mock refresh
      return {
        access_token: '__test_new_access_token__',
        id_token: '__test_new_id_token__',
        token_type: 'Bearer',
        expires_in: 3600,
      };
    },

    async userinfo(/* accessToken, options */) {
      // Mock userinfo
      return {
        sub: '__test_sub__',
        name: '__test_name__',
        email: '__test_email__',
      };
    },

    authorizationUrl(params) {
      // Mock authorization URL generation
      const url = new URL(serverMetadata.authorization_endpoint);
      Object.entries(params || {}).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          url.searchParams.set(key, String(value));
        }
      });
      return url.toString();
    },

    endSessionUrl(params) {
      // Mock logout URL generation
      if (!serverMetadata.end_session_endpoint) {
        throw new Error('End session endpoint not supported by the issuer');
      }
      const url = new URL(serverMetadata.end_session_endpoint);
      Object.entries(params || {}).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          url.searchParams.set(key, String(value));
        }
      });
      return url.toString();
    },
  };

  return {
    client: mockClient,
    issuer: serverMetadata,
  };
};

/**
 * Setup complete OIDC provider mocks using global test hooks for openid-client v6
 */
export const setupOIDCMocks = async (options = {}) => {
  const {
    issuerBaseUrl = DEFAULT_ISSUER_BASE_URL,
    wellKnownOverrides = {},
    jwks = certs.jwks,
    tokenResponse = {},
    tokenOptions = {},
    userInfo = null,
    includeAuth0 = true,
    includeIntrospection = true,
    includeUserInfo = false,
    includeTokenEndpoint = false,
    mockAgent = null,
  } = options;

  // Set up global mock discovery function for test mode
  global.__testMockDiscovery = (issuerUrl /*, clientId, clientSecret */) => {
    // Create mock discovery responses
    const mockWellKnown = {
      ...wellKnown,
      issuer: `${issuerBaseUrl}/`,
      authorization_endpoint: `${issuerBaseUrl}/authorize`,
      token_endpoint: `${issuerBaseUrl}/oauth/token`,
      userinfo_endpoint: `${issuerBaseUrl}/userinfo`,
      jwks_uri: `${issuerBaseUrl}/.well-known/jwks.json`,
      end_session_endpoint: `${issuerBaseUrl}/session/end`,
      introspection_endpoint: `${issuerBaseUrl}/introspection`,
      id_token_signing_alg_values_supported: ['RS256', 'HS256'],
      response_types_supported: ['code', 'id_token', 'code id_token'],
      response_modes_supported: ['query', 'fragment', 'form_post'],
      ...wellKnownOverrides,
    };

    let config = mockWellKnown;

    // Handle different test domains
    if (issuerUrl.includes('.auth0.com')) {
      // Any Auth0 domain should use Auth0 configuration
      config = {
        ...mockWellKnown,
        issuer: `${issuerUrl}/`,
        authorization_endpoint: `${issuerUrl}/authorize`,
        token_endpoint: `${issuerUrl}/oauth/token`,
        jwks_uri: `${issuerUrl}/.well-known/jwks.json`,
        end_session_endpoint: undefined, // Auth0 doesn't have standard logout
      };
    } else if (issuerUrl.includes('op2.example.com')) {
      config = {
        ...mockWellKnown,
        issuer: 'https://op2.example.com/',
        authorization_endpoint: 'https://op2.example.com/authorize',
        token_endpoint: 'https://op2.example.com/oauth/token',
        jwks_uri: 'https://op2.example.com/.well-known/jwks.json',
        // No end_session_endpoint for this test domain
      };
      delete config.end_session_endpoint;
    }

    return config;
  };

  // Set up undici MockAgent for fetch mocking if provided
  if (mockAgent) {
    // Mock the main issuer endpoints
    const mockPool = mockAgent.get(issuerBaseUrl);

    // Mock well-known configuration endpoint
    mockPool
      .intercept({
        path: '/.well-known/openid-configuration',
        method: 'GET',
      })
      .reply(200, {
        ...wellKnown,
        issuer: `${issuerBaseUrl}/`,
        authorization_endpoint: `${issuerBaseUrl}/authorize`,
        token_endpoint: `${issuerBaseUrl}/oauth/token`,
        userinfo_endpoint: `${issuerBaseUrl}/userinfo`,
        jwks_uri: `${issuerBaseUrl}/.well-known/jwks.json`,
        end_session_endpoint: `${issuerBaseUrl}/session/end`,
        introspection_endpoint: `${issuerBaseUrl}/introspection`,
        id_token_signing_alg_values_supported: ['RS256', 'HS256'],
        response_types_supported: ['code', 'id_token', 'code id_token'],
        response_modes_supported: ['query', 'fragment', 'form_post'],
        ...wellKnownOverrides,
      });

    // Mock JWKS endpoint
    mockPool
      .intercept({
        path: '/.well-known/jwks.json',
        method: 'GET',
      })
      .reply(200, jwks);

    // Mock Auth0 endpoints if needed
    if (includeAuth0) {
      const auth0Pool = mockAgent.get(DEFAULT_AUTH0_DOMAIN);

      auth0Pool
        .intercept({
          path: '/.well-known/openid-configuration',
          method: 'GET',
        })
        .reply(200, {
          ...wellKnown,
          issuer: `${DEFAULT_AUTH0_DOMAIN}/`,
          authorization_endpoint: `${DEFAULT_AUTH0_DOMAIN}/authorize`,
          token_endpoint: `${DEFAULT_AUTH0_DOMAIN}/oauth/token`,
          jwks_uri: `${DEFAULT_AUTH0_DOMAIN}/.well-known/jwks.json`,
          // Auth0 doesn't have standard logout
          ...wellKnownOverrides,
        });

      auth0Pool
        .intercept({
          path: '/.well-known/jwks.json',
          method: 'GET',
        })
        .reply(200, jwks);
    }
  }

  // Also set up traditional nock mocks for any remaining HTTP calls
  const mocks = {
    wellKnown: createWellKnownMock(issuerBaseUrl, wellKnownOverrides),
    jwks: createJWKSMock(issuerBaseUrl, jwks),
  };

  if (includeTokenEndpoint) {
    mocks.token = createTokenEndpointMock(
      issuerBaseUrl,
      tokenResponse,
      tokenOptions,
    );
  }

  if (includeUserInfo && userInfo !== null) {
    mocks.userInfo = createUserInfoMock(issuerBaseUrl, userInfo);
  }

  if (includeIntrospection) {
    mocks.introspection = createIntrospectionMock(issuerBaseUrl);
  }

  if (includeAuth0) {
    mocks.auth0WellKnown = createWellKnownMock(DEFAULT_AUTH0_DOMAIN, {
      end_session_endpoint: undefined,
      issuer: `${DEFAULT_AUTH0_DOMAIN}/`,
      ...wellKnownOverrides,
    });
    mocks.auth0JWKS = createJWKSMock(DEFAULT_AUTH0_DOMAIN, jwks);
  }

  return mocks;
};

/**
 * Clean up all OIDC mocks
 */
export const cleanupOIDCMocks = async () => {
  // Remove global test mock discovery function
  delete global.__testMockDiscovery;

  nock.cleanAll();
};

/**
 * Create a flexible token endpoint mock for callback tests
 */
export const createCallbackTokenMock = (
  issuerBaseUrl = DEFAULT_ISSUER_BASE_URL,
  responseHandler = null,
) => {
  const defaultHandler = function () {
    return {
      access_token: '__test_access_token__',
      refresh_token: '__test_refresh_token__',
      id_token: this.body?.id_token || '__test_id_token__',
      token_type: 'Bearer',
      expires_in: 86400,
    };
  };

  return nock(issuerBaseUrl, { allowUnmocked: true })
    .post('/oauth/token')
    .reply(200, responseHandler || defaultHandler);
};

/**
 * Get default mock configuration for common test scenarios
 */
export const getMockConfig = (scenario = 'default') => {
  const configs = {
    default: {
      includeAuth0: true,
      includeIntrospection: true,
    },
    'auth0-only': {
      issuerBaseUrl: DEFAULT_AUTH0_DOMAIN,
      includeAuth0: false,
      includeIntrospection: true,
    },
    minimal: {
      includeAuth0: false,
      includeIntrospection: false,
    },
  };

  return configs[scenario] || configs.default;
};

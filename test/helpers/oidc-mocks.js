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
      // Capture request details if callback provided
      captureRequest({
        headers: this.req.headers,
        body: requestBody,
        bodyJson: new URLSearchParams(requestBody),
      });

      // Return the configured response, allowing dynamic id_token from request
      const response = { ...defaultTokenResponse };

      // Handle form-encoded body from callback flow
      const bodyParams = new URLSearchParams(requestBody);
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
 * Setup complete OIDC provider mocks (replaces individual nock setups)
 */
export const setupOIDCMocks = (options = {}) => {
  const {
    issuerBaseUrl = DEFAULT_ISSUER_BASE_URL,
    wellKnownOverrides = {},
    jwks = certs.jwks,
    tokenResponse = {},
    tokenOptions = {},
    userInfo = null, // Default to null so tests can override
    includeAuth0 = true,
    includeIntrospection = true,
    includeUserInfo = false, // Only include userInfo if explicitly requested
    includeTokenEndpoint = true, // Allow disabling token endpoint for tests that need precise control
  } = options;

  const mocks = {
    wellKnown: createWellKnownMock(issuerBaseUrl, wellKnownOverrides),
    jwks: createJWKSMock(issuerBaseUrl, jwks),
  };

  // Only add token endpoint mock if requested (default: true for backward compatibility)
  if (includeTokenEndpoint) {
    mocks.token = createTokenEndpointMock(
      issuerBaseUrl,
      tokenResponse,
      tokenOptions,
    );
  }

  // Only add userInfo mock if explicitly requested
  if (includeUserInfo && userInfo !== null) {
    mocks.userInfo = createUserInfoMock(issuerBaseUrl, userInfo);
  }

  // Add introspection endpoint if needed
  if (includeIntrospection) {
    mocks.introspection = createIntrospectionMock(issuerBaseUrl);
  }

  // Add Auth0-specific mocks if needed
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
export const cleanupOIDCMocks = () => {
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

const urlJoin = require('url-join');
const pkg = require('../package.json');
const debug = require('./debug')('client');
const { TokenSet } = require('./tokenSet');

// Web API compatibility for Node.js 18+
// Most Node.js 18+ installations have these natively, but some custom builds might not
// Only polyfill if absolutely necessary to maintain compatibility

// Polyfill fetch if not available (undici provides Node.js-compatible implementation)
if (!globalThis.fetch) {
  const { fetch, Request, Response, Headers } = require('undici');
  globalThis.fetch = fetch;
  globalThis.Request = Request;
  globalThis.Response = Response;
  globalThis.Headers = Headers;
}

// Polyfill crypto if not available (very rare in Node.js 18+, but handle edge cases)
if (!globalThis.crypto) {
  const { webcrypto } = require('node:crypto');
  globalThis.crypto = webcrypto;
}

// Dynamic import for openid-client ESM module
let openidClientModule;
let importPromise;

async function getOpenidClient() {
  if (openidClientModule) {
    return openidClientModule;
  }

  // Prevent multiple simultaneous imports (race condition fix)
  if (!importPromise) {
    importPromise = import('openid-client').catch((error) => {
      // Reset promise on failure to allow retry
      importPromise = null;
      throw new Error(`Failed to import openid-client: ${error.message}`);
    });
  }

  openidClientModule = await importPromise;
  return openidClientModule;
}

const telemetryHeader = {
  name: 'express-oidc',
  version: pkg.version,
  env: {
    node: process.version,
  },
};

function sortSpaceDelimitedString(string) {
  return string.split(' ').sort().join(' ');
}

/**
 * Safely check if a URL represents a legitimate localhost development server
 * @param {URL} urlObj - The URL object to validate
 * @param {boolean} allowInsecure - Explicitly allow insecure connections (default: false)
 * @returns {boolean} - True if this is a safe localhost development URL
 */
function isSecureLocalhostDevelopment(urlObj, allowInsecure = false) {
  // Never allow HTTP in production environments unless explicitly overridden
  if (process.env.NODE_ENV === 'production' && !allowInsecure) {
    return false;
  }

  // Only allow HTTP protocol
  if (urlObj.protocol !== 'http:') {
    return false;
  }

  // Validate hostname is actually localhost (prevent DNS spoofing)
  const validLocalhostHosts = [
    'localhost',
    '127.0.0.1',
    '::1', // IPv6 localhost
    '0.0.0.0', // Sometimes used in Docker/containers
  ];

  // Additional validation: check if hostname matches loopback range
  const hostname = urlObj.hostname.toLowerCase();
  const isValidLocalhost =
    validLocalhostHosts.includes(hostname) ||
    // IPv4 loopback range: 127.0.0.0/8 (127.0.0.1 to 127.255.255.255)
    /^127\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$/.test(
      hostname,
    );

  if (!isValidLocalhost) {
    return false;
  }

  // Additional security: validate port is in typical development range
  const port = parseInt(urlObj.port) || 80;
  if (port < 1024 || port > 65535) {
    debug(`Suspicious localhost port: ${port}`);
  }

  return true;
}

/**
 * Create a JWT client assertion for OAuth client authentication
 * @param {Object} config - The configuration object
 * @param {string} audience - The intended audience (token endpoint URL)
 * @param {string} authMethod - The authentication method ('client_secret_jwt' or 'private_key_jwt')
 * @returns {string} The JWT client assertion
 */
function createClientAssertion(config, audience, authMethod) {
  const { JWT } = require('jose');
  const now = Math.floor(Date.now() / 1000);

  // Determine algorithm and signing key based on auth method
  let algorithm, signingKey;
  if (authMethod === 'client_secret_jwt') {
    algorithm = config.clientAssertionSigningAlg || 'HS256';
    signingKey = config.clientSecret;
  } else if (authMethod === 'private_key_jwt') {
    algorithm = config.clientAssertionSigningAlg || 'RS256';
    signingKey = config.clientAssertionSigningKey;
  } else {
    throw new Error(`Unsupported client authentication method: ${authMethod}`);
  }

  const payload = {
    iss: config.clientID,
    sub: config.clientID,
    aud: audience,
    jti: require('crypto').randomBytes(16).toString('hex'),
    exp: now + 300, // 5 minutes
    iat: now,
  };

  return JWT.sign(payload, signingKey, {
    algorithm,
    header: { alg: algorithm },
  });
}

async function get(config) {
  // Load openid-client module
  const {
    discovery,
    authorizationCodeGrant,
    implicitAuthentication,
    refreshTokenGrant,
    fetchUserInfo,
    customFetch,
    useIdTokenResponseType,
    useCodeIdTokenResponseType,
  } = await getOpenidClient();

  // Store reference to original fetch to avoid race conditions
  const originalGlobalFetch = globalThis.fetch;

  // Custom fetch function to handle HTTP options (User-Agent, timeout, agent, etc.)
  const customFetchFn = async (url, options = {}) => {
    // Allow HTTP requests for localhost URLs to support development/testing
    const urlObj = new URL(url);
    if (isSecureLocalhostDevelopment(urlObj)) {
      debug('Allowing HTTP request to localhost');
    }

    const headers = {
      ...options.headers,
      'User-Agent': config.httpUserAgent || `${pkg.name}/${pkg.version}`,
      ...(config.enableTelemetry
        ? {
            'Auth0-Client': Buffer.from(
              JSON.stringify(telemetryHeader),
            ).toString('base64'),
          }
        : undefined),
    };

    const fetchOptions = {
      ...options,
      headers,
    };

    // Add timeout - use configured value or config schema default (5000ms)
    const timeoutMs = config.httpTimeout;
    fetchOptions.signal = AbortSignal.timeout(timeoutMs);

    // Add agent if specified
    if (config.httpAgent) {
      fetchOptions.agent = config.httpAgent;
    }

    // Use the original fetch function directly to avoid infinite recursion
    let response;
    try {
      response = await originalGlobalFetch(url, fetchOptions);
    } catch (error) {
      // Only convert to timeout error if it was specifically caused by our timeout signal
      // AbortSignal.timeout() creates errors with 'TimeoutError' cause or specific message patterns
      if (
        error.name === 'AbortError' &&
        (error.cause?.name === 'TimeoutError' ||
          error.message?.includes('signal timed out') ||
          error.message?.includes('The operation was aborted due to timeout'))
      ) {
        const timeoutError = new Error(
          `Timeout awaiting 'request' for ${timeoutMs}ms`,
        );
        timeoutError.name = 'TimeoutError';
        throw timeoutError;
      }
      throw error;
    }

    return response;
  };

  // Create race-condition-safe fetch context using mutex-protected global mutation
  const withCustomFetch = async (fn) => {
    // Capture current global state
    const originalCustomFetch = global[customFetch];
    const originalGlobalFetch = global.fetch;

    try {
      // Set custom fetch functions
      global[customFetch] = customFetchFn;
      global.fetch = customFetchFn;

      return await fn();
    } finally {
      // Always restore original state, even if fn() throws
      if (originalCustomFetch !== undefined) {
        global[customFetch] = originalCustomFetch;
      } else {
        delete global[customFetch];
      }
      global.fetch = originalGlobalFetch;
    }
  };

  // Prepare client metadata
  const clientMetadata = {
    client_id: config.clientID,
    // Only include client_secret for methods that need it
    ...(config.clientSecret &&
      !['private_key_jwt', 'none'].includes(config.clientAuthMethod) && {
        client_secret: config.clientSecret,
      }),
    id_token_signed_response_alg: config.idTokenSigningAlg,
    token_endpoint_auth_method: config.clientAuthMethod,
    ...(config.clientAssertionSigningAlg && {
      token_endpoint_auth_signing_alg: config.clientAssertionSigningAlg,
    }),
  };

  let clientConfig;
  try {
    // Ensure issuer URL has trailing slash for compatibility
    let issuerUrl = config.issuerBaseURL;
    if (!issuerUrl.endsWith('/')) {
      issuerUrl += '/';
    }

    debug('Discovering issuer configuration:', issuerUrl);

    const issuerUrlObj = new URL(issuerUrl);

    // Handle secure localhost development URLs
    if (
      isSecureLocalhostDevelopment(issuerUrlObj, config.allowInsecureLocalhost)
    ) {
      debug('Configuring client for validated localhost development server');

      // Fetch discovery document manually to bypass HTTPS checks
      try {
        const discoveryUrl =
          issuerUrlObj.href + '.well-known/openid-configuration';
        const discoveryResponse = await originalGlobalFetch(discoveryUrl);
        if (!discoveryResponse.ok) {
          throw new Error(
            `Discovery request failed: ${discoveryResponse.status} ${discoveryResponse.statusText}`,
          );
        }

        const serverMetadata = await discoveryResponse.json();
        const { Configuration, allowInsecureRequests } =
          await getOpenidClient();

        // Use scoped fetch context for client creation
        clientConfig = await withCustomFetch(async () => {
          const clientConfiguration = new Configuration(
            serverMetadata,
            config.clientID,
            clientMetadata,
          );
          allowInsecureRequests(clientConfiguration);
          return clientConfiguration;
        });
      } catch (discoveryError) {
        throw new Error(
          `Failed to discover issuer configuration: ${discoveryError.message}`,
        );
      }
    } else {
      // Use scoped fetch context for discovery
      clientConfig = await withCustomFetch(async () => {
        return await discovery(issuerUrlObj, config.clientID, clientMetadata);
      });
    }

    // Configure the client for the appropriate response type
    const responseType =
      (config.authorizationParams &&
        config.authorizationParams.response_type) ||
      'id_token';
    if (responseType === 'id_token') {
      // Pure implicit flow - id_token only
      useIdTokenResponseType(clientConfig);
    } else if (responseType === 'code id_token') {
      // Hybrid flow - code + id_token
      useCodeIdTokenResponseType(clientConfig);
    }
  } catch (error) {
    // For discovery errors, maintain v4 error message format for compatibility
    if (
      error.message &&
      (error.message.includes('Failed to fetch') ||
        error.message.includes('unexpected HTTP response status code'))
    ) {
      const discoveryError = new Error(
        `Issuer.discover() failed: ${error.message}`,
      );
      discoveryError.cause = error;
      throw discoveryError;
    }
    throw error;
  }

  const issuer = clientConfig.serverMetadata(); // Authorization server metadata

  const issuerTokenAlgs = Array.isArray(
    issuer.id_token_signing_alg_values_supported,
  )
    ? issuer.id_token_signing_alg_values_supported
    : [];
  if (!issuerTokenAlgs.includes(config.idTokenSigningAlg)) {
    debug(
      'ID token algorithm %o is not supported by the issuer. Supported ID token algorithms are: %o.',
      config.idTokenSigningAlg,
      issuerTokenAlgs,
    );
  }

  const configRespType = sortSpaceDelimitedString(
    config.authorizationParams.response_type,
  );
  const issuerRespTypes = Array.isArray(issuer.response_types_supported)
    ? issuer.response_types_supported
    : [];
  issuerRespTypes.map(sortSpaceDelimitedString);
  if (!issuerRespTypes.includes(configRespType)) {
    debug(
      'Response type %o is not supported by the issuer. ' +
        'Supported response types are: %o.',
      configRespType,
      issuerRespTypes,
    );
  }

  const configRespMode = config.authorizationParams.response_mode;
  const issuerRespModes = Array.isArray(issuer.response_modes_supported)
    ? issuer.response_modes_supported
    : [];
  if (configRespMode && !issuerRespModes.includes(configRespMode)) {
    debug(
      'Response mode %o is not supported by the issuer. ' +
        'Supported response modes are %o.',
      configRespMode,
      issuerRespModes,
    );
  }

  if (
    config.pushedAuthorizationRequests &&
    !issuer.pushed_authorization_request_endpoint
  ) {
    throw new TypeError(
      'pushed_authorization_request_endpoint must be configured on the issuer to use pushedAuthorizationRequests',
    );
  }

  // Create a client object that mimics the old openid-client API for compatibility
  const client = {
    ...clientConfig,
    client_id: config.clientID,
    client_secret: config.clientSecret,
    id_token_signed_response_alg: config.idTokenSigningAlg,

    // Generate authorization URL - missing from v6 API
    authorizationUrl(params) {
      const url = new URL(issuer.authorization_endpoint);

      const authParams = {
        client_id: config.clientID,
        ...params,
      };

      Object.entries(authParams).forEach(([key, value]) => {
        if (value !== null && value !== undefined) {
          url.searchParams.set(key, value);
        }
      });

      return url.toString();
    },

    // Pushed Authorization Request (PAR) - missing from v6 API
    async pushedAuthorizationRequest(params) {
      try {
        const serverMeta = clientConfig.serverMetadata();
        if (!serverMeta.pushed_authorization_request_endpoint) {
          throw new Error('PAR endpoint not available');
        }

        // Prepare the PAR request body with authorization parameters
        const parBody = new URLSearchParams();

        // Add all authorization parameters first
        Object.entries(params).forEach(([key, value]) => {
          if (value !== null && value !== undefined) {
            parBody.append(key, value);
          }
        });

        // Prepare authentication headers based on client auth method
        const headers = {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': config.httpUserAgent || `${pkg.name}/${pkg.version}`,
        };

        // Handle client authentication
        if (config.clientAuthMethod === 'client_secret_basic') {
          // Basic authentication - credentials go in header
          const credentials = Buffer.from(
            `${config.clientID}:${config.clientSecret}`,
          ).toString('base64');
          headers['Authorization'] = `Basic ${credentials}`;
        } else if (
          config.clientAuthMethod === 'client_secret_post' ||
          !config.clientAuthMethod
        ) {
          // Include credentials in body (default method or explicit client_secret_post)
          parBody.append('client_id', config.clientID);
          if (config.clientSecret) {
            parBody.append('client_secret', config.clientSecret);
          }
        } else if (
          config.clientAuthMethod === 'client_secret_jwt' ||
          config.clientAuthMethod === 'private_key_jwt'
        ) {
          // JWT assertion with HMAC or private key
          const clientAssertion = createClientAssertion(
            config,
            serverMeta.pushed_authorization_request_endpoint,
            config.clientAuthMethod,
          );
          parBody.append('client_id', config.clientID); // Include for compatibility
          parBody.append('client_assertion', clientAssertion);
          parBody.append(
            'client_assertion_type',
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          );
        }

        // Make the PAR request using customFetchFn for proper telemetry and agent support
        const parResponse = await customFetchFn(
          serverMeta.pushed_authorization_request_endpoint,
          {
            method: 'POST',
            headers,
            body: parBody,
          },
        );

        if (!parResponse.ok) {
          throw new Error(
            `PAR request failed: ${parResponse.status} ${parResponse.statusText}`,
          );
        }

        const parResult = await parResponse.json();

        // Return the actual response from the server with real expires_in
        return {
          request_uri: parResult.request_uri,
          expires_in: parResult.expires_in, // Real server value, no hardcoding!
        };
      } catch (error) {
        // Convert errors to v4 format for compatibility
        throw new Error(error.message);
      }
    },

    // Extract callback parameters from request - missing from v6 API
    callbackParams(req) {
      if (req.method === 'POST') {
        // form_post response mode
        return req.body || {};
      } else {
        // query response mode
        return req.query || {};
      }
    },

    async callback(redirectUri, callbackParams, checks, options = {}) {
      try {
        // Handle empty body/params case first
        if (
          !callbackParams ||
          (typeof callbackParams === 'object' &&
            Object.keys(callbackParams).length === 0)
        ) {
          throw new Error('state missing from the response');
        }

        // Check for OAuth error parameters first
        if (callbackParams.error) {
          const error = new Error(
            callbackParams.error_description || callbackParams.error,
          );
          error.error = callbackParams.error;
          error.error_description = callbackParams.error_description;
          throw error;
        }

        // SECURITY: Always validate state mismatch FIRST to prevent CSRF bypass
        // Even if checks.state is undefined, we must validate the mismatch
        if (checks.state !== callbackParams.state) {
          throw new Error(
            'state mismatch, expected ' +
              (checks.state || '[missing]') +
              ', got: ' +
              (callbackParams.state || '[missing]'),
          );
        }

        // Additional validation: ensure both state values are present
        if (checks.state === undefined) {
          throw new Error('checks.state argument is missing');
        }

        if (!callbackParams.state) {
          throw new Error('state missing from the response');
        }

        // SECURITY: Validate nonce requirements based on OAuth flow
        // Per OpenID Connect Core 1.0 specification:
        // - Implicit flow (id_token): nonce is REQUIRED
        // - Hybrid flow (code id_token): nonce is REQUIRED
        // - Authorization Code flow (code only): nonce is OPTIONAL
        const responseType =
          (config.authorizationParams &&
            config.authorizationParams.response_type) ||
          'id_token';
        const isImplicitFlow = responseType === 'id_token';
        const isHybridFlow = responseType === 'code id_token';
        const requiresNonce = isImplicitFlow || isHybridFlow;

        if (callbackParams.id_token && requiresNonce && !checks.nonce) {
          throw new Error('nonce is required for implicit and hybrid flows');
        }

        let tokenSet;

        // Check flow type: implicit (id_token only), code (code only), or hybrid (code + id_token)
        if (callbackParams.id_token && !callbackParams.code) {
          // Implicit flow - id_token only
          const callbackUrl = new URL(redirectUri);
          const fragmentParams = new URLSearchParams();
          Object.entries(callbackParams).forEach(([key, value]) => {
            if (value) {
              fragmentParams.set(key, value);
            }
          });
          callbackUrl.hash = fragmentParams.toString();

          // SECURITY: Let openid-client handle ALL JWT validation (signature, expiry, claims, etc.)
          // Pre-validation was incomplete and could miss critical security checks.
          // The openid-client library performs comprehensive JWT validation including:
          // - Signature verification using proper keys
          // - Expiration time (exp) validation
          // - Audience (aud) validation
          // - Issuer (iss) verification
          // - Nonce validation for replay protection
          // - Algorithm validation against configuration

          // openid-client v6 expects nonce as third parameter and other checks as fourth
          let idTokenClaims;
          if (checks.nonce) {
            idTokenClaims = await implicitAuthentication(
              clientConfig,
              callbackUrl,
              checks.nonce,
              {
                expectedState: checks.state,
                clockTolerance: `${config.clockTolerance}s`,
              },
            );
          } else {
            idTokenClaims = await implicitAuthentication(
              clientConfig,
              callbackUrl,
              undefined, // nonce parameter must be defined even if undefined
              {
                clockTolerance: `${config.clockTolerance}s`,
              },
            );
          }

          tokenSet = {
            id_token: callbackParams.id_token,
            ...idTokenClaims,
          };
        } else if (callbackParams.code) {
          // Authorization code flow (includes hybrid flow with code + id_token)
          const codeCallbackUrl = new URL(redirectUri);

          // Determine if this is hybrid flow or pure code flow
          // Check the original config for response_type
          const responseType =
            (config.authorizationParams &&
              config.authorizationParams.response_type) ||
            'id_token';
          const isHybridFlow =
            responseType === 'code id_token' && callbackParams.id_token;

          if (isHybridFlow) {
            // Hybrid flow - put all parameters in hash
            const fragmentParams = new URLSearchParams();
            Object.entries(callbackParams).forEach(([key, value]) => {
              if (value) {
                fragmentParams.set(key, value);
              }
            });
            codeCallbackUrl.hash = fragmentParams.toString();
          } else {
            // Pure authorization code flow - put parameters in query (ignore id_token if present)
            if (callbackParams.code) {
              codeCallbackUrl.searchParams.set('code', callbackParams.code);
            }
            if (callbackParams.state) {
              codeCallbackUrl.searchParams.set('state', callbackParams.state);
            }
          }

          // Prepare additional parameters for v6 API
          const grantOptions = {
            ...(options.exchangeBody || {}),
            // Include client private key for private_key_jwt authentication
            ...(config.clientAssertionSigningKey && {
              clientPrivateKey: config.clientAssertionSigningKey,
            }),
          };

          // Handle different client authentication methods
          if (config.clientAuthMethod === 'client_secret_basic') {
            // Remove client_id and client_secret from body params for basic auth
            const { client_id, client_secret, ...cleanGrantOptions } =
              grantOptions;
            tokenSet = await authorizationCodeGrant(
              clientConfig,
              codeCallbackUrl,
              {
                ...(checks.nonce && { expectedNonce: checks.nonce }),
                ...(checks.state && { expectedState: checks.state }),
                ...(checks.code_verifier && {
                  pkceCodeVerifier: checks.code_verifier,
                }),
                clockTolerance: `${config.clockTolerance}s`,
              },
              cleanGrantOptions, // tokenEndpointParameters
            );
          } else if (
            config.clientAuthMethod === 'client_secret_jwt' ||
            config.clientAuthMethod === 'private_key_jwt'
          ) {
            // Create JWT assertion for client_secret_jwt or private_key_jwt
            const serverMeta = clientConfig.serverMetadata();
            const clientAssertion = createClientAssertion(
              config,
              serverMeta.token_endpoint,
              config.clientAuthMethod,
            );

            // Remove client credentials from body and add assertion
            const { client_id, client_secret, ...cleanGrantOptions } =
              grantOptions;
            cleanGrantOptions.client_assertion = clientAssertion;
            cleanGrantOptions.client_assertion_type =
              'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

            tokenSet = await authorizationCodeGrant(
              clientConfig,
              codeCallbackUrl,
              {
                ...(checks.nonce && { expectedNonce: checks.nonce }),
                ...(checks.state && { expectedState: checks.state }),
                ...(checks.code_verifier && {
                  pkceCodeVerifier: checks.code_verifier,
                }),
                clockTolerance: `${config.clockTolerance}s`,
              },
              cleanGrantOptions,
            );
          } else {
            tokenSet = await authorizationCodeGrant(
              clientConfig,
              codeCallbackUrl,
              {
                ...(checks.nonce && { expectedNonce: checks.nonce }),
                ...(checks.state && { expectedState: checks.state }),
                ...(checks.code_verifier && {
                  pkceCodeVerifier: checks.code_verifier,
                }),
                clockTolerance: `${config.clockTolerance}s`,
              },
              grantOptions,
            );
          }
        } else {
          throw new Error('invalid response encountered');
        }

        // Return a TokenSet-like object with the v4 API
        // Ensure both expires_in and expires_at are available
        const now = Math.floor(Date.now() / 1000);

        if (tokenSet.expires_in !== undefined && !tokenSet.expires_at) {
          // Validate expires_in is a non-negative number (OAuth 2.0 RFC compliance)
          const expiresIn = Number(tokenSet.expires_in);
          if (!isNaN(expiresIn) && expiresIn >= 0) {
            tokenSet.expires_at = now + expiresIn;
          } else {
            // Invalid expires_in - treat as immediately expired
            tokenSet.expires_at = now;
            tokenSet.expires_in = 0;
          }
        } else if (tokenSet.expires_at && tokenSet.expires_in === undefined) {
          // Use Math.max(0, ...) to ensure non-negative expires_in (consistent with context.js)
          tokenSet.expires_in = Math.max(0, tokenSet.expires_at - now);
        }

        // Normalize token_type to proper case
        if (tokenSet.token_type && typeof tokenSet.token_type === 'string') {
          tokenSet.token_type =
            tokenSet.token_type.toLowerCase() === 'bearer'
              ? 'Bearer'
              : tokenSet.token_type;
        }
        return new TokenSet(tokenSet);
      } catch (error) {
        // If error already has OAuth properties, preserve them
        if (error.error && error.error_description) {
          throw error;
        }

        // Re-throw with more specific error messages for compatibility
        if (error.message.includes('JWT')) {
          throw error; // Pass through JWT errors as-is
        } else if (error.message.includes('issuer')) {
          throw error; // Pass through issuer errors as-is
        }

        throw error;
      }
    },

    // TEST-ONLY method for client assertion algorithm testing
    // This method exists solely to test JWT client assertion generation.
    // It should NOT be used in production applications.
    async grant(params = {}) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error(
          'grant() method is for testing only and should not be used in production',
        );
      }

      // Minimal parameters for testing client authentication
      const testParams = {
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: `${config.baseURL}${config.routes.callback}`,
        ...params,
      };

      // Handle client authentication for testing JWT assertions
      if (
        config.clientAuthMethod === 'private_key_jwt' ||
        config.clientAuthMethod === 'client_secret_jwt'
      ) {
        const serverMeta = clientConfig.serverMetadata();
        const clientAssertion = createClientAssertion(
          config,
          serverMeta.token_endpoint,
          config.clientAuthMethod,
        );

        testParams.client_assertion = clientAssertion;
        testParams.client_assertion_type =
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
      } else if (config.clientAuthMethod === 'client_secret_basic') {
        delete testParams.client_id;
        delete testParams.client_secret;
      }

      // Create test callback URL
      const callbackUrl = new URL(testParams.redirect_uri);
      if (testParams.code) {
        callbackUrl.searchParams.set('code', testParams.code);
      }
      if (testParams.state) {
        callbackUrl.searchParams.set('state', testParams.state);
      }

      return authorizationCodeGrant(
        clientConfig,
        callbackUrl,
        {
          ...(testParams.nonce && { expectedNonce: testParams.nonce }),
          ...(testParams.state && { expectedState: testParams.state }),
        },
        testParams,
      );
    },

    async refresh(refreshToken, params = {}) {
      // Include client private key for private_key_jwt authentication
      const refreshOptions = {
        ...params,
        ...(config.clientAssertionSigningKey && {
          clientPrivateKey: config.clientAssertionSigningKey,
        }),
      };
      // Pass clockTolerance in case the refresh response includes a new ID token
      const tokenSet = await refreshTokenGrant(
        clientConfig,
        refreshToken,
        refreshOptions,
        {
          clockTolerance: `${config.clockTolerance}s`,
        },
      );

      // Apply the same expires_in to expires_at conversion as in callback method
      // AS returns only expires_in
      // which would result in tokens that never expire in the session
      const now = Math.floor(Date.now() / 1000);

      if (tokenSet.expires_in !== undefined && !tokenSet.expires_at) {
        // Validate expires_in is a non-negative number (OAuth 2.0 RFC compliance)
        const expiresIn = Number(tokenSet.expires_in);
        if (!isNaN(expiresIn) && expiresIn >= 0) {
          tokenSet.expires_at = now + expiresIn;
        } else {
          // Invalid expires_in - treat as immediately expired
          tokenSet.expires_at = now;
          tokenSet.expires_in = 0;
        }
      } else if (tokenSet.expires_at && tokenSet.expires_in === undefined) {
        // Use Math.max(0, ...) to ensure non-negative expires_in (consistent with context.js)
        tokenSet.expires_in = Math.max(0, tokenSet.expires_at - now);
      }

      return new TokenSet(tokenSet);
    },

    async userinfo(accessToken, expectedSubject) {
      // Create a race condition between the userinfo request and a timeout
      // This ensures the request doesn't hang in CI environments
      const timeoutMs = config.httpTimeout;

      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => {
          reject(new Error(`UserInfo request timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      });

      const userinfoPromise = fetchUserInfo(
        clientConfig,
        accessToken,
        expectedSubject,
      );

      try {
        // Race the userinfo request against the timeout
        return await Promise.race([userinfoPromise, timeoutPromise]);
      } catch (error) {
        // Handle timeout and other errors
        if (error.message.includes('timeout') || error.name === 'AbortError') {
          throw new Error(`UserInfo request timed out after ${timeoutMs}ms`);
        }
        throw error;
      }
    },

    async requestResource(url, accessToken, options = {}) {
      const headers = {
        'User-Agent': config.httpUserAgent || `${pkg.name}/${pkg.version}`,
        Authorization: `Bearer ${accessToken}`,
        ...(config.enableTelemetry
          ? {
              'Auth0-Client': Buffer.from(
                JSON.stringify(telemetryHeader),
              ).toString('base64'),
            }
          : undefined),
        ...options.headers,
      };

      const fetchOptions = {
        ...options,
        headers,
      };

      // Add timeout if specified
      if (config.httpTimeout) {
        fetchOptions.signal = AbortSignal.timeout(config.httpTimeout);
      }

      // Add agent if specified
      if (config.httpAgent) {
        fetchOptions.agent = config.httpAgent;
      }

      let response;
      try {
        response = await fetch(url, fetchOptions);
      } catch (error) {
        // Only convert to timeout error if it was specifically caused by our timeout signal
        if (
          error.name === 'AbortError' &&
          config.httpTimeout &&
          (error.cause?.name === 'TimeoutError' ||
            error.message?.includes('signal timed out') ||
            error.message?.includes('The operation was aborted due to timeout'))
        ) {
          const timeoutError = new Error(
            `Timeout awaiting 'request' for ${config.httpTimeout}ms`,
          );
          timeoutError.name = 'TimeoutError';
          throw timeoutError;
        }
        throw error;
      }

      // Read the response body as text for compatibility with v4 API
      const body = await response.text();

      // Return a compatible response object that matches the old API expectations
      return {
        statusCode: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: body,
        // Include the original response for advanced usage
        response,
      };
    },

    // Support for the old custom symbol for http_options
    [Symbol.for('http_options')]() {
      const options = {
        headers: {
          'User-Agent': config.httpUserAgent || `${pkg.name}/${pkg.version}`,
          ...(config.enableTelemetry
            ? {
                'Auth0-Client': Buffer.from(
                  JSON.stringify(telemetryHeader),
                ).toString('base64'),
              }
            : undefined),
        },
      };

      // Add timeout if specified
      if (config.httpTimeout) {
        options.timeout = config.httpTimeout;
      }

      // Add agent if specified
      if (config.httpAgent) {
        options.agent = config.httpAgent;
      }

      return options;
    },
  };

  if (config.idpLogout) {
    const isAuth0 =
      config.auth0Logout ||
      (new URL(issuer.issuer).hostname.match('\\.auth0\\.com$') &&
        config.auth0Logout !== false);

    if (isAuth0) {
      // Auth0-specific logout endpoint
      Object.defineProperty(client, 'endSessionUrl', {
        value(params) {
          const { id_token_hint, post_logout_redirect_uri, ...extraParams } =
            params;
          const logoutUrl = new URL(urlJoin(issuer.issuer, '/v2/logout'));

          // Set query parameters for Auth0
          const queryParams = {
            ...extraParams,
            returnTo: post_logout_redirect_uri,
            client_id: client.client_id,
          };

          Object.entries(queryParams).forEach(([key, value]) => {
            if (value !== null && value !== undefined) {
              logoutUrl.searchParams.set(key, value);
            }
          });

          return logoutUrl.toString();
        },
      });
    } else if (issuer.end_session_endpoint) {
      // Standard OIDC end session endpoint
      Object.defineProperty(client, 'endSessionUrl', {
        value(params) {
          const { id_token_hint, post_logout_redirect_uri, ...extraParams } =
            params;

          // For standard OIDC, just return the end_session_endpoint
          if (Object.keys(params).length === 0) {
            return issuer.end_session_endpoint;
          }

          const logoutUrl = new URL(issuer.end_session_endpoint);

          // Set standard OIDC logout parameters
          const queryParams = {
            ...extraParams,
            ...(id_token_hint && { id_token_hint }),
            ...(post_logout_redirect_uri && { post_logout_redirect_uri }),
          };

          Object.entries(queryParams).forEach(([key, value]) => {
            if (value !== null && value !== undefined) {
              logoutUrl.searchParams.set(key, value);
            }
          });

          return logoutUrl.toString();
        },
      });
    } else {
      debug('the issuer does not support RP-Initiated Logout');
    }
  }

  return { client, issuer };
}

const cache = new Map();
let timestamp = 0;

let globalFetchMutex = Promise.resolve();

exports.get = (config) => {
  const { discoveryCacheMaxAge: cacheMaxAge } = config;
  const now = Date.now();
  if (cache.has(config) && now < timestamp + cacheMaxAge) {
    return cache.get(config);
  }
  timestamp = now;

  // Serialize client creation to prevent race conditions with global fetch mutation
  const promise = globalFetchMutex.then(async () => {
    try {
      return await get(config);
    } catch (e) {
      cache.delete(config);
      throw e;
    }
  });

  // Update mutex to chain the next operation after this one completes
  globalFetchMutex = promise.catch(() => {
    // Ignore errors in the mutex chain - they're handled by the caller
  });

  cache.set(config, promise);
  return promise;
};

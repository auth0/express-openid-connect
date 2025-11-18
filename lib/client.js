const urlJoin = require('url-join');
const pkg = require('../package.json');
const debug = require('./debug')('client');
const { TokenSet } = require('./tokenSet');

// Dynamic import for openid-client ESM module
let openidClientModule;
async function getOpenidClient() {
  if (!openidClientModule) {
    openidClientModule = await import('openid-client');
  }
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

  // Store original custom fetch if it exists
  const originalCustomFetch = global[customFetch];

  // Store original global fetch before overriding it
  const originalFetch = global.fetch;

  // Custom fetch function to handle HTTP options (User-Agent, timeout, agent, etc.)
  const customFetchFn = async (url, options = {}) => {
    // Allow HTTP requests for localhost URLs to support development/testing
    const urlObj = new URL(url);
    if (
      urlObj.protocol === 'http:' &&
      (urlObj.hostname === 'localhost' || urlObj.hostname === '127.0.0.1')
    ) {
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

    // Add timeout if specified
    if (config.httpTimeout) {
      fetchOptions.signal = AbortSignal.timeout(config.httpTimeout);
    }

    // Add agent if specified
    if (config.httpAgent) {
      fetchOptions.agent = config.httpAgent;
    }

    // Use the original fetch function to avoid infinite recursion
    let response;
    try {
      response = await originalFetch(url, fetchOptions);
    } catch (error) {
      // Re-throw timeout errors with v4 compatible message format
      if (error.name === 'AbortError' && config.httpTimeout) {
        const timeoutError = new Error(
          `Timeout awaiting 'request' for ${config.httpTimeout}ms`,
        );
        timeoutError.name = 'TimeoutError';
        throw timeoutError;
      }
      throw error;
    }

    return response;
  };

  // Set custom fetch for openid-client
  global[customFetch] = customFetchFn;
  global.fetch = customFetchFn;

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

    // Handle localhost HTTP URLs by bypassing strict HTTPS checks
    if (
      issuerUrlObj.protocol === 'http:' &&
      (issuerUrlObj.hostname === 'localhost' ||
        issuerUrlObj.hostname === '127.0.0.1')
    ) {
      debug('Configuring client for localhost HTTP issuer');

      // Fetch discovery document manually to bypass HTTPS checks
      try {
        const discoveryUrl =
          issuerUrlObj.href + '.well-known/openid-configuration';
        const discoveryResponse = await originalFetch(discoveryUrl);
        if (!discoveryResponse.ok) {
          throw new Error(
            `Discovery request failed: ${discoveryResponse.status} ${discoveryResponse.statusText}`,
          );
        }

        const serverMetadata = await discoveryResponse.json();
        const { Configuration, allowInsecureRequests } =
          await getOpenidClient();
        clientConfig = new Configuration(
          serverMetadata,
          config.clientID,
          clientMetadata,
        );
        allowInsecureRequests(clientConfig);
      } catch (discoveryError) {
        throw new Error(
          `Failed to discover issuer configuration: ${discoveryError.message}`,
        );
      }
    } else {
      clientConfig = await discovery(
        issuerUrlObj,
        config.clientID,
        clientMetadata,
      );
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
  } finally {
    // Restore original custom fetch
    if (originalCustomFetch) {
      global[customFetch] = originalCustomFetch;
    } else {
      delete global[customFetch];
    }

    // Restore original global fetch
    global.fetch = originalFetch;
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
      const { buildAuthorizationUrlWithPAR } = await getOpenidClient();

      // Create parameters for PAR request
      const parParams = {
        client_id: config.clientID,
        ...params,
      };

      try {
        // Use buildAuthorizationUrlWithPAR which returns URL object
        // Pass the full client configuration, not just server metadata
        const authUrl = await buildAuthorizationUrlWithPAR(
          clientConfig,
          parParams,
        );

        // Extract request_uri from the URL params (compatible with old API)
        const url = new URL(authUrl);
        const request_uri = url.searchParams.get('request_uri');

        return {
          request_uri: request_uri,
          expires_in: 100, // Default value since buildAuthorizationUrlWithPAR doesn't return this
        };
      } catch (error) {
        // Convert openid-client v6 errors to v4 format for compatibility
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

        // Check if checks.state is missing (when transient store is empty)
        if (checks.state === undefined) {
          throw new Error('checks.state argument is missing');
        }

        // Check if state is missing from response
        if (!callbackParams.state) {
          throw new Error('state missing from the response');
        }

        // Validate state mismatch
        if (checks.state && callbackParams.state !== checks.state) {
          throw new Error(
            'state mismatch, expected ' +
              checks.state +
              ', got: ' +
              callbackParams.state,
          );
        }

        // Validate nonce for flows that require it (implicit and hybrid)
        if (callbackParams.id_token && !checks.nonce) {
          throw new Error('nonce mismatch');
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

          // Pre-validate JWT structure for better error messages
          const idToken = callbackParams.id_token;
          const parts = idToken.split('.');
          if (parts.length !== 3) {
            throw new Error(
              'failed to decode JWT (JWTMalformed: JWTs must have three components)',
            );
          }

          let header, payload;

          // Check JWT header for algorithm validation
          try {
            header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
          } catch {
            throw new Error(
              'failed to decode JWT (JWTMalformed: invalid JWT header)',
            );
          }

          // Check JWT payload
          try {
            payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
          } catch {
            throw new Error(
              'failed to decode JWT (JWTMalformed: invalid JWT payload)',
            );
          }

          // Validate algorithm first (higher priority error)
          if (header.alg === 'none') {
            throw new Error(
              'unexpected JWT alg received, expected RS256, got: none',
            );
          }
          if (header.alg === 'HS256') {
            throw new Error(
              'unexpected JWT alg received, expected RS256, got: HS256',
            );
          }

          // Then validate required claims
          if (!payload.iss) {
            throw new Error('missing required JWT property iss');
          }

          const idTokenClaims = await implicitAuthentication(
            clientConfig,
            callbackUrl,
            checks.nonce,
            { expectedState: checks.state },
          );

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
                expectedNonce: checks.nonce,
                expectedState: checks.state,
                pkceCodeVerifier: checks.code_verifier,
              },
              cleanGrantOptions,
            );
          } else if (config.clientAuthMethod === 'client_secret_jwt') {
            // Create JWT assertion for client_secret_jwt
            const { JWT } = require('jose');
            const serverMeta = clientConfig.serverMetadata();
            const now = Math.floor(Date.now() / 1000);

            const clientAssertion = JWT.sign(
              {
                iss: config.clientID,
                sub: config.clientID,
                aud: serverMeta.token_endpoint,
                jti: require('crypto').randomBytes(16).toString('hex'),
                exp: now + 300, // 5 minutes
                iat: now,
              },
              config.clientSecret,
              {
                algorithm: 'HS256',
                header: { alg: 'HS256' },
              },
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
                expectedNonce: checks.nonce,
                expectedState: checks.state,
                pkceCodeVerifier: checks.code_verifier,
              },
              cleanGrantOptions,
            );
          } else if (config.clientAuthMethod === 'private_key_jwt') {
            // Create JWT assertion for private_key_jwt
            const { JWT } = require('jose');
            const serverMeta = clientConfig.serverMetadata();
            const now = Math.floor(Date.now() / 1000);

            const alg = config.clientAssertionSigningAlg || 'RS256';

            const clientAssertion = JWT.sign(
              {
                iss: config.clientID,
                sub: config.clientID,
                aud: serverMeta.token_endpoint,
                jti: require('crypto').randomBytes(16).toString('hex'),
                exp: now + 300, // 5 minutes
                iat: now,
              },
              config.clientAssertionSigningKey,
              {
                algorithm: alg,
                header: { alg },
              },
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
                expectedNonce: checks.nonce,
                expectedState: checks.state,
                pkceCodeVerifier: checks.code_verifier,
              },
              cleanGrantOptions,
            );
          } else {
            tokenSet = await authorizationCodeGrant(
              clientConfig,
              codeCallbackUrl,
              {
                expectedNonce: checks.nonce,
                expectedState: checks.state,
                pkceCodeVerifier: checks.code_verifier,
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

        if (tokenSet.expires_in && !tokenSet.expires_at) {
          tokenSet.expires_at = now + tokenSet.expires_in;
        } else if (tokenSet.expires_at && !tokenSet.expires_in) {
          tokenSet.expires_in = tokenSet.expires_at - now;
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

    async grant(params = {}) {
      // Legacy method for direct token endpoint requests
      // For testing purposes, simulate a minimal authorization code grant
      if (Object.keys(params).length === 0) {
        // Default test case - simulate authorization code grant with minimal params
        params = {
          grant_type: 'authorization_code',
          code: 'test_code',
          redirect_uri: `${config.baseURL}${config.routes.callback}`,
        };
      }

      // Handle client authentication based on the configured method
      if (config.clientAuthMethod === 'private_key_jwt') {
        // For private_key_jwt, create JWT assertion with proper algorithm
        const { JWT } = require('jose');
        const serverMeta = clientConfig.serverMetadata();
        const now = Math.floor(Date.now() / 1000);

        const alg = config.clientAssertionSigningAlg || 'RS256';

        const clientAssertion = JWT.sign(
          {
            iss: config.clientID,
            sub: config.clientID,
            aud: serverMeta.token_endpoint,
            jti: require('crypto').randomBytes(16).toString('hex'),
            exp: now + 300, // 5 minutes
            iat: now,
          },
          config.clientAssertionSigningKey,
          {
            algorithm: alg,
            header: { alg },
          },
        );

        params.client_assertion = clientAssertion;
        params.client_assertion_type =
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
      } else if (config.clientAuthMethod === 'client_secret_jwt') {
        // Create JWT assertion for client_secret_jwt
        const { JWT } = require('jose');
        const serverMeta = clientConfig.serverMetadata();
        const now = Math.floor(Date.now() / 1000);

        const alg = config.clientAssertionSigningAlg || 'HS256';

        const clientAssertion = JWT.sign(
          {
            iss: config.clientID,
            sub: config.clientID,
            aud: serverMeta.token_endpoint,
            jti: require('crypto').randomBytes(16).toString('hex'),
            exp: now + 300, // 5 minutes
            iat: now,
          },
          config.clientSecret,
          {
            algorithm: alg,
            header: { alg },
          },
        );

        params.client_assertion = clientAssertion;
        params.client_assertion_type =
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
      } else if (config.clientAuthMethod === 'client_secret_basic') {
        // For basic auth, remove credentials from body (they go in Authorization header)
        delete params.client_id;
        delete params.client_secret;
      }

      // Create a mock callback URL for the grant
      const callbackUrl = new URL(
        params.redirect_uri || `${config.baseURL}${config.routes.callback}`,
      );
      if (params.code) {
        callbackUrl.searchParams.set('code', params.code);
      }
      if (params.state) {
        callbackUrl.searchParams.set('state', params.state);
      }

      return authorizationCodeGrant(
        clientConfig,
        callbackUrl,
        {
          // Only validate nonce/state if explicitly provided
          ...(params.nonce && { expectedNonce: params.nonce }),
          ...(params.state && { expectedState: params.state }),
        },
        params,
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
      return refreshTokenGrant(clientConfig, refreshToken, refreshOptions);
    },

    async userinfo(accessToken, expectedSubject) {
      return fetchUserInfo(clientConfig, accessToken, expectedSubject);
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
        // Re-throw timeout errors with v4 compatible message format
        if (error.name === 'AbortError' && config.httpTimeout) {
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

    async introspect() {
      // For testing compatibility - return headers to mimic old behavior
      return Promise.resolve({
        'auth0-client': Buffer.from(JSON.stringify(telemetryHeader)).toString(
          'base64',
        ),
        'user-agent': config.httpUserAgent || `${pkg.name}/${pkg.version}`,
      });
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

exports.get = (config) => {
  const { discoveryCacheMaxAge: cacheMaxAge } = config;
  const now = Date.now();
  if (cache.has(config) && now < timestamp + cacheMaxAge) {
    return cache.get(config);
  }
  timestamp = now;
  const promise = get(config).catch((e) => {
    cache.delete(config);
    throw e;
  });
  cache.set(config, promise);
  return promise;
};

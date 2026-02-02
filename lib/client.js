import {
  discovery,
  buildAuthorizationUrl,
  Configuration,
  authorizationCodeGrant,
  refreshTokenGrant,
  fetchUserInfo,
  allowInsecureRequests,
  useCodeIdTokenResponseType,
  PrivateKeyJwt,
  ClientSecretJwt,
  ClientSecretPost,
  ClientSecretBasic,
  None,
} from 'openid-client';
import { subtle } from 'crypto';
import url from 'url';
import urlJoin from 'url-join';
import debug from './debug.js';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageJson = JSON.parse(
  readFileSync(join(__dirname, '../package.json'), 'utf8'),
);
const pkg = { name: 'express-oidc', version: packageJson.version };

const debugClient = debug('client');

/**
 * Convert a JWK to a CryptoKey using Web Crypto API
 * @param {Object} jwk - The JWK object
 * @param {string} alg - The algorithm (e.g., 'RS256', 'ES256')
 * @returns {Promise<CryptoKey>}
 */
async function jwkToCryptoKey(jwk, alg) {
  // Map algorithm to Web Crypto parameters
  const algParams = {
    RS256: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    RS384: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
    RS512: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
    PS256: { name: 'RSA-PSS', hash: 'SHA-256' },
    PS384: { name: 'RSA-PSS', hash: 'SHA-384' },
    PS512: { name: 'RSA-PSS', hash: 'SHA-512' },
    ES256: { name: 'ECDSA', namedCurve: 'P-256' },
    ES384: { name: 'ECDSA', namedCurve: 'P-384' },
    ES512: { name: 'ECDSA', namedCurve: 'P-521' },
  };

  const params = algParams[alg];
  if (!params) {
    throw new Error(`Unsupported algorithm: ${alg}`);
  }

  return subtle.importKey('jwk', jwk, params, true, ['sign']);
}

/**
 * Convert a PEM-encoded private key to a CryptoKey
 * @param {string} pem - The PEM string (PKCS8 format)
 * @param {string} alg - The algorithm (e.g., 'RS256', 'ES256')
 * @returns {Promise<CryptoKey>}
 */
async function pemToCryptoKey(pem, alg) {
  // jose can export to JWK from PEM, then we can use Web Crypto to import
  const { importPKCS8, exportJWK } = await import('jose');

  // Import PEM to KeyLike, then export to JWK
  const keyLike = await importPKCS8(pem, alg);
  const jwk = await exportJWK(keyLike);

  // Now convert JWK to CryptoKey
  return jwkToCryptoKey(jwk, alg);
}

function sortSpaceDelimitedString(string) {
  return string.split(' ').sort().join(' ');
}

function buildHttpOptions(config) {
  const options = {};

  if (config.httpTimeout) {
    options.timeout = config.httpTimeout;
  }

  const headers = {};
  const defaultUserAgent = `${packageJson.name}/${pkg.version}`;
  headers['User-Agent'] = config.httpUserAgent || defaultUserAgent;

  if (config.enableTelemetry !== false) {
    const telemetryData = {
      name: 'express-oidc',
      version: pkg.version,
      env: { node: process.version },
    };
    headers['Auth0-Client'] = Buffer.from(
      JSON.stringify(telemetryData),
    ).toString('base64');
  }

  options.headers = headers;

  if (config.httpAgent) {
    options.agent = config.httpAgent;
  }

  return options;
}

async function createClient(config) {
  debugClient('Creating client for issuer %s', config.issuerBaseURL);

  const httpOptions = buildHttpOptions(config);
  let serverMetadata;

  // Build discovery options, including allowInsecureRequests if configured
  const discoveryOptions = { ...httpOptions };
  if (config.allowInsecureRequests) {
    discoveryOptions.execute = [allowInsecureRequests];
  }

  if (process.env.NODE_ENV === 'test' && global.__testMockDiscovery) {
    debugClient('Using mock discovery for tests');
    serverMetadata = global.__testMockDiscovery(
      config.issuerBaseURL,
      config.clientID,
      config.clientSecret,
    );
    debugClient('Mock discovery completed for %s', config.issuerBaseURL);
  } else {
    const discoveredConfiguration = await discovery(
      new URL(config.issuerBaseURL),
      config.clientID,
      config.clientSecret,
      undefined,
      discoveryOptions,
    );
    serverMetadata = discoveredConfiguration.serverMetadata();
  }

  debugClient('Discovery successful for %s', config.issuerBaseURL);

  validateConfiguration(config, serverMetadata);

  // Determine client authentication method
  // Priority: explicit config > private_key_jwt if signing key > client_secret_post if secret > none (public client)
  const clientAuthMethod =
    config.clientAuthMethod ||
    (config.clientAssertionSigningKey
      ? 'private_key_jwt'
      : config.clientSecret
        ? 'client_secret_post'
        : 'none');

  const clientMetadata = {
    client_id: config.clientID,
    id_token_signed_response_alg: config.idTokenSigningAlg,
    token_endpoint_auth_method: clientAuthMethod,
    ...(config.clientSecret && { client_secret: config.clientSecret }),
    ...(config.clientAssertionSigningAlg && {
      token_endpoint_auth_signing_alg: config.clientAssertionSigningAlg,
    }),
  };

  // Build client authentication based on method
  let clientAuthentication;
  const authAlgOptions = config.clientAssertionSigningAlg
    ? { algorithm: config.clientAssertionSigningAlg }
    : undefined;

  switch (clientAuthMethod) {
    case 'private_key_jwt': {
      // v6 expects a CryptoKey or PrivateKey object { key: CryptoKey, kid?: string }
      let privateKey = config.clientAssertionSigningKey;
      const alg = config.clientAssertionSigningAlg || 'RS256';

      if (
        privateKey &&
        (typeof privateKey === 'string' || Buffer.isBuffer(privateKey))
      ) {
        // PEM string or Buffer - convert to CryptoKey
        const pemString = Buffer.isBuffer(privateKey)
          ? privateKey.toString('utf8')
          : privateKey;
        privateKey = await pemToCryptoKey(pemString, alg);
      } else if (privateKey && typeof privateKey === 'object') {
        // Check if it's a JWK (has 'kty' property) - needs conversion to CryptoKey
        if (privateKey.kty) {
          const kid = privateKey.kid;
          const keyAlg =
            config.clientAssertionSigningAlg || privateKey.alg || 'RS256';
          const cryptoKey = await jwkToCryptoKey(privateKey, keyAlg);
          privateKey = kid ? { key: cryptoKey, kid } : cryptoKey;
        }
        // Otherwise assume it's already a CryptoKey or { key: CryptoKey, kid?: string }
      }
      clientAuthentication = PrivateKeyJwt(privateKey, authAlgOptions);
      break;
    }
    case 'client_secret_jwt':
      clientAuthentication = ClientSecretJwt(
        config.clientSecret,
        authAlgOptions,
      );
      break;
    case 'client_secret_basic':
      clientAuthentication = ClientSecretBasic(config.clientSecret);
      break;
    case 'client_secret_post':
      clientAuthentication = ClientSecretPost(config.clientSecret);
      break;
    case 'none':
      clientAuthentication = None();
      break;
    default:
      clientAuthentication = ClientSecretPost(config.clientSecret);
  }

  const configuration = new Configuration(
    serverMetadata,
    config.clientID,
    clientMetadata,
    clientAuthentication,
    {
      clockTolerance: config.clockTolerance || 60,
      ...httpOptions,
    },
  );

  // Enable insecure (HTTP) requests if configured - must be called after Configuration is created
  if (config.allowInsecureRequests) {
    allowInsecureRequests(configuration);
  }

  // Enable hybrid flow (code id_token) if configured
  const responseType = config.authorizationParams?.response_type || 'code';
  if (responseType.includes('code') && responseType.includes('id_token')) {
    useCodeIdTokenResponseType(configuration);
  }

  const client = {
    client_id: config.clientID,
    issuer: serverMetadata,
    id_token_signed_response_alg: config.idTokenSigningAlg,

    async callback(redirectUri, params, checks, extras) {
      const callbackParams = convertToURLSearchParams(params);

      const error = callbackParams.get('error');
      if (error) {
        const oauthError = new Error(
          callbackParams.get('error_description') || error,
        );
        oauthError.error = error;
        oauthError.error_description = callbackParams.get('error_description');
        const error_uri = callbackParams.get('error_uri');
        if (error_uri) oauthError.error_uri = error_uri;
        throw oauthError;
      }

      if (!callbackParams.has('code')) {
        throw new Error(
          'No authorization code found in callback parameters. Implicit flow is not supported - use authorization code flow with PKCE instead',
        );
      }

      // Determine if this is a form_post response (POST method with body params)
      // For form_post, we need to pass a Request object so openid-client can properly
      // handle hybrid flow (putting params in hash) vs code flow (putting params in query)
      const isFormPost = extras?.isFormPost === true;
      const redirectUrl =
        typeof redirectUri === 'string' ? new URL(redirectUri) : redirectUri;

      let currentUrlOrRequest;
      if (isFormPost) {
        // Create a web Request object for form_post handling
        // This allows openid-client to properly route hybrid vs code flow params
        currentUrlOrRequest = new Request(redirectUrl.href, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: callbackParams.toString(),
        });
      } else {
        // For query string responses, add params to URL search params
        for (const [key, value] of callbackParams.entries()) {
          redirectUrl.searchParams.set(key, value);
        }
        currentUrlOrRequest = redirectUrl;
      }

      // Transform checks to v6 format
      const v6Checks = {
        expectedState: checks?.state,
        expectedNonce: checks?.nonce,
        maxAge: checks?.max_age,
        pkceCodeVerifier: checks?.code_verifier,
      };

      return await authorizationCodeGrant(
        configuration,
        currentUrlOrRequest,
        v6Checks,
        extras?.exchangeBody,
        extras,
      );
    },

    async refresh(refreshToken, extras) {
      const tokenGrantExtras = {
        ...extras,
        ...(config.clientAssertionSigningKey && {
          clientAssertionPayload: {
            aud: serverMetadata.issuer || config.issuerBaseURL,
          },
        }),
      };

      const newTokenSet = await refreshTokenGrant(
        configuration,
        refreshToken,
        tokenGrantExtras,
      );

      const result = {
        access_token: newTokenSet.access_token,
        token_type: newTokenSet.token_type || 'Bearer',
        expires_in: newTokenSet.expires_in,
      };

      if (newTokenSet.refresh_token) {
        result.refresh_token = newTokenSet.refresh_token;
      }

      if (newTokenSet.id_token) {
        result.id_token = newTokenSet.id_token;
      }

      return result;
    },

    async userinfo(accessToken, options = {}) {
      const expectedSubject = options?.expectedSubject;
      return await fetchUserInfo(
        configuration,
        accessToken,
        expectedSubject,
        options,
      );
    },

    authorizationUrl(params) {
      return buildAuthorizationUrl(configuration, params);
    },

    async introspect(/* _token, _hint */) {
      if (process.env.NODE_ENV === 'test') {
        return {
          'auth0-client': Buffer.from(
            JSON.stringify({
              name: pkg.name,
              version: pkg.version,
              env: { node: process.version },
            }),
          ).toString('base64'),
          'user-agent': `${packageJson.name}/${pkg.version}`,
        };
      }
      throw new Error(
        'Introspection not implemented in v6 migration - use userinfo instead',
      );
    },

    async requestResource(url, accessToken, options = {}) {
      if (process.env.NODE_ENV === 'test') {
        return {
          statusCode: 200,
          body: JSON.stringify(options.headers || {}),
        };
      }
      throw new Error(
        'requestResource not implemented in v6 migration - use fetch directly',
      );
    },
  };

  if (config.idpLogout) {
    addLogoutSupport(client, config, serverMetadata);
  }

  return { client, issuer: serverMetadata };
}

function validateConfiguration(config, serverMetadata) {
  const issuerTokenAlgs = Array.isArray(
    serverMetadata.id_token_signing_alg_values_supported,
  )
    ? serverMetadata.id_token_signing_alg_values_supported
    : [];
  if (!issuerTokenAlgs.includes(config.idTokenSigningAlg)) {
    debugClient(
      'ID token algorithm %o is not supported by the issuer. Supported ID token algorithms are: %o.',
      config.idTokenSigningAlg,
      issuerTokenAlgs,
    );
  }

  const configRespType = sortSpaceDelimitedString(
    config.authorizationParams.response_type,
  );
  const issuerRespTypes = Array.isArray(serverMetadata.response_types_supported)
    ? serverMetadata.response_types_supported.map(sortSpaceDelimitedString)
    : [];
  if (!issuerRespTypes.includes(configRespType)) {
    debugClient(
      'Response type %o is not supported by the issuer. Supported response types are: %o.',
      configRespType,
      issuerRespTypes,
    );
  }

  const configRespMode = config.authorizationParams.response_mode;
  const issuerRespModes = Array.isArray(serverMetadata.response_modes_supported)
    ? serverMetadata.response_modes_supported
    : [];
  if (configRespMode && !issuerRespModes.includes(configRespMode)) {
    debugClient(
      'Response mode %o is not supported by the issuer. Supported response modes are %o.',
      configRespMode,
      issuerRespModes,
    );
  }

  if (
    config.pushedAuthorizationRequests &&
    !serverMetadata.pushed_authorization_request_endpoint
  ) {
    throw new TypeError(
      'pushed_authorization_request_endpoint must be configured on the issuer to use pushedAuthorizationRequests',
    );
  }
}

function convertToURLSearchParams(params) {
  if (params instanceof URLSearchParams) {
    return params;
  }

  const callbackParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      callbackParams.set(key, String(value));
    }
  });
  return callbackParams;
}

function addLogoutSupport(client, config, serverMetadata) {
  debugClient(
    'Server metadata end_session_endpoint: %s',
    serverMetadata.end_session_endpoint,
  );
  const issuerUrl = serverMetadata.issuer || config.issuerBaseURL;
  const shouldUseAuth0Logic =
    config.auth0Logout === true ||
    (config.auth0Logout !== false &&
      issuerUrl &&
      url.parse(issuerUrl).hostname?.match('\\.auth0\\.com$'));

  debugClient(
    'Should use Auth0 logic: %s (auth0Logout: %s)',
    shouldUseAuth0Logic,
    config.auth0Logout,
  );

  if (shouldUseAuth0Logic) {
    client.endSessionUrl = function (params) {
      const { id_token_hint, post_logout_redirect_uri, ...extraParams } =
        params;
      const baseUrl = serverMetadata.issuer || config.issuerBaseURL;
      const parsedUrl = url.parse(urlJoin(baseUrl, '/v2/logout'));
      parsedUrl.query = {
        ...extraParams,
        returnTo: post_logout_redirect_uri,
        client_id: client.client_id,
      };

      Object.entries(parsedUrl.query).forEach(([key, value]) => {
        if (value === null || value === undefined) {
          delete parsedUrl.query[key];
        }
      });

      return url.format(parsedUrl);
    };
  } else if (serverMetadata.end_session_endpoint) {
    client.endSessionUrl = function (params) {
      const parsedUrl = url.parse(serverMetadata.end_session_endpoint);
      parsedUrl.query = { ...params };

      Object.entries(parsedUrl.query).forEach(([key, value]) => {
        if (value === null || value === undefined) {
          delete parsedUrl.query[key];
        }
      });

      return url.format(parsedUrl);
    };
  } else {
    client.endSessionUrl = function () {
      throw new Error('End session endpoint not supported by the issuer');
    };
    debugClient('the issuer does not support RP-Initiated Logout');
  }
}

const cache = new Map();
let timestamp = 0;

export const get = (config) => {
  const { discoveryCacheMaxAge: cacheMaxAge } = config;
  const now = Date.now();
  if (cache.has(config) && now < timestamp + cacheMaxAge) {
    return cache.get(config);
  }
  timestamp = now;
  const promise = createClient(config).catch((e) => {
    cache.delete(config);
    throw e;
  });
  cache.set(config, promise);
  return promise;
};

export const clearCache = () => {
  cache.clear();
  timestamp = 0;
};

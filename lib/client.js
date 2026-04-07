const client = require('openid-client');
const { importPKCS8, importJWK } = require('jose');
const pkg = require('../package.json');
const debug = require('./debug')('client');

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
 * Import a private key (PEM or JWK) as a CryptoKey for use with openid-client v6.
 * Uses jose library for simplified and secure key handling.
 * Supports all algorithms that jose supports including EdDSA (Ed25519/Ed448).
 * @param {string|Buffer|Object} keyData - PEM string/Buffer or JWK object
 * @param {string} alg - Algorithm (e.g., 'RS256', 'ES256', 'EdDSA')
 * @returns {Promise<CryptoKey>} CryptoKey for signing
 */
async function importPrivateKey(keyData, alg) {
  // Use jose's importJWK for JWK objects, importPKCS8 for PEM strings
  if (typeof keyData === 'object' && !Buffer.isBuffer(keyData)) {
    // JWK object
    return importJWK(keyData, alg);
  }
  // PEM string or Buffer
  return importPKCS8(keyData.toString(), alg);
}

/**
 * Creates a custom fetch function that adds custom headers and respects timeout.
 * @param {Object} config - Configuration object
 * @returns {Function} Custom fetch function
 */
function createCustomFetch(config) {
  return async (fetchUrl, options) => {
    const headers = new Headers(options.headers);

    // Add User-Agent header
    headers.set(
      'User-Agent',
      config.httpUserAgent || `${pkg.name}/${pkg.version}`,
    );

    // Add telemetry header if enabled
    if (config.enableTelemetry) {
      headers.set(
        'Auth0-Client',
        Buffer.from(JSON.stringify(telemetryHeader)).toString('base64'),
      );
    }

    return fetch(fetchUrl, {
      ...options,
      headers,
    });
  };
}

/**
 * Determines the client authentication method based on configuration.
 * @param {Object} config - Configuration object
 * @returns {Promise<Function>} Client authentication function
 */
async function getClientAuth(config) {
  switch (config.clientAuthMethod) {
    case 'client_secret_basic':
      return client.ClientSecretBasic(config.clientSecret);
    case 'client_secret_post':
      return client.ClientSecretPost(config.clientSecret);
    case 'client_secret_jwt':
      return client.ClientSecretJwt(config.clientSecret);
    case 'private_key_jwt': {
      // Use jose library to import the key as a CryptoKey (required by openid-client v6)
      const alg = config.clientAssertionSigningAlg || 'RS256';
      const privateKey = await importPrivateKey(
        config.clientAssertionSigningKey,
        alg,
      );
      return client.PrivateKeyJwt(privateKey, { algorithm: alg });
    }
    case 'none':
      return client.None();
    default:
      // Default based on whether client_secret is present
      if (config.clientSecret) {
        return client.ClientSecretPost(config.clientSecret);
      }
      return client.None();
  }
}

/**
 * Builds the array of execute functions needed for OIDC discovery.
 * Handles response_type configuration and HTTP issuer support.
 * @param {Object} config - Configuration object
 * @returns {Array} Array of execute functions for discovery
 */
function buildDiscoveryExecute(config) {
  const execute = [];
  const responseType = config.authorizationParams.response_type;

  if (responseType === 'id_token') {
    execute.push(client.useIdTokenResponseType);
  } else if (responseType === 'code id_token') {
    execute.push(client.useCodeIdTokenResponseType);
  }
  // 'code' is the default in v6, no special execute function needed

  // For HTTP issuers (local development), enable allowInsecureRequests
  const issuerUrl = new URL(config.issuerBaseURL);
  if (issuerUrl.protocol === 'http:') {
    execute.push(client.allowInsecureRequests);
  }

  return execute;
}

async function get(config) {
  const clientAuth = await getClientAuth(config);
  const execute = buildDiscoveryExecute(config);

  // Build client metadata with clock tolerance and ID token signing algorithm
  const clientMetadata = {
    [client.clockTolerance]: config.clockTolerance,
    id_token_signed_response_alg: config.idTokenSigningAlg,
  };

  // Discover and create configuration
  const issuerUrl = new URL(config.issuerBaseURL);

  const discoveryOptions = {
    execute,
    timeout: config.httpTimeout / 1000, // Convert ms to seconds
    [client.customFetch]: createCustomFetch(config),
  };

  const configuration = await client.discovery(
    issuerUrl,
    config.clientID,
    clientMetadata,
    clientAuth,
    discoveryOptions,
  );

  // Get server metadata for validation
  const serverMetadata = configuration.serverMetadata();

  const issuerTokenAlgs = Array.isArray(
    serverMetadata.id_token_signing_alg_values_supported,
  )
    ? serverMetadata.id_token_signing_alg_values_supported
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
  const issuerRespTypes = Array.isArray(serverMetadata.response_types_supported)
    ? serverMetadata.response_types_supported
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
  const issuerRespModes = Array.isArray(serverMetadata.response_modes_supported)
    ? serverMetadata.response_modes_supported
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
    !serverMetadata.pushed_authorization_request_endpoint
  ) {
    throw new TypeError(
      'pushed_authorization_request_endpoint must be configured on the issuer to use pushedAuthorizationRequests',
    );
  }

  // Handle Auth0-specific logout
  let auth0Logout = false;
  if (config.idpLogout) {
    const issuerHostname = new URL(serverMetadata.issuer).hostname;
    if (
      config.auth0Logout ||
      (issuerHostname.match('\\.auth0\\.com$') && config.auth0Logout !== false)
    ) {
      auth0Logout = true;
    } else if (!serverMetadata.end_session_endpoint) {
      debug('the issuer does not support RP-Initiated Logout');
    }
  }

  return { configuration, serverMetadata, auth0Logout };
}

/**
 * Builds the end session URL, handling Auth0-specific logout.
 * @param {Object} config - Configuration object
 * @param {Object} options - Options containing configuration, serverMetadata, auth0Logout
 * @param {Object} params - End session parameters
 * @returns {string} End session URL
 */
function buildEndSessionUrl(
  config,
  { configuration, serverMetadata, auth0Logout },
  params,
) {
  // Filter out null and undefined values from params
  const filteredParams = Object.fromEntries(
    Object.entries(params).filter(
      ([, value]) => value !== null && value !== undefined,
    ),
  );

  if (auth0Logout) {
    const { id_token_hint, post_logout_redirect_uri, ...extraParams } =
      filteredParams;
    const logoutUrl = new URL('/v2/logout', serverMetadata.issuer);

    // Add query parameters in the expected order
    if (post_logout_redirect_uri) {
      logoutUrl.searchParams.set('returnTo', post_logout_redirect_uri);
    }
    logoutUrl.searchParams.set('client_id', config.clientID);

    // Add any extra params (already filtered for null/undefined by filteredParams)
    Object.entries(extraParams).forEach(([key, value]) => {
      logoutUrl.searchParams.set(key, value);
    });

    return logoutUrl.toString();
  }

  // Use standard RP-Initiated Logout
  return client.buildEndSessionUrl(configuration, filteredParams).toString();
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

exports.buildEndSessionUrl = buildEndSessionUrl;

// Re-export client module for access to functions
exports.client = client;

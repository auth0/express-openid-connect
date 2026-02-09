const client = require('openid-client6');
const crypto = require('crypto');
const url = require('url');
const urlJoin = require('url-join');
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
 * Uses Node.js crypto.createPrivateKey() for simplified key handling.
 * @param {string|Buffer|Object} keyData - PEM string/Buffer or JWK object
 * @param {string} alg - Algorithm (e.g., 'RS256')
 * @returns {Promise<CryptoKey>} CryptoKey for signing
 */
async function importPKCS8AsCryptoKey(keyData, alg) {
  // Map JWT algorithm to Web Crypto algorithm parameters
  const algorithmMap = {
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

  const algorithm = algorithmMap[alg];
  if (!algorithm) {
    throw new Error(`Unsupported algorithm: ${alg}`);
  }

  // Use Node.js crypto.createPrivateKey() to handle both PEM and JWK formats
  // This is much simpler than manual PEM parsing
  const keyObject = crypto.createPrivateKey(
    typeof keyData === 'object' && !Buffer.isBuffer(keyData)
      ? { key: keyData, format: 'jwk' }
      : keyData,
  );

  // Export as PKCS8 DER and import to Web Crypto API CryptoKey
  const pkcs8Der = keyObject.export({ type: 'pkcs8', format: 'der' });

  return crypto.subtle.importKey('pkcs8', pkcs8Der, algorithm, false, ['sign']);
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
      // Use Web Crypto API to import the key as a CryptoKey (required by openid-client6)
      const alg = config.clientAssertionSigningAlg || 'RS256';
      const privateKey = await importPKCS8AsCryptoKey(
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
 * Determines which execute functions to use based on response_type.
 * @param {Object} config - Configuration object
 * @returns {Array} Array of execute functions
 */
function getExecuteFunctions(config) {
  const execute = [];
  const responseType = config.authorizationParams.response_type;

  if (responseType === 'id_token') {
    execute.push(client.useIdTokenResponseType);
  } else if (responseType === 'code id_token') {
    execute.push(client.useCodeIdTokenResponseType);
  }
  // 'code' is the default in v6, no special execute function needed

  return execute;
}

async function get(config) {
  const clientAuth = await getClientAuth(config);
  const execute = getExecuteFunctions(config);

  // Build client metadata with clock tolerance
  const clientMetadata = {
    [client.clockTolerance]: config.clockTolerance,
  };

  // Discover and create configuration
  const issuerUrl = new URL(config.issuerBaseURL);

  // For HTTP issuers, we need to enable allowInsecureRequests
  // Add it to the execute array so it's called during configuration setup
  const isHttp = issuerUrl.protocol === 'http:';
  if (isHttp) {
    execute.push(client.allowInsecureRequests);
  }

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
    const issuerUrl = url.parse(serverMetadata.issuer);
    if (
      config.auth0Logout ||
      (issuerUrl.hostname.match('\\.auth0\\.com$') &&
        config.auth0Logout !== false)
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
    const parsedUrl = url.parse(urlJoin(serverMetadata.issuer, '/v2/logout'));
    parsedUrl.query = {
      ...extraParams,
      returnTo: post_logout_redirect_uri,
      client_id: config.clientID,
    };

    Object.entries(parsedUrl.query).forEach(([key, value]) => {
      if (value === null || value === undefined) {
        delete parsedUrl.query[key];
      }
    });

    return url.format(parsedUrl);
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

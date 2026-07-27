const crypto = require('crypto');
const client = require('openid-client');
const {
  importPKCS8,
  importJWK,
  exportPKCS8,
  SignJWT,
  compactDecrypt,
} = require('jose');
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
 * Import a private key as a CryptoKey for use with openid-client v6.
 * @param {CryptoKey|KeyObject|Object|string|Buffer} keyData
 * @param {string} [alg] - Required for PEM/Buffer/KeyObject/JWK-without-alg
 * @returns {Promise<CryptoKey>}
 */
async function importPrivateKey(keyData, alg) {
  // CryptoKey: algorithm already embedded, pass through
  if (
    typeof keyData?.algorithm?.name === 'string' &&
    Array.isArray(keyData?.usages)
  ) {
    return keyData;
  }

  // Node.js KeyObject: export to PKCS8 PEM then import as CryptoKey
  if (keyData?.asymmetricKeyType) {
    const pem = await exportPKCS8(keyData);
    return importPKCS8(pem, alg);
  }

  // Plain object that is not a Buffer: treat as JWK
  if (typeof keyData === 'object' && !Buffer.isBuffer(keyData)) {
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
  const fetchFn = config.customFetch || fetch;
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

    return fetchFn(fetchUrl, {
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
      const privateKey = await importPrivateKey(
        config.clientAssertionSigningKey,
        config.clientAssertionSigningAlg,
      );
      return client.PrivateKeyJwt(privateKey);
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
  const sortedRespTypes = issuerRespTypes.map(sortSpaceDelimitedString);
  if (!sortedRespTypes.includes(configRespType)) {
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

/**
 * Builds a signed JWT request object for JAR (JWT-Secured Authorization Requests).
 * All authorization parameters are embedded in the JWT payload along with iss and aud claims.
 */
async function buildRequestObject(authParams, config, audience) {
  // `aud` must equal the issuer identifier as advertised in discovery metadata
  // (which may carry a trailing slash), not the configured issuerBaseURL. It is
  // required: falling back to issuerBaseURL is the exact mismatch JAR rejects with
  // invalid_request_object, so callers must pass the discovered issuer.
  if (!audience) {
    throw new TypeError(
      'buildRequestObject requires the discovered issuer as audience',
    );
  }
  const key = await importPrivateKey(
    config.requestObjectSigningKey,
    config.requestObjectSigningAlg,
  );
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    ...authParams,
    client_id: config.clientID,
    iss: config.clientID,
    aud: audience,
    jti: crypto.randomBytes(16).toString('hex'),
    iat: now,
    nbf: now,
    exp: now + 60,
  };
  return new SignJWT(payload)
    .setProtectedHeader({
      alg: config.requestObjectSigningAlg,
      ...(config.requestObjectSigningKeyId && {
        kid: config.requestObjectSigningKeyId,
      }),
    })
    .sign(key);
}

// Key-management ("alg") algorithms accepted for access-token decryption when the
// developer has not pinned one. Deliberately excludes RSA1_5 (PKCS#1 v1.5), which
// is vulnerable to Bleichenbacher padding-oracle attacks. jose enforces this list
// against the JWE header before the key is imported, so a token cannot downgrade
// us to a weak or unexpected algorithm.
const ALLOWED_ACCESS_TOKEN_JWE_ALGS = [
  'RSA-OAEP',
  'RSA-OAEP-256',
  'RSA-OAEP-384',
  'RSA-OAEP-512',
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A192KW',
  'ECDH-ES+A256KW',
];

/**
 * Decrypts a JWE-encrypted access token.
 * Co-located here so it can call the internal importPrivateKey helper directly.
 *
 * A JWE in compact serialization has exactly five dot-separated parts. Anything
 * else (a plaintext 3-part JWT, an opaque token, etc.) is returned unchanged, so
 * that toggling Token Encryption off, a mid-rollout mismatch, or an audience that
 * yields an opaque token does not turn every login and refresh into a hard error.
 *
 * For genuine JWEs the key-management algorithm is taken from the protected header
 * (so the tenant can encrypt with e.g. RSA-OAEP-256 or RSA-OAEP-512 without the
 * client pre-declaring it) but ONLY after jose validates it against an allowlist of
 * strong algorithms. This prevents algorithm-confusion / downgrade attacks (notably
 * RSA1_5). When the developer sets `accessTokenDecryptionAlg`, the allowlist is
 * narrowed to that one value, turning it into a hard pin.
 */
async function decryptAccessToken(token, keyData, alg) {
  // Not a compact JWE (five parts) — pass through untouched.
  if (typeof token !== 'string' || token.split('.').length !== 5) {
    return token;
  }
  const keyManagementAlgorithms = alg ? [alg] : ALLOWED_ACCESS_TOKEN_JWE_ALGS;
  const { plaintext } = await compactDecrypt(
    token,
    (header) => importPrivateKey(keyData, header.alg),
    { keyManagementAlgorithms },
  );
  return Buffer.from(plaintext).toString('utf8');
}

exports.buildRequestObject = buildRequestObject;
exports.decryptAccessToken = decryptAccessToken;

exports.get = (config) => {
  const { discoveryCacheMaxAge: cacheMaxAge } = config;
  const now = Date.now();
  const entry = cache.get(config);
  if (entry && now < entry.expiresAt) {
    return entry.promise;
  }
  const promise = get(config).catch((e) => {
    cache.delete(config);
    throw e;
  });
  cache.set(config, { promise, expiresAt: now + cacheMaxAge });
  return promise;
};

exports.buildEndSessionUrl = buildEndSessionUrl;

// Re-export client module for access to functions
exports.client = client;

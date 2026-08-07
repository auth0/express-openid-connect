const crypto = require('crypto');
const client = require('openid-client');
const { importPKCS8, importJWK, exportPKCS8, SignJWT } = require('jose');
const pkg = require('../package.json');
const debug = require('./debug')('client');
const { MtlsError, MtlsErrorCode } = require('./errors');

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
    case 'tls_client_auth':
      // mTLS (RFC 8705). Enabled via `useMtls`. Covers both CA-signed and
      // self-signed; the distinction is enforced at the authorization server.
      return client.TlsClientAuth();
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
    // For mTLS, token/revocation requests must go to the server's
    // mtls_endpoint_aliases rather than the standard endpoints. In a
    // self-managed-certs custom domain setup only the mTLS alias host is
    // configured (at the edge) to extract the client certificate from the TLS
    // handshake; sending to the standard endpoint yields invalid_client.
    // openid-client routes to the aliases automatically when this is set.
    ...(config.useMtls && { use_mtls_endpoint_aliases: true }),
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

  // Resolve an endpoint the way oauth4webapi does: under mTLS, prefer the
  // mtls_endpoint_aliases entry, otherwise fall back to the standard endpoint.
  // Returns the effective URL string, or undefined if neither is advertised.
  // A non-string value (from a malformed discovery document) is treated as
  // absent so the precondition checks below fail fast rather than passing on a
  // truthy non-URL that oauth4webapi would later reject as INVALID_SERVER_METADATA.
  const resolveEndpoint = (name) => {
    const val =
      (config.useMtls && serverMetadata.mtls_endpoint_aliases?.[name]) ||
      serverMetadata[name];
    return typeof val === 'string' ? val : undefined;
  };

  if (
    config.pushedAuthorizationRequests &&
    !resolveEndpoint('pushed_authorization_request_endpoint')
  ) {
    throw new TypeError(
      'pushed_authorization_request_endpoint must be configured on the issuer to use pushedAuthorizationRequests',
    );
  }

  if (config.useMtls) {
    // Under mTLS every request the SDK sends must go to an mtls_endpoint_aliases
    // host, because only that host is configured (at the TLS edge) to extract
    // the client certificate. oauth4webapi silently falls back to the standard
    // endpoint when an alias is absent, sending the request over a non-mTLS
    // channel that fails with invalid_client. Validate the alias for the token
    // endpoint (always used) and for every optional endpoint this config will
    // reach, so the failure surfaces here rather than mid-flow.
    if (!serverMetadata.mtls_endpoint_aliases?.token_endpoint) {
      throw new MtlsError(
        MtlsErrorCode.MTLS_ENDPOINT_ALIASES_MISSING,
        'useMtls is enabled but the authorization server discovery document does ' +
          'not advertise "mtls_endpoint_aliases.token_endpoint". Ensure mTLS endpoint ' +
          'aliases are enabled on the tenant and requests are routed through your ' +
          'custom domain.',
      );
    }

    if (
      config.pushedAuthorizationRequests &&
      !serverMetadata.mtls_endpoint_aliases
        ?.pushed_authorization_request_endpoint
    ) {
      throw new MtlsError(
        MtlsErrorCode.MTLS_ENDPOINT_ALIASES_MISSING,
        'useMtls is enabled with pushedAuthorizationRequests, but the ' +
          'authorization server does not advertise ' +
          '"mtls_endpoint_aliases.pushed_authorization_request_endpoint". Without ' +
          'it the PAR request would be sent over a non-mTLS channel and fail with ' +
          'invalid_client.',
      );
    }

    // userinfo and revocation are used opportunistically; if the standard
    // endpoint is advertised but its alias is not, requests to them would fall
    // back to a non-mTLS host. Warn rather than throw, since these paths may
    // never be exercised by a given deployment.
    for (const name of ['userinfo_endpoint', 'revocation_endpoint']) {
      if (
        serverMetadata[name] &&
        !serverMetadata.mtls_endpoint_aliases?.[name]
      ) {
        debug(
          'useMtls is enabled but the authorization server does not advertise ' +
            '"mtls_endpoint_aliases.%s"; requests to it would be sent over a ' +
            'non-mTLS channel.',
          name,
        );
      }
    }
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

exports.buildRequestObject = buildRequestObject;

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

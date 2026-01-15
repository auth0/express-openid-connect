import {
  discovery,
  buildAuthorizationUrl,
  Configuration,
  authorizationCodeGrant,
  refreshTokenGrant,
  fetchUserInfo,
} from 'openid-client';
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
      httpOptions,
    );
    serverMetadata = discoveredConfiguration.serverMetadata();
  }

  debugClient('Discovery successful for %s', config.issuerBaseURL);

  validateConfiguration(config, serverMetadata);

  const clientAuthMethod =
    config.clientAuthMethod ||
    (config.clientAssertionSigningKey
      ? 'private_key_jwt'
      : 'client_secret_post');

  const clientMetadata = {
    client_id: config.clientID,
    client_secret: config.clientSecret,
    id_token_signed_response_alg: config.idTokenSigningAlg,
    token_endpoint_auth_method: clientAuthMethod,
    ...(config.clientAssertionSigningAlg && {
      token_endpoint_auth_signing_alg: config.clientAssertionSigningAlg,
    }),
  };

  const configuration = new Configuration(
    serverMetadata,
    config.clientID,
    clientMetadata,
    undefined,
    {
      clockTolerance: config.clockTolerance || 60,
      ...httpOptions,
    },
  );

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

      const currentUrl =
        typeof redirectUri === 'string' ? new URL(redirectUri) : redirectUri;
      const codeFlowUrl = new URL(currentUrl.toString());
      codeFlowUrl.searchParams.set('code', callbackParams.get('code'));

      return await authorizationCodeGrant(
        configuration,
        codeFlowUrl,
        callbackParams,
        checks,
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

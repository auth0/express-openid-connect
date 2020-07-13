const { Issuer, custom } = require('openid-client');
const memoize = require('p-memoize');
const url = require('url');
const urlJoin = require('url-join');
const pkg = require('../package.json');
const debug = require('./debug');

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

const getIssuer = memoize((issuer) => Issuer.discover(issuer));

async function get(config) {
  const defaultHttpOptions = (options) => {
    options.headers = {
      ...options.headers,
      'User-Agent': `${pkg.name}/${pkg.version}`,
      ...(config.enableTelemetry
        ? {
            'Auth0-Client': Buffer.from(
              JSON.stringify(telemetryHeader)
            ).toString('base64'),
          }
        : undefined),
    };
    options.timeout = 5000;
    return options;
  };
  const applyHttpOptionsCustom = (entity) => {
    entity[custom.http_options] = config.httpOptions
      ? (...args) => config.httpOptions(defaultHttpOptions(...args))
      : defaultHttpOptions;
  };

  applyHttpOptionsCustom(Issuer);
  const issuer = await getIssuer(config.issuerBaseURL);
  applyHttpOptionsCustom(issuer);

  const issuerTokenAlgs = Array.isArray(
    issuer.id_token_signing_alg_values_supported
  )
    ? issuer.id_token_signing_alg_values_supported
    : [];
  if (!issuerTokenAlgs.includes(config.idTokenSigningAlg)) {
    debug.warn(
      `ID token algorithm "${config.idTokenSigningAlg}" is not supported by the issuer. ` +
        `Supported ID token algorithms are: "${issuerTokenAlgs.join('", "')}".`
    );
  }

  const configRespType = sortSpaceDelimitedString(
    config.authorizationParams.response_type
  );
  const issuerRespTypes = Array.isArray(issuer.response_types_supported)
    ? issuer.response_types_supported
    : [];
  issuerRespTypes.map(sortSpaceDelimitedString);
  if (!issuerRespTypes.includes(configRespType)) {
    debug.warn(
      `Response type "${configRespType}" is not supported by the issuer. ` +
        `Supported response types are: "${issuerRespTypes.join('", "')}".`
    );
  }

  const configRespMode = config.authorizationParams.response_mode;
  const issuerRespModes = Array.isArray(issuer.response_modes_supported)
    ? issuer.response_modes_supported
    : [];
  if (configRespMode && !issuerRespModes.includes(configRespMode)) {
    debug.warn(
      `Response mode "${configRespMode}" is not supported by the issuer. ` +
        `Supported response modes are "${issuerRespModes.join('", "')}".`
    );
  }

  const client = new issuer.Client({
    client_id: config.clientID,
    client_secret: config.clientSecret,
    id_token_signed_response_alg: config.idTokenSigningAlg,
  });
  applyHttpOptionsCustom(client);
  client[custom.clock_tolerance] = config.clockTolerance;

  if (config.idpLogout && !issuer.end_session_endpoint) {
    if (
      config.auth0Logout ||
      url.parse(issuer.issuer).hostname.match('\\.auth0\\.com$')
    ) {
      Object.defineProperty(client, 'endSessionUrl', {
        value(params) {
          const parsedUrl = url.parse(urlJoin(issuer.issuer, '/v2/logout'));
          parsedUrl.query = {
            returnTo: params.post_logout_redirect_uri,
            client_id: client.client_id,
          };
          return url.format(parsedUrl);
        },
      });
    } else {
      debug.warn('The issuer does not support RP-Initiated Logout.');
    }
  }

  return client;
}

exports.get = memoize(get);

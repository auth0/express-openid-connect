const { Issuer, custom } = require('openid-client');
const memoize = require('p-memoize');
const url = require('url');
const urlJoin = require('url-join');
const pkg = require('../package.json');

const telemetryHeader = {
  name: 'express-oidc',
  version: pkg.version,
  env: {
    node: process.version
  }
};

function spacedStringsToAlphabetical(string) {
  return string.split(' ').sort().join(' ');
}

async function get(config) {

  const issuer = await Issuer.discover(config.issuerBaseURL);

  const issuerTokenAlgs = Array.isArray(issuer.id_token_signing_alg_values_supported) ?
    issuer.id_token_signing_alg_values_supported : [];
  if (!issuerTokenAlgs.includes(config.idTokenAlg)) {
    throw new Error(
      `ID token algorithm "${config.idTokenAlg}" is not supported by the issuer. ` +
      `Supported ID token algorithms are: "${issuerTokenAlgs.join('", "')}". `
    );
  }

  const configRespType = spacedStringsToAlphabetical(config.authorizationParams.response_type);
  const issuerRespTypes = Array.isArray(issuer.response_types_supported) ? issuer.response_types_supported : [];
  issuerRespTypes.map(spacedStringsToAlphabetical);
  if (!issuerRespTypes.includes(configRespType)) {
    throw new Error(
      `Response type "${configRespType}" is not supported by the issuer. ` +
      `Supported response types are: "${issuerRespTypes.join('", "')}". `
    );
  }

  const configRespMode = config.authorizationParams.response_mode;
  const issuerRespModes = Array.isArray(issuer.response_modes_supported) ? issuer.response_modes_supported : [];
  if (configRespMode && ! issuerRespModes.includes(configRespMode)) {
    throw new Error(
      `Response mode "${configRespMode}" is not supported by the issuer. ` +
      `Supported response modes are "${issuerRespModes.join('", "')}". `
    );
  }

  const client = new issuer.Client({
    client_id: config.clientID,
    client_secret: config.clientSecret,
    id_token_signed_response_alg: config.idTokenAlg,
  });

  if (config.idpLogout && !issuer.end_session_endpoint) {
    if (config.auth0Logout || url.parse(issuer.issuer).hostname.match('auth0.com$')) {
      client.endSessionUrl = function(params) {
        const parsedUrl = url.parse(urlJoin(issuer.issuer, '/v2/logout'));
        parsedUrl.query = {
          returnTo: params.post_logout_redirect_uri,
          client_id: client.client_id
        };
        return url.format(parsedUrl);
      };
    } else {
      throw new Error("The issuer doesn't support session management.");
    }
  }

  let httpOptions = config.httpOptions || {};
  httpOptions.headers = Object.assign(
    // Allow configuration to override user agent header.
    {'User-Agent': `${pkg.name}/${pkg.version}`},
    httpOptions.headers || {},
    // Do not allow overriding telemetry, but allow it to be omitted.
    config.enableTelemetry && {'Auth0-Client': Buffer.from(JSON.stringify(telemetryHeader)).toString('base64')}
  );

  custom.setHttpOptionsDefaults(httpOptions);

  client[custom.clock_tolerance] = config.clockTolerance;

  return client;
}

exports.get = memoize(get);

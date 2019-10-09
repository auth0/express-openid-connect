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

custom.setHttpOptionsDefaults({
  headers: {
    'User-Agent': `${pkg.name}/${pkg.version}`,
    'Auth0-Client': Buffer.from(JSON.stringify(telemetryHeader)).toString('base64')
  },
  timeout: 4000
});

async function get(config) {
  const authorizeParams = config.authorizationParams;

  const issuer = await Issuer.discover(config.issuerBaseURL);

  if (Array.isArray(issuer.id_token_signing_alg_values_supported) &&
    !issuer.id_token_signing_alg_values_supported.includes(config.idTokenAlg)) {
    throw new Error(`The issuer doesn't support the ID token algorithm ${config.idTokenAlg}
Supported types:
- ${issuer.id_token_signing_alg_values_supported.sort().join('\n- ')}
`);
  }

  // TODO: Does not respect out-of-order response types; 'id_token code' is not respected if issuer is 'code id_token'
  if (Array.isArray(issuer.response_types_supported) &&
    !issuer.response_types_supported.includes(authorizeParams.response_type)) {
    throw new Error(`The issuer doesn't support the response_type ${authorizeParams.response_type}
Supported types:
- ${issuer.response_types_supported.sort().join('\n- ')}
`);
  }

  const configRespMode = authorizeParams.response_mode;
  const issuerRespModes = Array.isArray(issuer.response_modes_supported) ? issuer.response_modes_supported : [];
  if (configRespMode && ! issuerRespModes.includes(authorizeParams.response_mode)) {
    throw new Error(
      `Response mode ${configRespMode} is not supported by the issuer. ` + 
      `Supported response modes are ${issuerRespModes.sort().join(', ')}. `
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

  client[custom.clock_tolerance] = config.clockTolerance;

  return client;
}

exports.get = memoize(get);

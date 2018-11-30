const { Issuer } = require('openid-client');
const memoize = require('p-memoize');
const url = require('url');
const urlJoin = require('url-join');
const pkg = require('../package.json');

Issuer.defaultHttpOptions = {
  headers: {
    'User-Agent': `${pkg.name}/${pkg.version} (${pkg.homepage})`
  },
  timeout: 4000
};

Issuer.useRequest();

async function get(config) {
  const authorizeParams = config.authorizationParams;

  const issuer = await Issuer.discover(config.issuerBaseURL);

  if (Array.isArray(issuer.response_types_supported) &&
    !issuer.response_types_supported.includes(authorizeParams.response_type)) {
    throw new Error(`The issuer doesn't support the response_type ${authorizeParams.response_type}
Supported types:
- ${issuer.response_types_supported.sort().join('\n- ')}
`);
  }

  if (authorizeParams.response_mode && Array.isArray(issuer.response_modes_supported) &&
    !issuer.response_modes_supported.includes(authorizeParams.response_mode)) {
    throw new Error(`The issuer doesn't support the response_mode ${authorizeParams.response_mode}
Supported response modes:
- ${issuer.response_modes_supported.sort().join('\n- ')}
`);
  }

  const client = new issuer.Client({
    client_id: config.clientID,
    client_secret: config.clientSecret
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

  client.CLOCK_TOLERANCE = config.clockTolerance;

  return client;
}

exports.get = memoize(get);

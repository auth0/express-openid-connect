const { Issuer } = require('openid-client');
const _ = require('lodash');
const pkg = require('../package.json');

Issuer.defaultHttpOptions = {
  headers: {
    'User-Agent': `${pkg.name}/${pkg.version} (${pkg.homepage})`
  },
  timeout: 4000
};

//We need request to be installed as a dependency.
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

  client.CLOCK_TOLERANCE = config.clockTolerance;

  return client;
}

exports.get = _.memoize(get);

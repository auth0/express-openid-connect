const { Issuer } = require('openid-client');
const _ = require('lodash');

async function get(params) {
  const authorizeParams = params.authorizationParams;

  const issuer = await Issuer.discover(params.issuerBaseURL);

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

  return new issuer.Client({
    client_id: params.clientID,
    client_secret: params.clientSecret
  });
}

exports.get = _.memoize(get);

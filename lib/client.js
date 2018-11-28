const { Issuer } = require('openid-client');
const memoize = require('p-memoize');
const urlJoin = require('url-join');
const url = require('url');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

const pkg = require('../package.json');

Issuer.defaultHttpOptions = {
  headers: {
    'User-Agent': `${pkg.name}/${pkg.version} (${pkg.homepage})`
  },
  timeout: 4000
};

//We need request to be installed as a dependency.
Issuer.useRequest();

async function testAuth0LogoutUrl(logoutUrl) {
  try {
    return (await request.get(logoutUrl)).statusCode === 200;
  } catch(err) {
    return false;
  }
}
async function appendAuth0LogoutLogic(client) {
  if (client.issuer.end_session_endpoint) { return; }

  const auth0LogoutUrl = urlJoin(client.issuer.issuer, '/v2/logout');
  const isAuth0Issuer = await testAuth0LogoutUrl(auth0LogoutUrl);
  if (!isAuth0Issuer) { return; }

  client.endSessionUrl = function(params) {
    const parsed = url.parse(auth0LogoutUrl);
    parsed.query = {
      returnTo: params.post_logout_redirect_uri,
      client_id: client.client_id,
      federated: params.federated || undefined
    };
    return url.format(parsed);
  };
}

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

  await appendAuth0LogoutLogic(client);

  client.CLOCK_TOLERANCE = config.clockTolerance;

  return client;
}

exports.get = memoize(get);

const assert = require('chai').assert;
const expressOpenid = require('..');
const server = require('./fixture/server');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

describe('with an invalid response_mode', function() {

  const router = expressOpenid.auth({
    appSessionSecret: '__test_session_secret__',
    clientID: '__test_client_id__',
    baseURL: 'https://example.org',
    issuerBaseURL: 'https://test.auth0.com',
    authorizationParams: {
      response_mode: '__invalid_response_mode__',
      response_type: 'id_token'
    }
  });

  let baseUrl;
  before(async function() {
    baseUrl = await server.create(router);
  });

  it('should return an error', async function() {
    const res = await request.get({ json: true, baseUrl, uri: '/login'});
    assert.equal(res.statusCode, 500);
    assert.include(res.body.err.message, 'Response mode "__invalid_response_mode__" is not supported by the issuer.');
  });
});

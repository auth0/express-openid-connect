const assert = require('chai').assert;
const expressOpenid = require('..');
const server = require('./fixture/server');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

describe('with an invalid response_mode', function() {

  const router = expressOpenid.auth({
    clientID: '123',
    baseURL: 'https://myapp.com',
    issuerBaseURL: 'https://flosser.auth0.com',
    authorizationParams: {
      response_mode: 'ffff',
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
    assert.include(res.body.err.message, 'The issuer doesn\'t support the response_mode ffff');
  });
});

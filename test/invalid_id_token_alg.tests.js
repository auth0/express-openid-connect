const assert = require('chai').assert;
const expressOpenid = require('..');
const server = require('./fixture/server');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

describe('with an invalid id token alg', function() {

  const router = expressOpenid.auth({
    clientID: '123',
    baseURL: 'https://myapp.com',
    issuerBaseURL: 'https://flosser.auth0.com',
    idTokenAlg: '__invalid_alg__'
  });

  let baseUrl;
  before(async function() {
    baseUrl = await server.create(router);
  });

  it('should return an error', async function() {
    const res = await request.get({ json: true, baseUrl, uri: '/login'});
    assert.equal(res.statusCode, 500);
    assert.include(res.body.err.message, 'ID token algorithm "__invalid_alg__" is not supported by the issuer.');
  });
});

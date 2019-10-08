const { assert } = require('chai');
const expressOpenid = require('..');

describe('invalid parameters', function() {
  it('should fail when the issuerBaseURL is invalid', function() {
    assert.throws(() => {
      expressOpenid.auth({
        baseURL: 'https://example.org',
        issuerBaseURL: '__invalid_url__',
        clientID: '__test_client_id__'
      });
    }, '"issuerBaseURL" must be a valid uri');
  });

  it('should fail when the baseURL is invalid', function() {
    assert.throws(() => {
      expressOpenid.auth({
        baseURL: '__invalid_url__',
        issuerBaseURL: 'https://test.auth0.com',
        clientID: '__test_client_id__'
      });
    }, '"baseURL" must be a valid uri');
  });

  it('should fail when the clientID is not provided', function() {
    assert.throws(() => {
      expressOpenid.auth({
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://test.auth0.com',
      });
    }, '"clientID" is required');
  });

  it('should fail when the baseURL is not provided', function() {
    assert.throws(() => {
      expressOpenid.auth({
        issuerBaseURL: 'https://test.auth0.com',
        clientID: '__test_client_id__',
      });
    }, '"baseURL" is required');
  });

  it('should fail when client secret is not provided and using the response type code in mode query', function() {
    assert.throws(() => {
      expressOpenid.auth({
        issuerBaseURL: 'https://test.auth0.com',
        baseURL: 'https://example.org',
        clientID: '__test_client_id__',
        authorizationParams: {
          response_type: 'code id_token'
        }
      });
    }, '"clientSecret" is required for response_type code');
  });

  it('should fail when client secret is not provided and using an HS256 ID token algorithm', function() {
    assert.throws(() => {
      expressOpenid.auth({
        issuerBaseURL: 'http://foobar.auth0.com',
        baseURL: 'http://foobar.com',
        clientID: 'asdas',
        idTokenAlg: 'HS256'
      });
    }, '"clientSecret" is required for ID tokens with HS algorithms');
  });
});

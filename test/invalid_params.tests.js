const { assert } = require('chai');
const expressOpenid = require('..');

describe('invalid parameters', function() {
  it('should fail when the issuerBaseURL is invalid', function() {
    assert.throws(() => {
      expressOpenid.auth({
        baseURL: 'http://localhost',
        issuerBaseURL: '123 r423.json xxx',
        clientID: '123ewasda'
      });
    }, '"issuerBaseURL" must be a valid uri');
  });

  it('should fail when the baseURL is invalid', function() {
    assert.throws(() => {
      expressOpenid.auth({
        baseURL: 'xasxasa sads',
        issuerBaseURL: 'http://foobar.com',
        clientID: '123ewasda'
      });
    }, '"baseURL" must be a valid uri');
  });

  it('should fail when the clientID is not provided', function() {
    assert.throws(() => {
      expressOpenid.auth({
        baseURL: 'http://foobar.com',
        issuerBaseURL: 'http://foobar.com',
      });
    }, '"clientID" is required');
  });

  it('should fail when the baseURL is not provided', function() {
    assert.throws(() => {
      expressOpenid.auth({
        issuerBaseURL: 'http://foobar.com',
        clientID: 'asdas',
      });
    }, '"baseURL" is required');
  });

  it('should fail when client secret is not provided and using the response type code in mode query', function() {
    assert.throws(() => {
      expressOpenid.auth({
        issuerBaseURL: 'http://foobar.auth0.com',
        baseURL: 'http://foobar.com',
        clientID: 'asdas',
        authorizationParams: {
          response_type: 'code id_token'
        }
      });
    }, '"clientSecret" is required for response_type code');
  });
});

const { assert } = require('chai');
const expressOpenid = require('..');
const ResponseMode = expressOpenid.ResponseMode;

describe('invalid parameters', function() {
  it('should fail when the issuer_base_url is invalid', function() {
    assert.throws(() => {
      expressOpenid.routes({
        base_url: 'http://localhost',
        issuer_base_url: '123 r423.json xxx',
        client_id: '123ewasda'
      });
    }, '"issuer_base_url" must be a valid uri');
  });

  it('should fail when the base_url is invalid', function() {
    assert.throws(() => {
      expressOpenid.routes({
        base_url: 'xasxasa sads',
        issuer_base_url: 'http://foobar.com',
        client_id: '123ewasda'
      });
    }, '"base_url" must be a valid uri');
  });

  it('should fail when the client_id is not provided', function() {
    assert.throws(() => {
      expressOpenid.routes({
        base_url: 'http://foobar.com',
        issuer_base_url: 'http://foobar.com',
      });
    }, '"client_id" is required');
  });

  it('should fail when the base_url is not provided', function() {
    assert.throws(() => {
      expressOpenid.routes({
        issuer_base_url: 'http://foobar.com',
        client_id: 'asdas'
      });
    }, '"base_url" is required');
  });

  it('should fail when client secret is not provided and using the response type code in mode query', function() {
    assert.throws(() => {
      expressOpenid.routes({
        issuer_base_url: 'http://foobar.auth0.com',
        base_url: 'http://foobar.com',
        client_id: 'asdas',
        authorizationParams: {
          response_type: 'code id_token'
        }
      });
    }, '"client_secret" is required for response_type code');
  });
});

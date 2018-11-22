const { assert } = require('chai');
const paramsValidator = require('../lib/paramsValidator');

describe('params handling', function() {
  describe('when authorizationParams is not specified', function() {
    const params = paramsValidator.validate({
      clientID: '123',
      issuerBaseURL: 'https://flosser.auth0.com',
      baseURL: 'https://jjj.com',
    });

    it('should default to response_type=id_token', function() {
      assert.equal(params.authorizationParams.response_type, 'id_token');
    });

    it('should default to response_mode=form_post', function() {
      assert.equal(params.authorizationParams.response_mode, 'form_post');
    });

    it('should default to scope=openid profile email ', function() {
      assert.equal(params.authorizationParams.scope, 'openid profile email');
    });
  });

  describe('when authorizationParams is response_type=x', function() {
    const params = paramsValidator.validate({
      clientID: '123',
      clientSecret: '123',
      issuerBaseURL: 'https://flosser.auth0.com',
      baseURL: 'https://jjj.com',
      authorizationParams: {
        response_type: 'code'
      }
    });

    it('should default to response_type=id_token', function() {
      assert.equal(params.authorizationParams.response_type, 'code');
    });

    it('should default to response_mode=form_post', function() {
      assert.equal(params.authorizationParams.response_mode, undefined);
    });

    it('should default to scope=openid profile email ', function() {
      assert.equal(params.authorizationParams.scope, 'openid profile email');
    });
  });
});

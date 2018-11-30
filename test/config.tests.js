const { assert } = require('chai');
const { get: getConfig } = require('../lib/config');

describe('config', function() {
  describe('simple case', function() {
    const config = getConfig({
      clientID: '123',
      issuerBaseURL: 'https://flosser.auth0.com',
      baseURL: 'https://jjj.com',
    });

    it('should default to response_type=id_token', function() {
      assert.equal(config.authorizationParams.response_type, 'id_token');
    });

    it('should default to response_mode=form_post', function() {
      assert.equal(config.authorizationParams.response_mode, 'form_post');
    });

    it('should default to scope=openid profile email ', function() {
      assert.equal(config.authorizationParams.scope, 'openid profile email');
    });

    it('should default to required true ', function() {
      assert.ok(config.required);
    });
  });

  describe('when authorizationParams is response_type=x', function() {
    const config = getConfig({
      clientID: '123',
      clientSecret: '123',
      issuerBaseURL: 'https://flosser.auth0.com',
      baseURL: 'https://jjj.com',
      authorizationParams: {
        response_type: 'code'
      }
    });

    it('should default to response_type=id_token', function() {
      assert.equal(config.authorizationParams.response_type, 'code');
    });

    it('should default to response_mode=form_post', function() {
      assert.equal(config.authorizationParams.response_mode, undefined);
    });

    it('should default to scope=openid profile email ', function() {
      assert.equal(config.authorizationParams.scope, 'openid profile email');
    });
  });

  describe('with auth0Logout', function() {
    const config = getConfig({
      clientID: '123',
      issuerBaseURL: 'https://flosser.auth0.com',
      baseURL: 'https://jjj.com',
      auth0Logout: true
    });

    it('should set idpLogout to true', function() {
      assert.equal(config.auth0Logout, true);
      assert.equal(config.idpLogout, true);
    });
  });

  describe('without auth0Logout nor idpLogout', function() {
    const config = getConfig({
      clientID: '123',
      issuerBaseURL: 'https://flosser.auth0.com',
      baseURL: 'https://jjj.com',
    });

    it('should set both to false', function() {
      assert.equal(config.auth0Logout, false);
      assert.equal(config.idpLogout, false);
    });
  });

  describe('with idpLogout', function() {
    const config = getConfig({
      clientID: '123',
      issuerBaseURL: 'https://flosser.auth0.com',
      baseURL: 'https://jjj.com',
      idpLogout: true
    });

    it('should set both to false', function() {
      assert.equal(config.auth0Logout, false);
      assert.equal(config.idpLogout, true);
    });
  });

});

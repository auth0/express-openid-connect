const { assert } = require('chai');
const { get: getConfig } = require('../lib/config');

describe('config', function() {
  describe('simple case', function() {
    const config = getConfig({
      appSessionSecret: false,
      clientID: '__test_client_id__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org',
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
      appSessionSecret: '__test_session_secret__',
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org',
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
      appSessionSecret: '__test_session_secret__',
      clientID: '__test_client_id__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org',
      auth0Logout: true
    });

    it('should set idpLogout to true', function() {
      assert.equal(config.auth0Logout, true);
      assert.equal(config.idpLogout, true);
    });
  });

  describe('without auth0Logout nor idpLogout', function() {
    const config = getConfig({
      appSessionSecret: '__test_session_secret__',
      clientID: '__test_client_id__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org',
    });

    it('should set both to false', function() {
      assert.equal(config.auth0Logout, false);
      assert.equal(config.idpLogout, false);
    });
  });

  describe('with idpLogout', function() {
    const config = getConfig({
      appSessionSecret: '__test_session_secret__',
      clientID: '__test_client_id__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org',
      idpLogout: true
    });

    it('should set both to false', function() {
      assert.equal(config.auth0Logout, false);
      assert.equal(config.idpLogout, true);
    });
  });

  describe('default auth paths', function() {
    const config = getConfig({
      appSessionSecret: '__test_session_secret__',
      clientID: '__test_client_id__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org',
    });

    it('should set the default callback path', function() {
      assert.equal(config.redirectUriPath, '/callback');
    });

    it('should set the default login path', function() {
      assert.equal(config.loginPath, '/login');
    });

    it('should set the default logout path', function() {
      assert.equal(config.logoutPath, '/logout');
    });
  });

  describe('custom auth paths', function() {
    const config = getConfig({
      appSessionSecret: '__test_session_secret__',
      clientID: '__test_client_id__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org',
      redirectUriPath: '/custom-callback',
      loginPath: '/custom-login',
      logoutPath: '/custom-logout',
    });

    it('should accept the custom callback path', function() {
      assert.equal(config.redirectUriPath, '/custom-callback');
    });

    it('should accept the login path', function() {
      assert.equal(config.loginPath, '/custom-login');
    });

    it('should accept the logout path', function() {
      assert.equal(config.logoutPath, '/custom-logout');
    });
  });

  describe('app session default configuration', function() {
    const config = getConfig({
      appSessionSecret: '__test_session_secret__',
      clientID: '__test_client_id__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org'
    });

    it('should set the app session secret', function() {
      assert.equal(config.appSessionSecret, '__test_session_secret__');
    });

    it('should set the session length to 7 days by default', function() {
      assert.equal(config.appSessionDuration, 604800);
    });

    it('should set the session name to "identity" by default', function() {
      assert.equal(config.appSessionName, 'identity');
    });

    it('should set the session cookie attributes to correct defaults', function() {
      assert.notExists(config.appSessionCookie.domain);
      assert.notExists(config.appSessionCookie.path);
      assert.notExists(config.appSessionCookie.secure);
      assert.notExists(config.appSessionCookie.sameSite);
      assert.equal(config.appSessionCookie.httpOnly, true);
    });
  });

  describe('app session cookie configuration', function() {
    const config = getConfig({
      appSessionSecret: [ '__test_session_secret_1__', '__test_session_secret_2__' ],
      appSessionName: '__test_custom_session_name__',
      appSessionDuration: 1234567890,
      appSessionCookie: {
        domain: '__test_custom_domain__',
        path: '__test_custom_path__',
        httpOnly: false,
        secure: true,
        sameSite: 'Lax',
      },
      clientID: '__test_client_id__',
      issuerBaseURL: 'https://test.auth0.com',
      baseURL: 'https://example.org'
    });

    it('should set an array of secrets', function() {
      assert.equal(config.appSessionSecret.length, 2);
      assert.equal(config.appSessionSecret[0], '__test_session_secret_1__');
      assert.equal(config.appSessionSecret[1], '__test_session_secret_2__');
    });

    it('should set the custom session values', function() {
      assert.equal(config.appSessionDuration, 1234567890);
      assert.equal(config.appSessionName, '__test_custom_session_name__');
    });

    it('should set the session cookie attributes to custom values', function() {
      assert.equal(config.appSessionCookie.domain, '__test_custom_domain__');
      assert.equal(config.appSessionCookie.path, '__test_custom_path__');
      assert.equal(config.appSessionCookie.httpOnly, false);
      assert.equal(config.appSessionCookie.secure, true);
      assert.equal(config.appSessionCookie.sameSite, 'Lax');
    });
  });

});

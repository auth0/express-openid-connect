const { assert } = require('chai');
const sinon = require('sinon');
const { get: getConfig } = require('../lib/config');

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org'
};

describe('config', function () {

  afterEach(() => sinon.restore());

  it('should validate default config', function() {
    const config = getConfig(defaultConfig);
    assert.deepInclude(config, {
      authorizationParams: {
        response_type: 'id_token',
        response_mode: 'form_post',
        scope: 'openid profile email'
      },
      authRequired: true
    });
  });

  it('should validate default config with environment variables', function() {
    sinon.stub(process, 'env').value({
      ...process.env,
      ISSUER_BASE_URL: defaultConfig.issuerBaseURL,
      CLIENT_ID: defaultConfig.clientID,
      SECRET: defaultConfig.secret,
      BASE_URL: defaultConfig.baseURL,
    });
    const config = getConfig();
    assert.deepInclude(config, {
      authorizationParams: {
        response_type: 'id_token',
        response_mode: 'form_post',
        scope: 'openid profile email'
      },
      authRequired: true
    });
  });

  it('should validate default config for response_type=code', function() {
    const config = getConfig({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code'
      }
    });
    assert.deepInclude(config, {
      authorizationParams: {
        response_type: 'code',
        scope: 'openid profile email'
      },
      authRequired: true
    });
  });

  it('should set idpLogout to true when auth0Logout is true', function() {
    const config = getConfig({
      ...defaultConfig,
      auth0Logout: true
    });
    assert.include(config, {
      auth0Logout: true,
      idpLogout: true
    });
  });

  it('auth0Logout and idpLogout should default to false', function() {
    const config = getConfig(defaultConfig);
    assert.include(config, {
      auth0Logout: false,
      idpLogout: false
    });
  });

  it('should not set auth0Logout to true when idpLogout is true', function () {
    const config = getConfig({
      ...defaultConfig,
      idpLogout: true
    });
    assert.include(config, {
      auth0Logout: false,
      idpLogout: true
    });
  });

  it('should set default route paths', function () {
    const config = getConfig(defaultConfig);
    assert.include(config.routes, {
      callback: '/callback',
      login: '/login',
      logout: '/logout',
    });
  });

  it('should set custom route paths', function () {
    const config = getConfig({
      ...defaultConfig,
      routes: {
        callback: '/custom-callback',
        login: '/custom-login',
        logout: '/custom-logout'
      }
    });
    assert.include(config.routes, {
      callback: '/custom-callback',
      login: '/custom-login',
      logout: '/custom-logout',
    });
  });

  it('should set default app session configuration', function () {
    const config = getConfig(defaultConfig);
    assert.deepInclude(config.session, {
      rollingDuration: 86400,
      name: 'appSession',
      cookie: {
        sameSite: 'Lax',
        httpOnly: true,
        transient: false,
      }
    });
  });

  it('should set custom cookie configuration', function () {
    const config = getConfig({
      ...defaultConfig,
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      session: {
        name: '__test_custom_session_name__',
        rollingDuration: 1234567890,
        cookie: {
          domain: '__test_custom_domain__',
          transient: true,
          httpOnly: false,
          secure: true,
          sameSite: 'Strict'
        }
      }
    });
    assert.deepInclude(config, {
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      session: {
        name: '__test_custom_session_name__',
        rollingDuration: 1234567890,
        absoluteDuration: 604800,
        rolling: true,
        cookie: {
          domain: '__test_custom_domain__',
          transient: true,
          httpOnly: false,
          secure: true,
          sameSite: 'Strict',
        }
      }
    });
  });
});

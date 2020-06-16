const { assert } = require('chai');
const { get: getConfig } = require('../lib/config');

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org'
};

describe('config', function () {
  describe('simple case', function () {
    const config = getConfig(defaultConfig);

    it('should default to response_type=id_token', function () {
      assert.equal(config.authorizationParams.response_type, 'id_token');
    });

    it('should default to response_mode=form_post', function () {
      assert.equal(config.authorizationParams.response_mode, 'form_post');
    });

    it('should default to scope=openid profile email', function () {
      assert.equal(config.authorizationParams.scope, 'openid profile email');
    });

    it('should default to authRequired true', function () {
      assert.ok(config.authRequired);
    });
  });

  describe('simple case with environment variables', function () {
    let config;
    let env;

    beforeEach(function () {
      env = process.env;
      process.env = Object.assign({}, process.env, {
        ISSUER_BASE_URL: defaultConfig.issuerBaseURL,
        CLIENT_ID: defaultConfig.clientID,
        SECRET: defaultConfig.secret,
        BASE_URL: defaultConfig.baseURL
      });
      config = getConfig();
    });

    afterEach(function () {
      process.env = env;
    });

    it('should default to response_type=id_token', function () {
      assert.equal(config.authorizationParams.response_type, 'id_token');
    });

    it('should default to response_mode=form_post', function () {
      assert.equal(config.authorizationParams.response_mode, 'form_post');
    });

    it('should default to scope=openid profile email', function () {
      assert.equal(config.authorizationParams.scope, 'openid profile email');
    });

    it('should default to authRequired true', function () {
      assert.ok(config.authRequired);
    });
  });

  describe('when authorizationParams is response_type=code', function () {
    const customConfig = Object.assign({}, defaultConfig, {
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code'
      }
    });
    const config = getConfig(customConfig);

    it('should set new response_type', function () {
      assert.equal(config.authorizationParams.response_type, 'code');
    });

    it('should allow undefined response_mode', function () {
      assert.equal(config.authorizationParams.response_mode, undefined);
    });

    it('should keep default scope', function () {
      assert.equal(config.authorizationParams.scope, 'openid profile email');
    });
  });

  describe('with auth0Logout', function () {
    const config = getConfig(Object.assign({}, defaultConfig, { auth0Logout: true }));

    it('should set idpLogout to true', function () {
      assert.equal(config.auth0Logout, true);
      assert.equal(config.idpLogout, true);
    });
  });

  describe('without auth0Logout nor idpLogout', function () {
    const config = getConfig(defaultConfig);

    it('should set both to false', function () {
      assert.equal(config.auth0Logout, false);
      assert.equal(config.idpLogout, false);
    });
  });

  describe('with idpLogout', function () {
    const config = getConfig(Object.assign({}, defaultConfig, { idpLogout: true }));

    it('should set both to false', function () {
      assert.equal(config.auth0Logout, false);
      assert.equal(config.idpLogout, true);
    });
  });

  describe('default auth paths', function () {
    const config = getConfig(defaultConfig);

    it('should set the default callback path', function () {
      assert.equal(config.routes.callback, '/callback');
    });

    it('should set the default login path', function () {
      assert.equal(config.routes.login, '/login');
    });

    it('should set the default logout path', function () {
      assert.equal(config.routes.logout, '/logout');
    });
  });

  describe('custom auth paths', function () {
    const customConfig = Object.assign({}, defaultConfig, {
      routes: {
        callback: '/custom-callback',
        login: '/custom-login',
        logout: '/custom-logout'
      }
    });
    const config = getConfig(customConfig);

    it('should accept the custom callback path', function () {
      assert.equal(config.routes.callback, '/custom-callback');
    });

    it('should accept the login path', function () {
      assert.equal(config.routes.login, '/custom-login');
    });

    it('should accept the logout path', function () {
      assert.equal(config.routes.logout, '/custom-logout');
    });
  });

  describe('app session default configuration', function () {
    const config = getConfig(defaultConfig);

    it('should set the app session secret', function () {
      assert.equal(config.secret, '__test_session_secret__');
    });

    it('should set the session length to 1 day by default', function () {
      assert.equal(config.session.rollingDuration, 86400);
    });

    it('should set the session name to "session" by default', function () {
      assert.equal(config.session.name, 'appSession');
    });

    it('should set the session cookie attributes to correct defaults', function () {
      assert.notExists(config.session.cookie.domain);
      assert.notExists(config.session.cookie.secure);
      assert.equal(config.session.cookie.sameSite, 'Lax');
      assert.equal(config.session.cookie.httpOnly, true);
    });
  });

  describe('app session cookie configuration', function () {
    const customConfig = Object.assign({}, defaultConfig, {
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

    it('should set an array of secrets', function () {
      const config = getConfig(customConfig);
      assert.equal(config.secret.length, 2);
      assert.equal(config.secret[0], '__test_session_secret_1__');
      assert.equal(config.secret[1], '__test_session_secret_2__');
    });

    it('should set the custom session values', function () {
      const config = getConfig(customConfig);
      assert.equal(config.session.rollingDuration, 1234567890);
      assert.equal(config.session.name, '__test_custom_session_name__');
    });

    it('should set the session cookie attributes to custom values', function () {
      const config = getConfig(customConfig);
      assert.equal(config.session.cookie.domain, '__test_custom_domain__');
      assert.equal(config.session.cookie.transient, true);
      assert.equal(config.session.cookie.httpOnly, false);
      assert.equal(config.session.cookie.secure, true);
      assert.equal(config.session.cookie.sameSite, 'Strict');
    });
  });
});

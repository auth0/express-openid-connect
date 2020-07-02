const { assert } = require('chai');
const sinon = require('sinon');
const { get: getConfig } = require('../lib/config');

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org'
};

const validateAuthorizationParams = (authorizationParams) => getConfig({ ...defaultConfig, authorizationParams });

describe('get config', () => {

  afterEach(() => sinon.restore());

  it('should get config for default config', () => {
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

  it('should get config for default config with environment variables', () => {
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

  it('should get config for response_type=code', () => {
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
        response_mode: 'query',
        scope: 'openid profile email'
      },
      authRequired: true
    });
  });

  it('should set idpLogout to true when auth0Logout is true', () => {
    const config = getConfig({
      ...defaultConfig,
      auth0Logout: true
    });
    assert.include(config, {
      auth0Logout: true,
      idpLogout: true
    });
  });

  it('auth0Logout and idpLogout should default to false', () => {
    const config = getConfig(defaultConfig);
    assert.include(config, {
      auth0Logout: false,
      idpLogout: false
    });
  });

  it('should not set auth0Logout to true when idpLogout is true', () => {
    const config = getConfig({
      ...defaultConfig,
      idpLogout: true
    });
    assert.include(config, {
      auth0Logout: false,
      idpLogout: true
    });
  });

  it('should set default route paths', () => {
    const config = getConfig(defaultConfig);
    assert.include(config.routes, {
      callback: '/callback',
      login: '/login',
      logout: '/logout',
    });
  });

  it('should set custom route paths', () => {
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

  it('should set default app session configuration', () => {
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

  it('should set custom cookie configuration', () => {
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

  it('shouldn\'t allow a secret of less than 8 chars', () => {
    assert.throws(() => getConfig({ ...defaultConfig, secret: 'short' }), TypeError, '"secret" does not match any of the allowed types');
    assert.throws(() => getConfig({ ...defaultConfig, secret: ['short', 'too'] }), TypeError, '"secret[0]" does not match any of the allowed types');
    assert.throws(() => getConfig({ ...defaultConfig, secret: Buffer.from('short') }), TypeError, '"secret" must be at least 8 bytes');
  });

  it('shouldn\'t allow code flow without clientSecret', () => {
    const config = {
      ...defaultConfig,
      authorizationParams: {
        response_type: 'code'
      }
    };
    assert.throws(() => getConfig(config), TypeError, '"clientSecret" is required for a response_type that includes code');
  });

  it('shouldn\'t allow hybrid flow without clientSecret', () => {
    const config = {
      ...defaultConfig,
      authorizationParams: {
        response_type: 'code id_token'
      }
    };
    assert.throws(() => getConfig(config), TypeError, '"clientSecret" is required for a response_type that includes code');
  });

  it('should require clientSecret for ID tokens with HS algorithms', () => {
    const config = {
      ...defaultConfig,
      idTokenSigningAlg: 'HS256',
      authorizationParams: {
        response_type: 'id_token'
      }
    };
    assert.throws(() => getConfig(config), TypeError, '"clientSecret" is required for ID tokens with HS algorithms');
  });

  it('should require clientSecret for ID tokens in hybrid flow with HS algorithms', () => {
    const config = {
      ...defaultConfig,
      idTokenSigningAlg: 'HS256',
      authorizationParams: {
        response_type: 'code id_token'
      }
    };
    assert.throws(() => getConfig(config), TypeError, '"clientSecret" is required for ID tokens with HS algorithms');
  });

  it('should allow empty auth params', () => {
    assert.doesNotThrow(validateAuthorizationParams);
    assert.doesNotThrow(() => validateAuthorizationParams({}));
  });

  it('should not allow empty scope', () => {
    assert.throws(() => validateAuthorizationParams({ scope: null }), TypeError, '"authorizationParams.scope" must be a string');
    assert.throws(() => validateAuthorizationParams({ scope: '' }), TypeError, '"authorizationParams.scope" is not allowed to be empty');
    // assert.throws(() => validateAuthorizationParams({ scope: undefined }), TypeError, '"authorizationParams.scope" is not allowed to be set to undefined');
  });

  it('should not allow scope without openid', () => {
    assert.throws(() => validateAuthorizationParams({ scope: 'profile email' }), TypeError, '"authorizationParams.scope" with value "profile email" fails to match the contains openid pattern');
  });

  it('should allow scope with openid', () => {
    assert.doesNotThrow(() => validateAuthorizationParams({ scope: 'openid read:users' }));
    assert.doesNotThrow(() => validateAuthorizationParams({ scope: 'read:users openid' }));
    assert.doesNotThrow(() => validateAuthorizationParams({ scope: 'read:users openid profile email' }));
  });

  it('should not allow empty response_type', () => {
    assert.throws(() => validateAuthorizationParams({ response_type: null }), TypeError, '"authorizationParams.response_type" must be one of [id_token, code id_token, code]');
    assert.throws(() => validateAuthorizationParams({ response_type: '' }), TypeError, '"authorizationParams.response_type" must be one of [id_token, code id_token, code]');
    // assert.throws(() => validateAuthorizationParams({ response_type: undefined }), TypeError, '"response_type" is not allowed to be set to undefined');
  });

  it('should not allow invalid response_types', () => {
    assert.throws(() => validateAuthorizationParams({ response_type: 'foo' }), TypeError, '"authorizationParams.response_type" must be one of [id_token, code id_token, code]');
    assert.throws(() => validateAuthorizationParams({ response_type: 'foo id_token' }), TypeError, '"authorizationParams.response_type" must be one of [id_token, code id_token, code]');
    assert.throws(() => validateAuthorizationParams({ response_type: 'id_token code' }), TypeError, '"authorizationParams.response_type" must be one of [id_token, code id_token, code]');
  });

  it('should allow valid response_types', () => {
    const config = (authorizationParams) => ({
      ...defaultConfig,
      clientSecret: 'foo',
      authorizationParams
    });
    assert.doesNotThrow(() => validateAuthorizationParams({ response_type: 'id_token' }));
    assert.doesNotThrow(() => config({ response_type: 'code id_token' }));
    assert.doesNotThrow(() => config({ response_type: 'code' }));
  });

  it('should not allow empty response_mode', () => {
    assert.throws(() => validateAuthorizationParams({ response_mode: null }), TypeError, '"authorizationParams.response_mode" must be [form_post]');
    assert.throws(() => validateAuthorizationParams({ response_mode: '' }), TypeError, '"authorizationParams.response_mode" must be [form_post]');
    assert.throws(() => validateAuthorizationParams({ response_type: 'code', response_mode: '' }), TypeError, '"authorizationParams.response_mode" must be one of [query, form_post]');
    // assert.throws(() => validateAuthorizationParams({ response_mode: undefined }), TypeError, '"authorizationParams.response_mode" is not allowed to be set to undefined');
  });

  it('should not allow response_type id_token and response_mode query', () => {
    assert.throws(() => validateAuthorizationParams({ response_type: 'id_token', response_mode: 'query' }), TypeError, '"authorizationParams.response_mode" must be [form_post]');
    assert.throws(() => validateAuthorizationParams({ response_type: 'code id_token', response_mode: 'query' }), TypeError, '"authorizationParams.response_mode" must be [form_post]');
  });

  it('should allow valid response_type response_mode combinations', () => {
    const config = (authorizationParams) => ({
      ...defaultConfig,
      clientSecret: 'foo',
      authorizationParams
    });
    assert.doesNotThrow(() => config({ response_type: 'code', response_mode: 'query' }));
    assert.doesNotThrow(() => config({ response_type: 'code', response_mode: 'form_post' }));
    assert.doesNotThrow(() => validateAuthorizationParams({ response_type: 'id_token', response_mode: 'form_post' }));
    assert.doesNotThrow(() => config({ response_type: 'code id_token', response_mode: 'form_post' }));
  });

});

const { assert } = require('chai');
const sinon = require('sinon');
const { get: getConfig } = require('../lib/config');

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org',
};

const validateAuthorizationParams = (authorizationParams) =>
  getConfig({ ...defaultConfig, authorizationParams });

describe('get config', () => {
  afterEach(() => sinon.restore());

  it('should get config for default config', () => {
    const config = getConfig(defaultConfig);
    assert.deepInclude(config, {
      authorizationParams: {
        response_type: 'id_token',
        response_mode: 'form_post',
        scope: 'openid profile email',
      },
      authRequired: true,
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
        scope: 'openid profile email',
      },
      authRequired: true,
    });
  });

  it('should get config for response_type=code', () => {
    const config = getConfig({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code',
      },
    });
    assert.deepInclude(config, {
      authorizationParams: {
        response_type: 'code',
        scope: 'openid profile email',
      },
      authRequired: true,
    });
  });

  it('should require a fully qualified URL for issuer', () => {
    const config = {
      ...defaultConfig,
      issuerBaseURL: 'www.example.com',
    };
    assert.throws(
      () => getConfig(config),
      TypeError,
      '"issuerBaseURL" must be a valid uri'
    );
  });

  it('should set idpLogout to true when auth0Logout is true', () => {
    const config = getConfig({
      ...defaultConfig,
      auth0Logout: true,
    });
    assert.include(config, {
      auth0Logout: true,
      idpLogout: true,
    });
  });

  it('auth0Logout and idpLogout should default to false', () => {
    const config = getConfig(defaultConfig);
    assert.include(config, {
      auth0Logout: false,
      idpLogout: false,
    });
  });

  it('should not set auth0Logout to true when idpLogout is true', () => {
    const config = getConfig({
      ...defaultConfig,
      idpLogout: true,
    });
    assert.include(config, {
      auth0Logout: false,
      idpLogout: true,
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
        logout: '/custom-logout',
      },
    });
    assert.include(config.routes, {
      callback: '/custom-callback',
      login: '/custom-login',
      logout: '/custom-logout',
    });
  });

  it('should set default app session configuration for http', () => {
    const config = getConfig({
      ...defaultConfig,
      baseURL: 'http://example.com',
    });
    assert.deepInclude(config.session, {
      rollingDuration: 86400,
      name: 'appSession',
      cookie: {
        sameSite: 'Lax',
        httpOnly: true,
        transient: false,
        secure: false,
      },
    });
  });

  it('should set default app session configuration for https', () => {
    const config = getConfig({
      ...defaultConfig,
      baseURL: 'https://example.com',
    });
    assert.deepInclude(config.session, {
      rollingDuration: 86400,
      name: 'appSession',
      cookie: {
        sameSite: 'Lax',
        httpOnly: true,
        transient: false,
        secure: true,
      },
    });
  });

  it('should set custom cookie configuration', () => {
    const sessionIdGenerator = () => '1235';
    const config = getConfig({
      ...defaultConfig,
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      session: {
        name: '__test_custom_session_name__',
        rollingDuration: 1234567890,
        genid: sessionIdGenerator,
        cookie: {
          domain: '__test_custom_domain__',
          transient: true,
          httpOnly: false,
          secure: true,
          sameSite: 'Strict',
        },
      },
    });
    assert.deepInclude(config, {
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      session: {
        name: '__test_custom_session_name__',
        rollingDuration: 1234567890,
        absoluteDuration: 604800,
        rolling: true,
        genid: sessionIdGenerator,
        cookie: {
          domain: '__test_custom_domain__',
          transient: true,
          httpOnly: false,
          secure: true,
          sameSite: 'Strict',
        },
      },
    });
  });

  it('should fail when the baseURL is http and cookie is secure', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        baseURL: 'http://example.com',
        session: { cookie: { secure: true } },
      });
    }, 'Cookies set with the `Secure` property wont be attached to http requests');
  });

  it('should warn when the baseURL is https and cookie is not secure', function () {
    getConfig({
      ...defaultConfig,
      baseURL: 'https://example.com',
      session: { cookie: { secure: false } },
    });
    sinon.assert.calledWith(
      console.warn,
      "Setting your cookie to insecure when over https is not recommended, I hope you know what you're doing."
    );
  });

  it('should warn when the baseURL is http and response_mode is form_post', function () {
    getConfig({
      ...defaultConfig,
      baseURL: 'http://example.com',
      authorizationParams: { response_mode: 'form_post' },
    });
    sinon.assert.calledWith(
      console.warn,
      "Using 'form_post' for response_mode may cause issues for you logging in over http, see https://github.com/auth0/express-openid-connect/blob/master/FAQ.md"
    );
  });

  it('should fail when the baseURL is invalid', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        baseURL: '__invalid_url__',
      });
    }, '"baseURL" must be a valid uri');
  });

  it('should fail when the clientID is not provided', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        clientID: undefined,
      });
    }, '"clientID" is required');
  });

  it('should fail when the baseURL is not provided', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        baseURL: undefined,
      });
    }, '"baseURL" is required');
  });

  it('should fail when the secret is not provided', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        secret: undefined,
      });
    }, '"secret" is required');
  });

  it('should fail when app session length is not an integer', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        session: {
          rollingDuration: 3.14159,
        },
      });
    }, '"session.rollingDuration" must be an integer');
  });

  it('should fail when rollingDuration is defined and rolling is false', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        session: {
          rolling: false,
          rollingDuration: 100,
        },
      });
    }, '"session.rollingDuration" must be false when "session.rolling" is disabled');
  });

  it('should fail when rollingDuration is not defined and rolling is true', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        session: {
          rolling: true,
          rollingDuration: false,
        },
      });
    }, '"session.rollingDuration" must be provided an integer value when "session.rolling" is true');
  });

  it('should fail when absoluteDuration is not defined and rolling is false', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        session: {
          rolling: false,
          absoluteDuration: false,
        },
      });
    }, '"session.absoluteDuration" must be provided an integer value when "session.rolling" is false');
  });

  it('should fail when app session secret is invalid', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        secret: { key: '__test_session_secret__' },
      });
    }, '"secret" must be one of [string, binary, array]');
  });

  it('should fail when app session cookie httpOnly is not a boolean', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        session: {
          cookie: {
            httpOnly: '__invalid_httponly__',
          },
        },
      });
    }, '"session.cookie.httpOnly" must be a boolean');
  });

  it('should fail when app session cookie secure is not a boolean', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        secret: '__test_session_secret__',
        session: {
          cookie: {
            secure: '__invalid_secure__',
          },
        },
      });
    }, '"session.cookie.secure" must be a boolean');
  });

  it('should fail when app session cookie sameSite is invalid', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        secret: '__test_session_secret__',
        session: {
          cookie: {
            sameSite: '__invalid_samesite__',
          },
        },
      });
    }, '"session.cookie.sameSite" must be one of [Lax, Strict, None]');
  });

  it('should fail when app session cookie domain is invalid', function () {
    assert.throws(() => {
      getConfig({
        ...defaultConfig,
        secret: '__test_session_secret__',
        session: {
          cookie: {
            domain: false,
          },
        },
      });
    }, '"session.cookie.domain" must be a string');
  });

  it("shouldn't allow a secret of less than 8 chars", () => {
    assert.throws(
      () => getConfig({ ...defaultConfig, secret: 'short' }),
      TypeError,
      '"secret" does not match any of the allowed types'
    );
    assert.throws(
      () => getConfig({ ...defaultConfig, secret: ['short', 'too'] }),
      TypeError,
      '"secret[0]" does not match any of the allowed types'
    );
    assert.throws(
      () => getConfig({ ...defaultConfig, secret: Buffer.from('short') }),
      TypeError,
      '"secret" must be at least 8 bytes'
    );
  });

  it("shouldn't allow code flow without clientSecret", () => {
    const config = {
      ...defaultConfig,
      authorizationParams: {
        response_type: 'code',
      },
    };
    assert.throws(
      () => getConfig(config),
      TypeError,
      '"clientSecret" is required for a response_type that includes code'
    );
  });

  it("shouldn't allow hybrid flow without clientSecret", () => {
    const config = {
      ...defaultConfig,
      authorizationParams: {
        response_type: 'code id_token',
      },
    };
    assert.throws(
      () => getConfig(config),
      TypeError,
      '"clientSecret" is required for a response_type that includes code'
    );
  });

  it('should not allow "none" for idTokenSigningAlg', () => {
    let config = (idTokenSigningAlg) =>
      getConfig({
        ...defaultConfig,
        idTokenSigningAlg,
      });
    let expected = '"idTokenSigningAlg" contains an invalid value';
    assert.throws(() => config('none'), TypeError, expected);
    assert.throws(() => config('NONE'), TypeError, expected);
    assert.throws(() => config('noNE'), TypeError, expected);
  });

  it('should require clientSecret for ID tokens with HMAC based algorithms', () => {
    const config = {
      ...defaultConfig,
      idTokenSigningAlg: 'HS256',
      authorizationParams: {
        response_type: 'id_token',
      },
    };
    assert.throws(
      () => getConfig(config),
      TypeError,
      '"clientSecret" is required for ID tokens with HMAC based algorithms'
    );
  });

  it('should require clientSecret for ID tokens in hybrid flow with HMAC based algorithms', () => {
    const config = {
      ...defaultConfig,
      idTokenSigningAlg: 'HS256',
      authorizationParams: {
        response_type: 'code id_token',
      },
    };
    assert.throws(
      () => getConfig(config),
      TypeError,
      '"clientSecret" is required for ID tokens with HMAC based algorithms'
    );
  });

  it('should require clientSecret for ID tokens in code flow with HMAC based algorithms', () => {
    const config = {
      ...defaultConfig,
      idTokenSigningAlg: 'HS256',
      authorizationParams: {
        response_type: 'code',
      },
    };
    assert.throws(
      () => getConfig(config),
      TypeError,
      '"clientSecret" is required for ID tokens with HMAC based algorithms'
    );
  });

  it('should allow empty auth params', () => {
    assert.doesNotThrow(validateAuthorizationParams);
    assert.doesNotThrow(() => validateAuthorizationParams({}));
  });

  it('should not allow empty scope', () => {
    assert.throws(
      () => validateAuthorizationParams({ scope: null }),
      TypeError,
      '"authorizationParams.scope" must be a string'
    );
    assert.throws(
      () => validateAuthorizationParams({ scope: '' }),
      TypeError,
      '"authorizationParams.scope" is not allowed to be empty'
    );
  });

  it('should not allow scope without openid', () => {
    assert.throws(
      () => validateAuthorizationParams({ scope: 'profile email' }),
      TypeError,
      '"authorizationParams.scope" with value "profile email" fails to match the contains openid pattern'
    );
  });

  it('should allow scope with openid', () => {
    assert.doesNotThrow(() =>
      validateAuthorizationParams({ scope: 'openid read:users' })
    );
    assert.doesNotThrow(() =>
      validateAuthorizationParams({ scope: 'read:users openid' })
    );
    assert.doesNotThrow(() =>
      validateAuthorizationParams({ scope: 'read:users openid profile email' })
    );
  });

  it('should not allow empty response_type', () => {
    assert.throws(
      () => validateAuthorizationParams({ response_type: null }),
      TypeError,
      '"authorizationParams.response_type" must be one of [id_token, code id_token, code]'
    );
    assert.throws(
      () => validateAuthorizationParams({ response_type: '' }),
      TypeError,
      '"authorizationParams.response_type" must be one of [id_token, code id_token, code]'
    );
  });

  it('should not allow invalid response_types', () => {
    assert.throws(
      () => validateAuthorizationParams({ response_type: 'foo' }),
      TypeError,
      '"authorizationParams.response_type" must be one of [id_token, code id_token, code]'
    );
    assert.throws(
      () => validateAuthorizationParams({ response_type: 'foo id_token' }),
      TypeError,
      '"authorizationParams.response_type" must be one of [id_token, code id_token, code]'
    );
    assert.throws(
      () => validateAuthorizationParams({ response_type: 'id_token code' }),
      TypeError,
      '"authorizationParams.response_type" must be one of [id_token, code id_token, code]'
    );
  });

  it('should allow valid response_types', () => {
    const config = (authorizationParams) => ({
      ...defaultConfig,
      clientSecret: 'foo',
      authorizationParams,
    });
    assert.doesNotThrow(() =>
      validateAuthorizationParams({ response_type: 'id_token' })
    );
    assert.doesNotThrow(() => config({ response_type: 'code id_token' }));
    assert.doesNotThrow(() => config({ response_type: 'code' }));
  });

  it('should not allow empty response_mode', () => {
    assert.throws(
      () => validateAuthorizationParams({ response_mode: null }),
      TypeError,
      '"authorizationParams.response_mode" must be [form_post]'
    );
    assert.throws(
      () => validateAuthorizationParams({ response_mode: '' }),
      TypeError,
      '"authorizationParams.response_mode" must be [form_post]'
    );
    assert.throws(
      () =>
        validateAuthorizationParams({
          response_type: 'code',
          response_mode: '',
        }),
      TypeError,
      '"authorizationParams.response_mode" must be one of [query, form_post]'
    );
  });

  it('should not allow response_type id_token and response_mode query', () => {
    assert.throws(
      () =>
        validateAuthorizationParams({
          response_type: 'id_token',
          response_mode: 'query',
        }),
      TypeError,
      '"authorizationParams.response_mode" must be [form_post]'
    );
    assert.throws(
      () =>
        validateAuthorizationParams({
          response_type: 'code id_token',
          response_mode: 'query',
        }),
      TypeError,
      '"authorizationParams.response_mode" must be [form_post]'
    );
  });

  it('should allow valid response_type response_mode combinations', () => {
    const config = (authorizationParams) => ({
      ...defaultConfig,
      clientSecret: 'foo',
      authorizationParams,
    });
    assert.doesNotThrow(() =>
      config({ response_type: 'code', response_mode: 'query' })
    );
    assert.doesNotThrow(() =>
      config({ response_type: 'code', response_mode: 'form_post' })
    );
    assert.doesNotThrow(() =>
      validateAuthorizationParams({
        response_type: 'id_token',
        response_mode: 'form_post',
      })
    );
    assert.doesNotThrow(() =>
      config({ response_type: 'code id_token', response_mode: 'form_post' })
    );
  });

  it('should default clientAuthMethod to none for id_token response type', () => {
    {
      const config = getConfig(defaultConfig);
      assert.deepInclude(config, {
        clientAuthMethod: 'none',
      });
    }
    {
      const config = getConfig({
        ...defaultConfig,
        authorizationParams: { response_type: 'id_token' },
      });
      assert.deepInclude(config, {
        clientAuthMethod: 'none',
      });
    }
  });

  it('should default clientAuthMethod to client_secret_basic for other response types', () => {
    {
      const config = getConfig({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: { response_type: 'code' },
      });
      assert.deepInclude(config, {
        clientAuthMethod: 'client_secret_basic',
      });
    }

    {
      const config = getConfig({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: { response_type: 'code id_token' },
      });
      assert.deepInclude(config, {
        clientAuthMethod: 'client_secret_basic',
      });
    }
  });
});

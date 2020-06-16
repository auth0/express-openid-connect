const { assert } = require('chai');
const expressOpenid = require('..');

const validConfiguration = {
  secret: '__test_session_secret__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org',
  clientID: '__test_client_id__'
};

function getTestConfig (modify) {
  return Object.assign({}, validConfiguration, modify);
}

describe('invalid parameters', function () {
  it('should fail when the issuerBaseURL is invalid', function () {
    assert.throws(() => {
      expressOpenid.auth({
        secret: '__test_session_secret__',
        baseURL: 'https://example.org',
        issuerBaseURL: '__invalid_url__',
        clientID: '__test_client_id__'
      });
    }, '"issuerBaseURL" does not match any of the allowed types');
  });

  it('should fail when the baseURL is invalid', function () {
    assert.throws(() => {
      expressOpenid.auth({
        secret: '__test_session_secret__',
        baseURL: '__invalid_url__',
        issuerBaseURL: 'https://op.example.com',
        clientID: '__test_client_id__'
      });
    }, '"baseURL" must be a valid uri');
  });

  it('should fail when the clientID is not provided', function () {
    assert.throws(() => {
      expressOpenid.auth({
        secret: '__test_session_secret__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://op.example.com'
      });
    }, '"clientID" is required');
  });

  it('should fail when the baseURL is not provided', function () {
    assert.throws(() => {
      expressOpenid.auth({
        secret: '__test_session_secret__',
        issuerBaseURL: 'https://op.example.com',
        clientID: '__test_client_id__'
      });
    }, '"baseURL" is required');
  });

  it('should fail when the secret is not provided', function () {
    assert.throws(() => {
      expressOpenid.auth({
        issuerBaseURL: 'https://op.example.com',
        baseURL: 'https://example.org',
        clientID: '__test_client_id__'
      });
    }, '"secret" is required');
  });

  it('should fail when client secret is not provided and using the response type code in mode query', function () {
    assert.throws(() => {
      expressOpenid.auth({
        secret: '__test_session_secret__',
        issuerBaseURL: 'https://op.example.com',
        baseURL: 'https://example.org',
        clientID: '__test_client_id__',
        authorizationParams: {
          response_type: 'code id_token'
        }
      });
    }, '"clientSecret" is required for response_type code');
  });

  it('should fail when client secret is not provided and using an HS256 ID token algorithm', function () {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({ idTokenSigningAlg: 'HS256' }));
    }, '"clientSecret" is required for ID tokens with HS algorithms');
  });

  it('should fail when app session length is not an integer', function () {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({
        secret: '__test_session_secret__',
        session: {
          rollingDuration: 3.14159
        }
      }));
    }, '"session.rollingDuration" must be an integer');
  });

  it('should fail when app session secret is invalid', function () {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({ secret: { key: '__test_session_secret__' } }));
    }, '"secret" must be one of [string, binary, array]');
  });

  it('should fail when app session cookie httpOnly is not a boolean', function () {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({
        secret: '__test_session_secret__',
        session: {
          cookie: {
            httpOnly: '__invalid_httponly__'
          }
        }
      }));
    }, '"session.cookie.httpOnly" must be a boolean');
  });

  it('should fail when app session cookie secure is not a boolean', function () {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({
        secret: '__test_session_secret__',
        session: {
          cookie: {
            secure: '__invalid_secure__'
          }
        }
      }));
    }, '"session.cookie.secure" must be a boolean');
  });

  it('should fail when app session cookie sameSite is invalid', function () {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({
        secret: '__test_session_secret__',
        session: {
          cookie: {
            sameSite: '__invalid_samesite__'
          }
        }
      }));
    }, '"session.cookie.sameSite" must be one of [Lax, Strict, None]');
  });

  it('should fail when app session cookie domain is invalid', function () {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({
        secret: '__test_session_secret__',
        session: {
          cookie: {
            domain: false
          }
        }
      }));
    }, '"session.cookie.domain" must be a string');
  });
});

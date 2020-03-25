const { assert } = require('chai');
const expressOpenid = require('..');

const validConfiguration = {
  appSession: {secret: '__test_session_secret__'},
  issuerBaseURL: 'https://test.auth0.com',
  baseURL: 'https://example.org',
  clientID: '__test_client_id__',
};

function getTestConfig(modify) {
  return Object.assign({}, validConfiguration, modify);
}

describe('invalid parameters', function() {
  it('should fail when the issuerBaseURL is invalid', function() {
    assert.throws(() => {
      expressOpenid.auth({
        appSession: {secret: '__test_session_secret__'},
        baseURL: 'https://example.org',
        issuerBaseURL: '__invalid_url__',
        clientID: '__test_client_id__'
      });
    }, '"issuerBaseURL" does not match any of the allowed types');
  });

  it('should fail when the baseURL is invalid', function() {
    assert.throws(() => {
      expressOpenid.auth({
        appSession: {secret: '__test_session_secret__'},
        baseURL: '__invalid_url__',
        issuerBaseURL: 'https://test.auth0.com',
        clientID: '__test_client_id__'
      });
    }, '"baseURL" must be a valid uri');
  });

  it('should fail when the clientID is not provided', function() {
    assert.throws(() => {
      expressOpenid.auth({
        appSession: {secret: '__test_session_secret__'},
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://test.auth0.com',
      });
    }, '"clientID" is required');
  });

  it('should fail when the baseURL is not provided', function() {
    assert.throws(() => {
      expressOpenid.auth({
        appSession: {secret: '__test_session_secret__'},
        issuerBaseURL: 'https://test.auth0.com',
        clientID: '__test_client_id__',
      });
    }, '"baseURL" is required');
  });

  it('should fail when the appSession.secret is not provided', function() {
    assert.throws(() => {
      expressOpenid.auth({
        issuerBaseURL: 'https://test.auth0.com',
        baseURL: 'https://example.org',
        clientID: '__test_client_id__',
      });
    }, '"appSession.secret" is required');
  });

  it('should fail when client secret is not provided and using the response type code in mode query', function() {
    assert.throws(() => {
      expressOpenid.auth({
        appSession: {secret: '__test_session_secret__'},
        issuerBaseURL: 'https://test.auth0.com',
        baseURL: 'https://example.org',
        clientID: '__test_client_id__',
        authorizationParams: {
          response_type: 'code id_token'
        }
      });
    }, '"clientSecret" is required for response_type code');
  });

  it('should fail when client secret is not provided and using an HS256 ID token algorithm', function() {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({idTokenAlg: 'HS256'}));
    }, '"clientSecret" is required for ID tokens with HS algorithms');
  });

  it('should fail when app session length is not an integer', function() {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({
        appSession: {
          secret: '__test_session_secret__',
          duration: 3.14159
        }
      }));
    }, '"appSession.duration" must be an integer');
  });

  it('should fail when app session secret is invalid', function() {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({appSession: {secret: {key: '__test_session_secret__'}}}));
    }, '"appSession.secret" must be one of [string, array]');
  });

  it('should fail when app session cookie httpOnly is not a boolean', function() {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({
        appSession: {
          secret: '__test_session_secret__',
          cookieHttpOnly: '__invalid_httponly__'
        }
      }));
    }, '"appSession.cookieHttpOnly" must be a boolean');
  });

  it('should fail when app session cookie secure is not a boolean', function() {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({
        appSession: {
          secret: '__test_session_secret__',
          cookieSecure: '__invalid_secure__'
        }
      }));
    }, '"appSession.cookieSecure" must be a boolean');
  });

  it('should fail when app session cookie sameSite is invalid', function() {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({
        appSession: {
          secret: '__test_session_secret__',
          cookieSameSite: '__invalid_samesite__'
        }
      }));
    }, '"appSession.cookieSameSite" must be one of [Lax, Strict, None]');
  });

  it('should fail when app session cookie domain is invalid', function() {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({
        appSession: {
          secret: '__test_session_secret__',
          cookieDomain: false
        }
      }));
    }, '"appSession.cookieDomain" must be a string');
  });

  it('should fail when app session cookie sameSite is an invalid value', function() {
    assert.throws(() => {
      expressOpenid.auth(getTestConfig({
        appSession: {
          secret: '__test_session_secret__',
          cookiePath: 123
        }
      }));
    }, '"appSession.cookiePath" must be a string');
  });
});

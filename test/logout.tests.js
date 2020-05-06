const { assert } = require('chai');
const server = require('./fixture/server');
const { auth } = require('./..');

const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

describe('logout route', function() {
  describe('application only logout', function() {
    let baseUrl;
    let currentSession;
    let logoutResponse;
    const jar = request.jar();

    before(async function() {
      const middleware = auth({
        idpLogout: false,
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://test.auth0.com',
        appSession: {secret: '__test_session_secret__'},
        required: false
      });
      baseUrl = await server.create(middleware);
      await request.post({
        uri: '/session',
        json: {
          openidTokens: {
            id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
          }
        },
        baseUrl, jar
      });
      logoutResponse = await request.get({uri: '/logout', baseUrl, jar, followRedirect: false});
      currentSession = (await request.get({uri: '/session', baseUrl, jar})).body;
    });

    it('should clear the session', function() {
      assert.notOk(currentSession.openidTokens);
    });

    it('should redirect to the base url', function() {
      assert.equal(logoutResponse.statusCode, 302);
      assert.equal(logoutResponse.headers.location, 'https://example.org');
    });
  });

  describe('identity provider logout (auth0)', function() {
    let baseUrl;
    let currentSession;
    let logoutResponse;
    const jar = request.jar();

    before(async function() {
      const middleware = auth({
        idpLogout: true,
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://test.auth0.com',
        appSession: {secret: '__test_session_secret__'},
        required: false
      });
      baseUrl = await server.create(middleware);
      await request.post({
        uri: '/session',
        json: {
          openidTokens: {
            id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
          }
        },
        baseUrl, jar
      });
      logoutResponse = await request.get({uri: '/logout', baseUrl, jar, followRedirect: false});
      currentSession = (await request.get({uri: '/session', baseUrl, jar})).body;
    });

    it('should clear the session', function() {
      assert.notOk(currentSession.openidTokens);
    });

    it('should redirect to the base url', function() {
      assert.equal(logoutResponse.statusCode, 302);
      assert.equal(logoutResponse.headers.location, 'https://example.org');
    });
  });


  describe('should use postLogoutRedirectUri if present', function() {
    describe('should allow relative paths, and prepend with baseURL', () => {
      let baseUrl;
      const jar = request.jar();

      before(async function() {
        const middleware = auth({
          idpLogout: false,
          clientID: '__test_client_id__',
          baseURL: 'https://example.org',
          issuerBaseURL: 'https://test.auth0.com',
          appSession: {secret: '__test_session_secret__'},
          postLogoutRedirectUri: '/after-logout-in-auth-config',
          required: false,
        });
        baseUrl = await server.create(middleware);
        await request.post({
          uri: '/session',
          json: {
            openidTokens: {
              id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
            }
          },
          baseUrl, jar
        });
      });

      it('should redirect to postLogoutRedirectUri in auth() config', async function() {
        const logoutResponse = await request.get({uri: '/logout', baseUrl, jar, followRedirect: false});
        assert.equal(logoutResponse.headers.location, 'https://example.org/after-logout-in-auth-config');
      });
    });

    describe('should allow absolute paths', () => {
      let baseUrl;
      const jar = request.jar();

      before(async function() {
        const middleware = auth({
          idpLogout: false,
          clientID: '__test_client_id__',
          baseURL: 'https://example.org',
          issuerBaseURL: 'https://test.auth0.com',
          appSession: {secret: '__test_session_secret__'},
          postLogoutRedirectUri: 'https://external-domain.com/after-logout-in-auth-config',
          required: false,
        });
        baseUrl = await server.create(middleware);
        await request.post({
          uri: '/session',
          json: {
            openidTokens: {
              id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
            }
          },
          baseUrl, jar
        });
      });

      it('should redirect to postLogoutRedirectUri in auth() config', async function() {
        const logoutResponse = await request.get({uri: '/logout', baseUrl, jar, followRedirect: false});
        assert.equal(logoutResponse.headers.location, 'https://external-domain.com/after-logout-in-auth-config');
      });
    });
  });

  describe('logout with custom path', function() {
    let baseUrl;
    let currentSession;
    const jar = request.jar();

    before(async function() {
      const middleware = auth({
        idpLogout: false,
        clientID: '__test_client_id__',
        baseURL: 'https://example.org/foo',
        issuerBaseURL: 'https://test.auth0.com',
        appSession: {
          secret: '__test_secret__',
          cookiePath: '/foo'
        },
        required: false
      });
      baseUrl = (await server.create(middleware, null, '/foo')) + '/foo';
      await request.post({
        uri: '/session',
        json: {
          openidTokens: {
            id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
          },
          claims: {}
        },
        baseUrl, jar
      });
    });

    it('should populate the session', async function() {
      currentSession = JSON.parse((await request.get({uri: '/session', baseUrl, jar})).body);
      assert.ok(currentSession.openidTokens);
    });

    it('should clear the session', async function() {
      await request.get({uri: '/logout', baseUrl, jar, followRedirect: false});
      currentSession = JSON.parse((await request.get({uri: '/session', baseUrl, jar})).body);
      assert.notOk(currentSession.openidTokens);
    });
  });
});

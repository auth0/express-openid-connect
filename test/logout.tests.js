const { assert } = require('chai');
const { create: createServer } = require('./fixture/server');
const { auth } = require('./..');

const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

const defaultConfig = {
  clientID: '__test_client_id__',
  baseURL: 'https://example.org',
  issuerBaseURL: 'https://op.example.com',
  secret: '__test_session_secret__',
  authRequired: false
};

const login = async (baseUrl = 'http://localhost:3000') => {
  const jar = request.jar();
  await request.post({
    uri: '/session',
    json: {
      id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    },
    baseUrl, jar
  });

  const session = (await request.get({uri: '/session', baseUrl, jar, json: true })).body;
  return { jar, session };
};

const logout = async (jar, baseUrl = 'http://localhost:3000') => {
  const response = await request.get({uri: '/logout', baseUrl, jar, followRedirect: false});
  const session = (await request.get({uri: '/session', baseUrl, jar, json: true})).body;
  return { response, session };
};

describe('logout route', async () => {
  let server;

  afterEach(async () => {
    if (server) {
      server.close();
    }
  });

  it('should perform a local logout', async () => {
    server = await createServer(auth({
      ...defaultConfig,
      idpLogout: false,
    }));

    const { jar, session: loggedInSession } = await login();
    assert.ok(loggedInSession.id_token);
    const { response, session: loggedOutSession } = await logout(jar);
    assert.notOk(loggedOutSession.id_token);
    assert.equal(response.statusCode, 302);
    assert.include(response.headers, {
      location: 'https://example.org'
    }, 'should redirect to the base url');
  });

  it('should perform a distributed logout', async () => {
    server = await createServer(auth({
      ...defaultConfig,
      idpLogout: true,
    }));

    const { jar } = await login();
    const { response, session: loggedOutSession } = await logout(jar);
    assert.notOk(loggedOutSession.id_token);
    assert.equal(response.statusCode, 302);
    assert.include(response.headers, {
      location: 'https://op.example.com/session/end?post_logout_redirect_uri=https%3A%2F%2Fexample.org&id_token_hint=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    }, 'should redirect to the identity provider');
  });

  it('should perform an auth0 logout', async () => {
    server = await createServer(auth({
      ...defaultConfig,
      issuerBaseURL: 'https://test.eu.auth0.com',
      idpLogout: true,
      auth0Logout: true,
    }));

    const { jar } = await login();
    const { response, session: loggedOutSession } = await logout(jar);
    assert.notOk(loggedOutSession.id_token);
    assert.equal(response.statusCode, 302);
    assert.include(response.headers, {
      location: 'https://op.example.com/v2/logout?returnTo=https%3A%2F%2Fexample.org&client_id=__test_client_id__'
    }, 'should redirect to the identity provider');
  });

  it('should redirect to postLogoutRedirectUri', async () => {
    server = await createServer(auth({
      ...defaultConfig,
      routes: {
        postLogoutRedirectUri: '/after-logout-in-auth-config',
      },
    }));

    const { jar } = await login();
    const { response, session: loggedOutSession } = await logout(jar);
    assert.notOk(loggedOutSession.id_token);
    assert.equal(response.statusCode, 302);
    assert.include(response.headers, {
      location: 'https://example.org/after-logout-in-auth-config'
    }, 'should redirect to postLogoutRedirectUri');
  });

  it('should logout when under a sub path', async () => {
    server = await createServer(auth(defaultConfig), null, '/foo');
    const baseUrl = 'http://localhost:3000/foo';

    const { jar, session: loggedInSession } = await login(baseUrl);
    assert.ok(loggedInSession.id_token);
    const { session: loggedOutSession } = await logout(jar, baseUrl);
    assert.notOk(loggedOutSession.id_token);
  });
});

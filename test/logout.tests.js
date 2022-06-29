const nock = require('nock');
const { assert } = require('chai');
const { URL } = require('url');
const { create: createServer } = require('./fixture/server');
const { makeIdToken } = require('./fixture/cert');
const { auth } = require('./..');

const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});

const defaultConfig = {
  clientID: '__test_client_id__',
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
  secret: '__test_session_secret__',
  authRequired: false,
};

const login = async (baseUrl = 'http://localhost:3000', idToken) => {
  const jar = request.jar();
  await request.post({
    uri: '/session',
    json: {
      id_token: idToken || makeIdToken(),
    },
    baseUrl,
    jar,
  });

  const session = (
    await request.get({ uri: '/session', baseUrl, jar, json: true })
  ).body;
  return { jar, session };
};

const logout = async (jar, baseUrl = 'http://localhost:3000') => {
  const response = await request.get({
    uri: '/logout',
    baseUrl,
    jar,
    followRedirect: false,
  });
  const session = (
    await request.get({ uri: '/session', baseUrl, jar, json: true })
  ).body;
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
    server = await createServer(
      auth({
        ...defaultConfig,
        idpLogout: false,
      })
    );

    const { jar, session: loggedInSession } = await login();
    assert.ok(loggedInSession.id_token);
    const { response, session: loggedOutSession } = await logout(jar);
    assert.notOk(loggedOutSession.id_token);
    assert.equal(response.statusCode, 302);
    assert.include(
      response.headers,
      {
        location: 'http://example.org',
      },
      'should redirect to the base url'
    );
  });

  it('should perform a distributed logout', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        idpLogout: true,
      })
    );

    const idToken = makeIdToken();
    const { jar } = await login('http://localhost:3000', idToken);
    const { response, session: loggedOutSession } = await logout(jar);
    assert.notOk(loggedOutSession.id_token);
    assert.equal(response.statusCode, 302);
    assert.include(
      response.headers,
      {
        location: `https://op.example.com/session/end?post_logout_redirect_uri=http%3A%2F%2Fexample.org&id_token_hint=${idToken}`,
      },
      'should redirect to the identity provider'
    );
  });

  it('should perform an auth0 logout', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        issuerBaseURL: 'https://test.eu.auth0.com',
        idpLogout: true,
        auth0Logout: true,
      })
    );

    const { jar } = await login();
    const { response, session: loggedOutSession } = await logout(jar);
    assert.notOk(loggedOutSession.id_token);
    assert.equal(response.statusCode, 302);
    assert.include(
      response.headers,
      {
        location:
          'https://op.example.com/v2/logout?returnTo=http%3A%2F%2Fexample.org&client_id=__test_client_id__',
      },
      'should redirect to the identity provider'
    );
  });

  it('should redirect to postLogoutRedirect', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        routes: {
          postLogoutRedirect: '/after-logout-in-auth-config',
        },
      })
    );

    const { jar } = await login();
    const { response, session: loggedOutSession } = await logout(jar);
    assert.notOk(loggedOutSession.id_token);
    assert.equal(response.statusCode, 302);
    assert.include(
      response.headers,
      {
        location: 'http://example.org/after-logout-in-auth-config',
      },
      'should redirect to postLogoutRedirect'
    );
  });

  it('should redirect to the specified returnTo', async () => {
    const router = auth({
      ...defaultConfig,
      routes: {
        logout: false,
        postLogoutRedirect: '/after-logout-in-auth-config',
      },
    });
    server = await createServer(router);
    router.get('/logout', (req, res) =>
      res.oidc.logout({ returnTo: 'http://www.another-example.org/logout' })
    );

    const { jar } = await login();
    const { response, session: loggedOutSession } = await logout(jar);
    assert.notOk(loggedOutSession.id_token);
    assert.equal(response.statusCode, 302);
    assert.include(
      response.headers,
      {
        location: 'http://www.another-example.org/logout',
      },
      'should redirect to params.returnTo'
    );
  });

  it('should logout when scoped to a sub path', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        session: {
          cookie: {
            path: '/foo',
          },
        },
      }),
      null,
      '/foo'
    );
    const baseUrl = 'http://localhost:3000/foo';

    const { jar, session: loggedInSession } = await login(baseUrl);
    assert.ok(loggedInSession.id_token);
    const sessionCookie = jar
      .getCookies('http://localhost:3000/foo')
      .find(({ key }) => key === 'appSession');
    assert.equal(sessionCookie.path, '/foo');
    const { session: loggedOutSession } = await logout(jar, baseUrl);
    assert.notOk(loggedOutSession.id_token);
  });

  it('should cancel silent logins when user logs out', async () => {
    server = await createServer(auth(defaultConfig));

    const { jar } = await login();
    const baseUrl = 'http://localhost:3000';
    assert.notOk(
      jar.getCookies(baseUrl).find(({ key }) => key === 'skipSilentLogin')
    );
    await logout(jar);
    assert.ok(
      jar.getCookies(baseUrl).find(({ key }) => key === 'skipSilentLogin')
    );
  });

  it('should pass logout params to end session url', async () => {
    server = await createServer(
      auth({ ...defaultConfig, idpLogout: true, logoutParams: { foo: 'bar' } })
    );

    const { jar } = await login();
    const {
      response: {
        headers: { location },
      },
    } = await logout(jar);
    const params = new URL(location).searchParams;
    assert.equal(params.get('foo'), 'bar');
  });

  it('should override logout params per request', async () => {
    const router = auth({
      ...defaultConfig,
      idpLogout: true,
      logoutParams: { foo: 'bar' },
      routes: { logout: false },
    });
    server = await createServer(router);
    router.get('/logout', (req, res) =>
      res.oidc.logout({ logoutParams: { foo: 'baz' } })
    );

    const { jar } = await login();
    const {
      response: {
        headers: { location },
      },
    } = await logout(jar);
    const params = new URL(location).searchParams;
    assert.equal(params.get('foo'), 'baz');
  });

  it('should pass logout params to auth0 logout url', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        issuerBaseURL: 'https://test.eu.auth0.com',
        idpLogout: true,
        auth0Logout: true,
        logoutParams: { foo: 'bar' },
      })
    );

    const { jar } = await login();
    const {
      response: {
        headers: { location },
      },
    } = await logout(jar);
    const url = new URL(location);
    assert.equal(url.pathname, '/v2/logout');
    assert.equal(url.searchParams.get('foo'), 'bar');
  });

  it('should honor logout url config over logout params', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        routes: { postLogoutRedirect: 'http://foo.com' },
        idpLogout: true,
        logoutParams: {
          foo: 'bar',
          post_logout_redirect_uri: 'http://bar.com',
        },
      })
    );

    const { jar } = await login();
    const {
      response: {
        headers: { location },
      },
    } = await logout(jar);
    const url = new URL(
      new URL(location).searchParams.get('post_logout_redirect_uri')
    );
    assert.equal(url.hostname, 'foo.com');
  });

  it('should ignore undefined or null logout params', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        issuerBaseURL: 'https://test.eu.auth0.com',
        idpLogout: true,
        auth0Logout: true,
        logoutParams: { foo: 'bar', bar: undefined, baz: null, qux: '' },
      })
    );

    const { jar } = await login();
    const {
      response: {
        headers: { location },
      },
    } = await logout(jar);
    const url = new URL(location);
    assert.equal(url.pathname, '/v2/logout');
    assert.equal(url.searchParams.get('foo'), 'bar');
    assert.isFalse(url.searchParams.has('bar'));
    assert.isFalse(url.searchParams.has('baz'));
    assert.equal(url.searchParams.get('qux'), '');
  });

  it('should pass discovery errors to the express mw', async () => {
    nock('https://example.com')
      .get('/.well-known/openid-configuration')
      .reply(500);
    nock('https://example.com')
      .get('/.well-known/oauth-authorization-server')
      .reply(500);

    server = await createServer(
      auth({
        ...defaultConfig,
        issuerBaseURL: 'https://example.com',
      })
    );
    const res = await request.get({
      uri: '/logout',
      baseUrl: 'http://localhost:3000',
      followRedirect: false,
      json: true,
    });
    assert.equal(res.statusCode, 500);
    console.log(res.body.err.message);
    assert.match(
      res.body.err.message,
      /^Issuer.discover\(\) failed/,
      'Should get error json from server error middleware'
    );
  });
});

const server = require('../test/fixture/server');
const { auth } = require('./..');
const urlJoin = require('url-join');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

const defaultAuthConfig = {
  idpLogout: false,
  clientID: '__test_client_id__',
  baseURL: 'https://example.org',
  issuerBaseURL: 'https://test.auth0.com',
  appSession: {secret: '__test_session_secret__'},
  required: false
};

/** @param {Parameters<typeof auth>[0]} authConfig - Override the default auth config */
const init = async (authConfig) => {
  const middleware = auth({
    ...defaultAuthConfig,
    ...authConfig
  });

  const baseUrl = await server.create(middleware);

  const jar = request.jar();
  await request.post({
    uri: '/session',
    json: {
      openidTokens: {
        id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
      }
    },
    baseUrl, jar
  });

  const logoutResponse = await request.get({uri: '/logout', baseUrl, jar, followRedirect: false});

  const currentSession = (await request.get({uri: '/session', baseUrl, jar})).body;

  return { logoutResponse, currentSession };
};


describe('application only logout', () => {

  test('should clear the session', async () => {
    const {currentSession} = await init();
    expect(currentSession.openidTokens).toBeUndefined();
  });

  test('should redirect to the base url', async () => {
    const {logoutResponse} = await init();
    expect(logoutResponse.statusCode).toBe(302);
    expect(logoutResponse.headers.location).toBe(defaultAuthConfig.baseURL);
  });
});

describe('identity provider logout (auth0)', () => {

  test('should clear the session', async () => {
    const {currentSession} = await init({idpLogout: true});
    expect(currentSession.openidTokens).toBeUndefined();
  });

  test('should redirect to the base url', async () => {
    const {logoutResponse} = await init({idpLogout: true});
    expect(logoutResponse.statusCode).toBe(302);
    expect(logoutResponse.headers.location).toBe(defaultAuthConfig.baseURL);
  });
});


describe('use postLogoutRedirectUri, if present', () => {

  test('redirect to relative paths defined in auth() config', async () => {
    const relativePostLogoutUri = '/after-logout-in-auth-config';

    const {logoutResponse} = await init({
      postLogoutRedirectUri: relativePostLogoutUri
    });

    expect(logoutResponse.headers.location).toBe(
      // Prepended with baseUrl
      urlJoin(defaultAuthConfig.baseURL, relativePostLogoutUri)
    );
  });

  test('redirect to absolute paths defined in auth() config', async () => {
    const externalPostLogoutUri = 'https://external-domain.com/after-logout-in-auth-config';

    const {logoutResponse} = await init({ postLogoutRedirectUri: externalPostLogoutUri
    });

    expect(logoutResponse.headers.location).toBe(externalPostLogoutUri);
  });
});
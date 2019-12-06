const { assert } = require('chai');
const url = require('url');
const server = require('./fixture/server');
const { auth } = require('./..');

const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true
});

const mockData = {
  clientID: '__test_client_id__',
  baseURL: 'https://example.org',
  postLogoutRedirectUri: 'https://example.com/logged-out',
};


async function setup({authParams, logoutQuery} = {}) {
  const jar = request.jar();
  const middleware = auth({
    idpLogout: false,
    clientID: mockData.clientID,
    baseURL: mockData.baseURL,
    issuerBaseURL: 'https://test.auth0.com',
    required: false,
    ...authParams
  });
  const baseUrl = await server.create(middleware);

  await request.post({
    uri: '/session',
    json: {
      openidTokens: {
        id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
      }
    },
    baseUrl, jar
  });

  return {
    logoutResponse: await request.get({uri: '/logout', qs: logoutQuery, baseUrl, jar, followRedirect: false}),
    currentSession: (await request.get({uri: '/session', baseUrl, jar})).body
  };
}

describe('logout route', function() {
  describe('application only logout', function() {

    it('should clear the session', async function() {
      const result = await setup();
      assert.notOk(result.currentSession.openidTokens);
    });

    it('should redirect to the base url', async function() {
      const result = await setup();
      assert.equal(result.logoutResponse.statusCode, 302);
      assert.equal(result.logoutResponse.headers.location, mockData.baseURL);
    });

    it('should redirect to post_logout_redirect_uri', async function() {
      const result = await setup({authParams: {postLogoutRedirectUri: mockData.postLogoutRedirectUri}});
      assert.equal(result.logoutResponse.statusCode, 302);
      assert.equal(result.logoutResponse.headers.location, mockData.postLogoutRedirectUri);
    });

    it('should redirect using returnTo from logout query', async function() {
      const result = await setup({
        logoutQuery: {
          returnTo: mockData.postLogoutRedirectUri
        }});
      assert.equal(result.logoutResponse.statusCode, 302);
      assert.equal(result.logoutResponse.headers.location, mockData.postLogoutRedirectUri);
    });

  });

  describe('identity provider logout (auth0)', function() {

    const authOParsedUrl = {
      protocol: 'https:',
      hostname: 'test.auth0.com',
      pathname: '/v2/logout',
    };

    it('should clear the session', async function() {
      const result = await setup({authParams: {idpLogout: true}});
      assert.notOk(result.currentSession.openidTokens);
    });

    it('should redirect to the base url', async function() {
      const result = await setup({authParams: {idpLogout: true}});
      assert.equal(result.logoutResponse.statusCode, 302);
      const parsedUrl = url.parse(result.logoutResponse.headers.location, true);
      assert.deepInclude(parsedUrl, {
        query: { returnTo: mockData.baseURL, client_id: mockData.clientID },
        ...authOParsedUrl
      });
    });

    it('should redirect to post_logout_redirect_uri', async function() {
      const result = await setup({
        authParams: {
          idpLogout: true,
          postLogoutRedirectUri: mockData.postLogoutRedirectUri
        }
      });
      assert.equal(result.logoutResponse.statusCode, 302);
      const parsedUrl = url.parse(result.logoutResponse.headers.location, true);
      assert.deepInclude(parsedUrl, {
        query: { returnTo: mockData.postLogoutRedirectUri, client_id: mockData.clientID },
        ...authOParsedUrl
      });
    });

    it('should redirect using returnTo from logout query', async function() {
      const result = await setup({
        authParams: {idpLogout: true},
        logoutQuery: {
          returnTo: mockData.postLogoutRedirectUri
        }});
      assert.equal(result.logoutResponse.statusCode, 302);
      const parsedUrl = url.parse(result.logoutResponse.headers.location, true);
      assert.deepInclude(parsedUrl, {
        query: { 
          returnTo: mockData.postLogoutRedirectUri,
          client_id: mockData.clientID
        },
        ...authOParsedUrl
      });
      
    });
  });


});

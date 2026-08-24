const assert = require('chai').assert;
const nock = require('nock');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});

const { auth } = require('..');
const { create: createServer } = require('./fixture/server');

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
};

describe('startEnterpriseLogin', () => {
  let server;
  const baseUrl = 'http://localhost:3000';

  const mountRoute = (opts = {}) => {
    const router = auth({ ...defaultConfig, enterpriseConnect: true, ...opts });
    router.post('/enterprise-login', async (req, res) => {
      const started = await res.oidc.startEnterpriseLogin({
        email: req.body.email,
        returnTo: '/dashboard',
      });
      if (!started) {
        res.json({ started: false });
      }
    });
    return router;
  };

  afterEach(async () => {
    if (server) {
      server.close();
    }
  });

  it('should redirect to Auth0 with login_hint set for a federated domain', async () => {
    nock('https://op.example.com')
      .get('/.well-known/webfinger')
      .query(true)
      .reply(200, {
        links: [
          {
            rel: 'http://openid.net/specs/connect/1.0/issuer',
            href: 'https://op.example.com/',
          },
        ],
      });

    server = await createServer(mountRoute());

    const response = await request.post({
      uri: '/enterprise-login',
      baseUrl,
      json: { email: 'jane@acmecorp.com' },
      followRedirect: false,
    });

    assert.equal(response.statusCode, 302);
    const location = new URL(response.headers.location);
    assert.equal(location.searchParams.get('login_hint'), 'jane@acmecorp.com');
  });

  it('should send no connection/organization params — HRD resolves them from login_hint', async () => {
    nock('https://op.example.com')
      .get('/.well-known/webfinger')
      .query(true)
      .reply(200, {
        links: [
          {
            rel: 'http://openid.net/specs/connect/1.0/issuer',
            href: 'https://op.example.com/',
          },
        ],
      });

    server = await createServer(mountRoute());

    const response = await request.post({
      uri: '/enterprise-login',
      baseUrl,
      json: { email: 'jane@acmecorp.com' },
      followRedirect: false,
    });

    const location = new URL(response.headers.location);
    assert.isNull(location.searchParams.get('connection'));
    assert.isNull(location.searchParams.get('organization'));
  });

  it('should return false and not redirect for a non-federated domain', async () => {
    nock('https://op.example.com')
      .get('/.well-known/webfinger')
      .query(true)
      .reply(404);

    server = await createServer(mountRoute());

    const response = await request.post({
      uri: '/enterprise-login',
      baseUrl,
      json: { email: 'jane@gmail.com' },
      followRedirect: false,
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.body, { started: false });
  });

  it('should return false without making a WebFinger request for an email with no domain', async () => {
    const scope = nock('https://op.example.com')
      .get('/.well-known/webfinger')
      .query(true)
      .reply(200, { links: [] });

    server = await createServer(mountRoute());

    const response = await request.post({
      uri: '/enterprise-login',
      baseUrl,
      json: { email: 'not-an-email' },
      followRedirect: false,
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.body, { started: false });
    assert.isFalse(scope.isDone());
  });
});

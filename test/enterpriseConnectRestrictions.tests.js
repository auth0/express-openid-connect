const assert = require('chai').assert;
const express = require('express');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});

const { auth, EnterpriseConnectError } = require('..');
const { create: createServer } = require('./fixture/server');
const { makeIdToken } = require('./fixture/cert');

const baseUrl = 'http://localhost:3000';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
  enterpriseConnect: true,
};

const defaultSession = () => ({
  id_token: makeIdToken(),
  access_token: '__test_access_token__',
  token_type: 'Bearer',
  expires_at: Math.floor(Date.now() / 1000) + 86400,
});

// These three members read or exchange an Auth0-managed access/refresh token,
// which Enterprise Connect never issues or persists (the SDK's own session
// write is suppressed in this mode). Matches the reference implementations'
// (nextjs-auth0, auth0-server-js) `enterprise_connect_not_supported` error
// code — see EnterpriseConnectError.
describe('Enterprise Connect method/property restrictions', () => {
  let server;

  afterEach(() => {
    if (server) {
      server.close();
    }
  });

  const setup = async (routeFn, authConfig = defaultConfig) => {
    const router = express.Router();
    router.use(auth(authConfig));
    router.get('/restricted', async (req, res, next) => {
      try {
        const result = await routeFn(req, res);
        res.json(result ?? {});
      } catch (err) {
        next(err);
      }
    });

    server = await createServer(router);
    const jar = request.jar();
    await request.post('/session', { baseUrl, jar, json: defaultSession() });

    return request.get('/restricted', { baseUrl, jar, json: true });
  };

  it('accessToken throws when enterpriseConnect is true', async () => {
    const response = await setup((req) => req.oidc.accessToken);
    assert.equal(response.statusCode, 500);
    assert.match(response.body.err.message, /accessToken/);
    assert.match(response.body.err.message, /enterpriseConnect: true/);
  });

  it('accessToken works normally without enterpriseConnect', async () => {
    const nonEcConfig = {
      secret: '__test_session_secret__',
      clientID: '__test_client_id__',
      baseURL: 'http://example.org',
      issuerBaseURL: 'https://op.example.com',
      authRequired: false,
    };
    const response = await setup(
      (req) => ({ token: req.oidc.accessToken }),
      nonEcConfig,
    );
    assert.equal(response.statusCode, 200);
    assert.equal(response.body.token.access_token, '__test_access_token__');
  });

  it('requestSessionTransferToken() throws when enterpriseConnect is true', async () => {
    const response = await setup((req) =>
      req.oidc.requestSessionTransferToken({
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      }),
    );
    assert.equal(response.statusCode, 500);
    assert.match(response.body.err.message, /requestSessionTransferToken\(\)/);
  });

  it('buildSessionTransferRedirect() throws when enterpriseConnect is true', async () => {
    const response = await setup((req) =>
      req.oidc.buildSessionTransferRedirect('https://app.example.com/login', {
        session_transfer_token: '__test_stt__',
        issued_token_type:
          'urn:auth0:params:oauth:token-type:session_transfer_token',
      }),
    );
    assert.equal(response.statusCode, 500);
    assert.match(response.body.err.message, /buildSessionTransferRedirect\(\)/);
  });

  it('EnterpriseConnectError has the same code as the reference implementations', () => {
    const err = new EnterpriseConnectError('accessToken');
    assert.equal(err.name, 'EnterpriseConnectError');
    assert.equal(err.code, 'enterprise_connect_not_supported');
  });
});

const assert = require('chai').assert;
const nock = require('nock');
const qs = require('querystring');
const express = require('express');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});

const { auth } = require('..');
const { create: createServer } = require('./fixture/server');
const { makeIdToken } = require('./fixture/cert');

const baseUrl = 'http://localhost:3000';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
};

describe('customTokenExchange', () => {
  let server;

  afterEach(() => {
    if (server) {
      server.close();
    }
  });

  const setup = async ({
    authConfig = {},
    exchangeOptions = {},
    mockTokenResponse = null,
    sessionData = null,
  } = {}) => {
    const config = { ...defaultConfig, ...authConfig };

    const router = express.Router();
    router.use(auth(config));
    router.get('/custom-exchange', async (req, res, next) => {
      try {
        const result = await req.oidc.customTokenExchange(exchangeOptions);
        res.json(result);
      } catch (err) {
        next(err);
      }
    });

    server = await createServer(router);
    const jar = request.jar();

    // Seed session with tokens
    await request.post('/session', {
      baseUrl,
      jar,
      json: sessionData || {
        id_token: makeIdToken(),
        access_token: '__test_access_token__',
        token_type: 'Bearer',
        expires_at: Math.floor(Date.now() / 1000) + 86400,
      },
    });

    let capturedBody;
    nock('https://op.example.com')
      .post('/oauth/token')
      .reply(
        mockTokenResponse ? mockTokenResponse.status : 200,
        function (uri, body) {
          capturedBody = qs.parse(body);
          return mockTokenResponse
            ? mockTokenResponse.body
            : {
                access_token: '__test_exchanged_token__',
                token_type: 'Bearer',
              };
        },
      );

    const response = await request.get('/custom-exchange', {
      baseUrl,
      jar,
      json: true,
    });

    return { response, capturedBody };
  };

  it('uses the current access token as the default subject_token', async () => {
    const { capturedBody } = await setup();
    assert.equal(capturedBody.subject_token, '__test_access_token__');
    assert.equal(
      capturedBody.subject_token_type,
      'urn:ietf:params:oauth:token-type:access_token',
    );
  });

  it('throws 400 immediately when subject_token cannot be resolved', async () => {
    const { response } = await setup({
      sessionData: { id_token: makeIdToken() }, // no access_token in session
    });
    assert.equal(response.statusCode, 400);
    assert.equal(
      response.body.err.message,
      'subject_token is required for token exchange',
    );
  });

  it('applies authorizationParams defaults for audience and scope', async () => {
    const { capturedBody } = await setup({
      authConfig: {
        authorizationParams: {
          audience: 'https://default-api.example.com',
          scope: 'openid read:data',
        },
      },
    });
    assert.equal(capturedBody.audience, 'https://default-api.example.com');
    assert.equal(capturedBody.scope, 'openid read:data');
  });

  it('sends organization when explicitly provided via extra', async () => {
    const { capturedBody } = await setup({
      exchangeOptions: { extra: { organization: 'org_abc123' } },
    });
    assert.equal(capturedBody.organization, 'org_abc123');
  });

  it('caller-provided options override authorizationParams defaults', async () => {
    const { capturedBody } = await setup({
      authConfig: {
        authorizationParams: {
          audience: 'https://default-api.example.com',
          scope: 'openid read:data',
        },
      },
      exchangeOptions: {
        subject_token: '__custom_subject_token__',
        subject_token_type: 'urn:ietf:params:oauth:token-type:refresh_token',
        audience: 'https://custom-api.example.com',
        scope: 'openid write:data',
      },
    });
    assert.equal(capturedBody.subject_token, '__custom_subject_token__');
    assert.equal(
      capturedBody.subject_token_type,
      'urn:ietf:params:oauth:token-type:refresh_token',
    );
    assert.equal(capturedBody.audience, 'https://custom-api.example.com');
    assert.equal(capturedBody.scope, 'openid write:data');
  });

  it('passes extra params to the token endpoint', async () => {
    const { capturedBody } = await setup({
      exchangeOptions: {
        extra: { custom_param: 'custom_value' },
      },
    });
    assert.equal(capturedBody.custom_param, 'custom_value');
  });

  it('silently strips denylisted keys from extra without throwing', async () => {
    const { response, capturedBody } = await setup({
      exchangeOptions: {
        extra: { grant_type: 'x', scope: 'bad', custom_param: 'ok' },
      },
    });
    // should succeed with no error
    assert.equal(response.statusCode, 200);
    // non-denylisted key passes through
    assert.equal(capturedBody.custom_param, 'ok');
    // denylisted grant_type from extra is stripped; real grant_type is preserved
    assert.equal(
      capturedBody.grant_type,
      'urn:ietf:params:oauth:grant-type:token-exchange',
    );
    // denylisted scope from extra is stripped; config default scope is used instead
    assert.notEqual(capturedBody.scope, 'bad');
  });

  it('allows RFC 8693 optional params and IdP-specific params via extra', async () => {
    const { capturedBody } = await setup({
      exchangeOptions: {
        extra: {
          connection: 'google-oauth2',
          requested_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          actor_token: '__test_actor_token__',
          actor_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        },
      },
    });
    assert.equal(capturedBody.connection, 'google-oauth2');
    assert.equal(
      capturedBody.requested_token_type,
      'urn:ietf:params:oauth:token-type:jwt',
    );
    assert.equal(capturedBody.actor_token, '__test_actor_token__');
    assert.equal(
      capturedBody.actor_token_type,
      'urn:ietf:params:oauth:token-type:access_token',
    );
  });

  it('returns the TokenSet from client.grant()', async () => {
    const { response } = await setup();
    assert.equal(response.statusCode, 200);
    assert.equal(response.body.access_token, '__test_exchanged_token__');
  });

  it('propagates AS errors as HTTP 400 with error fields', async () => {
    const { response } = await setup({
      mockTokenResponse: {
        status: 400,
        body: {
          error: 'access_denied',
          error_description: 'Token exchange not allowed',
        },
      },
    });
    assert.equal(response.statusCode, 400);
    assert.equal(response.body.err.error, 'access_denied');
    assert.equal(
      response.body.err.error_description,
      'Token exchange not allowed',
    );
  });

  it('maps mfa_required AS error to HTTP 401', async () => {
    const { response } = await setup({
      mockTokenResponse: {
        status: 400,
        body: {
          error: 'mfa_required',
          error_description: 'Multifactor authentication required',
        },
      },
    });
    assert.equal(response.statusCode, 401);
    assert.equal(response.body.err.error, 'mfa_required');
    assert.equal(
      response.body.err.error_description,
      'Multifactor authentication required',
    );
  });

  it('throws 400 when caller has no session', async () => {
    const { response } = await setup({
      sessionData: {},
    });
    assert.equal(response.statusCode, 400);
    assert.equal(
      response.body.err.message,
      'subject_token is required for token exchange',
    );
  });
});

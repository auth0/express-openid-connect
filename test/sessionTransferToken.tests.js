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

const SESSION_TRANSFER_TOKEN_IDENTIFIER =
  'urn:auth0:params:oauth:token-type:session_transfer_token';
const ID_TOKEN_IDENTIFIER = 'urn:ietf:params:oauth:token-type:id_token';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
};

const defaultSession = () => ({
  id_token: makeIdToken(),
  access_token: '__test_access_token__',
  token_type: 'Bearer',
  expires_at: Math.floor(Date.now() / 1000) + 86400,
});

const defaultSTTResponse = () => ({
  issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
  access_token: '__test_stt__',
  token_type: 'N_A',
  expires_in: 60,
});

// ---------------------------------------------------------------------------
// requestSessionTransferToken tests
// ---------------------------------------------------------------------------

describe('requestSessionTransferToken', () => {
  let server;

  afterEach(() => {
    nock.cleanAll();
    if (server) {
      server.close();
    }
  });

  const setup = async ({
    authConfig = {},
    sttOptions = {},
    mockTokenResponse = null,
    sessionData = null,
  } = {}) => {
    const config = { ...defaultConfig, ...authConfig };

    const router = express.Router();
    router.use(auth(config));
    router.get('/stt', async (req, res, next) => {
      try {
        const result = await req.oidc.requestSessionTransferToken(sttOptions);
        res.json(result);
      } catch (err) {
        next(err);
      }
    });

    server = await createServer(router);
    const jar = request.jar();

    await request.post('/session', {
      baseUrl,
      jar,
      json: sessionData !== null ? sessionData : defaultSession(),
    });

    let capturedBody;
    if (mockTokenResponse !== false) {
      nock('https://op.example.com')
        .post('/oauth/token')
        .reply(
          mockTokenResponse ? mockTokenResponse.status : 200,
          function (uri, body) {
            capturedBody = qs.parse(body);
            return mockTokenResponse
              ? mockTokenResponse.body
              : defaultSTTResponse();
          },
        );
    }

    const response = await request.get('/stt', { baseUrl, jar, json: true });
    return { response, capturedBody };
  };

  // -------------------------------------------------------------------------
  // Actor resolution
  // -------------------------------------------------------------------------

  it('sources actor_token from the agent session id_token when not explicitly provided', async () => {
    const idToken = makeIdToken();
    const { capturedBody } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
      sessionData: {
        id_token: idToken,
        access_token: '__test_access_token__',
        token_type: 'Bearer',
        expires_at: Math.floor(Date.now() / 1000) + 86400,
      },
    });
    assert.equal(capturedBody.actor_token, idToken);
    assert.equal(capturedBody.actor_token_type, ID_TOKEN_IDENTIFIER);
  });

  it('uses explicit actor_token and actor_token_type when provided', async () => {
    const { capturedBody } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
        actor_token: '__explicit_actor_token__',
        actor_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      },
    });
    assert.equal(capturedBody.actor_token, '__explicit_actor_token__');
    assert.equal(
      capturedBody.actor_token_type,
      'urn:ietf:params:oauth:token-type:access_token',
    );
  });

  it('defaults actor_token_type to id_token URN when actor_token provided without type', async () => {
    const { capturedBody } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
        actor_token: '__explicit_actor_token__',
      },
    });
    assert.equal(capturedBody.actor_token, '__explicit_actor_token__');
    assert.equal(capturedBody.actor_token_type, ID_TOKEN_IDENTIFIER);
  });

  it('throws 400 with actor_unavailable when agent has no session', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
      sessionData: {},
      mockTokenResponse: false,
    });
    assert.equal(response.statusCode, 400);
    assert.equal(response.body.err.error, 'actor_unavailable');
  });

  it('throws 400 with actor_unavailable when explicit actor_token is blank', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
        actor_token: '   ',
      },
      mockTokenResponse: false,
    });
    assert.equal(response.statusCode, 400);
    assert.equal(response.body.err.error, 'actor_unavailable');
  });

  it('throws 400 with actor_unavailable when id_token is expired and no refresh_token', async () => {
    const expiredIdToken = makeIdToken({
      exp: Math.floor(Date.now() / 1000) - 3600,
    });
    const { response } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
      sessionData: {
        id_token: expiredIdToken,
        access_token: '__test_access_token__',
        token_type: 'Bearer',
        expires_at: Math.floor(Date.now() / 1000) - 3600,
      },
      mockTokenResponse: false,
    });
    assert.equal(response.statusCode, 400);
    assert.equal(response.body.err.error, 'actor_unavailable');
  });

  it('refreshes expired id_token and uses the fresh one as actor when refresh_token is available', async () => {
    const expiredIdToken = makeIdToken({
      exp: Math.floor(Date.now() / 1000) - 3600,
    });
    const freshIdToken = makeIdToken();

    const router = express.Router();
    router.use(auth({ ...defaultConfig }));
    router.get('/stt', async (req, res, next) => {
      try {
        const result = await req.oidc.requestSessionTransferToken({
          subject_token: '__test_subject__',
          subject_token_type: 'urn:mycompany:test-token',
        });
        res.json(result);
      } catch (err) {
        next(err);
      }
    });

    server = await createServer(router);
    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: expiredIdToken,
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_at: Math.floor(Date.now() / 1000) - 3600,
      },
    });

    let capturedSttBody;
    // First call: refresh grant; second call: STT exchange
    nock('https://op.example.com')
      .post('/oauth/token')
      .reply(200, {
        access_token: '__new_access_token__',
        id_token: freshIdToken,
        refresh_token: '__new_refresh_token__',
        token_type: 'Bearer',
        expires_in: 86400,
      })
      .post('/oauth/token')
      .reply(200, function (uri, body) {
        capturedSttBody = qs.parse(body);
        return defaultSTTResponse();
      });

    const response = await request.get('/stt', { baseUrl, jar, json: true });
    assert.equal(response.statusCode, 200);
    assert.equal(capturedSttBody.actor_token, freshIdToken);
    assert.equal(capturedSttBody.actor_token_type, ID_TOKEN_IDENTIFIER);
  });

  it('throws 400 with actor_unavailable when refresh succeeds but returns no new id_token', async () => {
    const expiredIdToken = makeIdToken({
      exp: Math.floor(Date.now() / 1000) - 3600,
    });

    const router = express.Router();
    router.use(auth({ ...defaultConfig }));
    router.get('/stt', async (req, res, next) => {
      try {
        const result = await req.oidc.requestSessionTransferToken({
          subject_token: '__test_subject__',
          subject_token_type: 'urn:mycompany:test-token',
        });
        res.json(result);
      } catch (err) {
        next(err);
      }
    });

    server = await createServer(router);
    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: {
        id_token: expiredIdToken,
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        token_type: 'Bearer',
        expires_at: Math.floor(Date.now() / 1000) - 3600,
      },
    });

    // Refresh grant succeeds but returns no new id_token — old expired one is kept
    nock('https://op.example.com').post('/oauth/token').reply(200, {
      access_token: '__new_access_token__',
      token_type: 'Bearer',
      expires_in: 86400,
    });

    const response = await request.get('/stt', { baseUrl, jar, json: true });
    assert.equal(response.statusCode, 400);
    assert.equal(response.body.err.error, 'actor_unavailable');
    assert.match(
      response.body.err.message,
      /refresh did not return a new id_token/,
    );
  });

  // -------------------------------------------------------------------------
  // subject_token validation (reuses validateSubjectToken)
  // -------------------------------------------------------------------------

  it('throws 400 when subject_token is missing', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token_type: 'urn:mycompany:test-token',
      },
      mockTokenResponse: false,
    });
    assert.equal(response.statusCode, 400);
    assert.match(response.body.err.message, /subject_token is required/);
  });

  it('throws 400 when subject_token has leading or trailing whitespace', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: '  token  ',
        subject_token_type: 'urn:mycompany:test-token',
      },
      mockTokenResponse: false,
    });
    assert.equal(response.statusCode, 400);
    assert.match(response.body.err.message, /whitespace/);
  });

  it("throws 400 when subject_token includes a 'Bearer ' prefix", async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: 'Bearer __test__',
        subject_token_type: 'urn:mycompany:test-token',
      },
      mockTokenResponse: false,
    });
    assert.equal(response.statusCode, 400);
    assert.match(response.body.err.message, /Bearer/);
  });

  // -------------------------------------------------------------------------
  // Audience construction
  // -------------------------------------------------------------------------

  it('sets audience to urn:{issuer-hostname}:session_transfer', async () => {
    const { capturedBody } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
    });
    assert.equal(capturedBody.audience, 'urn:op.example.com:session_transfer');
  });

  it('strips protocol from issuerBaseURL when building audience', async () => {
    // The audience must be urn:{hostname}:session_transfer — not including https://
    const { capturedBody } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
    });
    // issuerBaseURL is 'https://op.example.com' → audience must be urn:op.example.com:session_transfer
    assert.notMatch(capturedBody.audience, /https?:\/\//);
    assert.equal(capturedBody.audience, 'urn:op.example.com:session_transfer');
  });

  // -------------------------------------------------------------------------
  // Optional parameters
  // -------------------------------------------------------------------------

  it('sends scope when provided', async () => {
    const { capturedBody } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
        scope: 'openid profile',
      },
    });
    assert.equal(capturedBody.scope, 'openid profile');
  });

  it('sends organization when provided', async () => {
    const { capturedBody } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
        organization: 'org_abc123',
      },
    });
    assert.equal(capturedBody.organization, 'org_abc123');
  });

  it('forwards extra params to the token endpoint', async () => {
    const { capturedBody } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
        extra: { reason: 'Investigating TCK-4821' },
      },
    });
    assert.equal(capturedBody.reason, 'Investigating TCK-4821');
  });

  it('omits scope, organization, and extra when not provided', async () => {
    const { capturedBody } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
    });
    assert.isUndefined(capturedBody.scope);
    assert.isUndefined(capturedBody.organization);
  });

  // -------------------------------------------------------------------------
  // Result shape
  // -------------------------------------------------------------------------

  it('returns session_transfer_token from access_token in response', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
    });
    assert.equal(response.statusCode, 200);
    assert.equal(response.body.session_transfer_token, '__test_stt__');
  });

  it('returns issued_token_type from AS response', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
    });
    assert.equal(
      response.body.issued_token_type,
      SESSION_TRANSFER_TOKEN_IDENTIFIER,
    );
  });

  it('returns empty string for issued_token_type when absent in AS response', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
      mockTokenResponse: {
        status: 200,
        body: {
          access_token: '__test_stt__',
          token_type: 'N_A',
          expires_in: 60,
          // no issued_token_type
        },
      },
    });
    assert.equal(response.statusCode, 200);
    assert.equal(response.body.issued_token_type, '');
  });

  it('result has no access_token field — STT is in session_transfer_token', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
    });
    assert.isUndefined(response.body.access_token);
    assert.isString(response.body.session_transfer_token);
  });

  it('result has no act claim — act is not on the STT response', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
    });
    assert.isUndefined(response.body.act);
  });

  // -------------------------------------------------------------------------
  // STT is never written to the session
  // -------------------------------------------------------------------------

  it('does not persist the STT to the session', async () => {
    const router = express.Router();
    router.use(auth({ ...defaultConfig }));
    router.get('/stt', async (req, res, next) => {
      try {
        await req.oidc.requestSessionTransferToken({
          subject_token: '__test_subject__',
          subject_token_type: 'urn:mycompany:test-token',
        });
        res.json(req.appSession);
      } catch (err) {
        next(err);
      }
    });

    server = await createServer(router);
    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: defaultSession(),
    });

    nock('https://op.example.com')
      .post('/oauth/token')
      .reply(200, defaultSTTResponse());

    const response = await request.get('/stt', { baseUrl, jar, json: true });
    assert.equal(response.statusCode, 200);
    assert.notProperty(response.body, 'session_transfer_token');
    assert.notProperty(response.body, 'issued_token_type');
  });

  // -------------------------------------------------------------------------
  // Server-side error mapping
  // -------------------------------------------------------------------------

  it('propagates setactor_required AS 400 as HTTP 400', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
      mockTokenResponse: {
        status: 400,
        body: {
          error: 'setactor_required',
          error_description:
            'setActor is required when requesting a session transfer token via token exchange.',
        },
      },
    });
    assert.equal(response.statusCode, 400);
    assert.equal(response.body.err.error, 'setactor_required');
  });

  it('propagates session_transfer_disabled AS 400 as HTTP 400', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
      mockTokenResponse: {
        status: 400,
        body: {
          error: 'session_transfer_disabled',
          error_description:
            'Session Transfer Tokens cannot be requested using Custom Token Exchange.',
        },
      },
    });
    assert.equal(response.statusCode, 400);
    assert.equal(response.body.err.error, 'session_transfer_disabled');
  });

  it('propagates generic AS errors as HTTP 400', async () => {
    const { response } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
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
  });

  // -------------------------------------------------------------------------
  // grant_type wired correctly
  // -------------------------------------------------------------------------

  it('uses token-exchange grant_type', async () => {
    const { capturedBody } = await setup({
      sttOptions: {
        subject_token: '__test_subject__',
        subject_token_type: 'urn:mycompany:test-token',
      },
    });
    assert.equal(
      capturedBody.grant_type,
      'urn:ietf:params:oauth:grant-type:token-exchange',
    );
  });
});

// ---------------------------------------------------------------------------
// buildSessionTransferRedirect tests
// ---------------------------------------------------------------------------

describe('buildSessionTransferRedirect', () => {
  let server;

  afterEach(() => {
    if (server) {
      server.close();
    }
  });

  const setupRedirect = async (targetLoginUrl, result, opts) => {
    const router = express.Router();
    router.use(auth({ ...defaultConfig }));
    router.get('/redirect', async (req, res, next) => {
      try {
        const url = req.oidc.buildSessionTransferRedirect(
          targetLoginUrl,
          result,
          opts,
        );
        res.json({ url });
      } catch (err) {
        next(err);
      }
    });

    server = await createServer(router);
    const jar = request.jar();
    await request.post('/session', {
      baseUrl,
      jar,
      json: defaultSession(),
    });

    return request.get('/redirect', { baseUrl, jar, json: true });
  };

  it('appends session_transfer_token as a query param', async () => {
    const response = await setupRedirect('https://app.example.com/login', {
      session_transfer_token: '__test_stt__',
      issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
    });
    assert.equal(response.statusCode, 200);
    const redirectUrl = new URL(response.body.url);
    assert.equal(
      redirectUrl.searchParams.get('session_transfer_token'),
      '__test_stt__',
    );
  });

  it('URL-encodes the STT', async () => {
    const sttWithSpecialChars = 'abc+def/ghi=';
    const response = await setupRedirect('https://app.example.com/login', {
      session_transfer_token: sttWithSpecialChars,
      issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
    });
    assert.equal(response.statusCode, 200);
    const redirectUrl = new URL(response.body.url);
    assert.equal(
      redirectUrl.searchParams.get('session_transfer_token'),
      sttWithSpecialChars,
    );
  });

  it('appends organization when provided in opts', async () => {
    const response = await setupRedirect(
      'https://app.example.com/login',
      {
        session_transfer_token: '__test_stt__',
        issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
      },
      { organization: 'org_globex' },
    );
    assert.equal(response.statusCode, 200);
    const redirectUrl = new URL(response.body.url);
    assert.equal(redirectUrl.searchParams.get('organization'), 'org_globex');
    assert.equal(
      redirectUrl.searchParams.get('session_transfer_token'),
      '__test_stt__',
    );
  });

  it('does not append organization when not provided', async () => {
    const response = await setupRedirect('https://app.example.com/login', {
      session_transfer_token: '__test_stt__',
      issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
    });
    assert.equal(response.statusCode, 200);
    const redirectUrl = new URL(response.body.url);
    assert.isNull(redirectUrl.searchParams.get('organization'));
  });

  it('preserves existing query params on targetLoginUrl', async () => {
    const response = await setupRedirect(
      'https://app.example.com/login?foo=bar',
      {
        session_transfer_token: '__test_stt__',
        issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
      },
    );
    assert.equal(response.statusCode, 200);
    const redirectUrl = new URL(response.body.url);
    assert.equal(redirectUrl.searchParams.get('foo'), 'bar');
    assert.equal(
      redirectUrl.searchParams.get('session_transfer_token'),
      '__test_stt__',
    );
  });

  it('throws TypeError when targetLoginUrl is null', async () => {
    const response = await setupRedirect(null, {
      session_transfer_token: '__test_stt__',
      issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
    });
    assert.equal(response.statusCode, 500);
    assert.match(
      response.body.err.message,
      /targetLoginUrl must be a valid URL/,
    );
  });

  it('throws TypeError when targetLoginUrl is whitespace only', async () => {
    const response = await setupRedirect('   ', {
      session_transfer_token: '__test_stt__',
      issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
    });
    assert.equal(response.statusCode, 500);
    assert.match(
      response.body.err.message,
      /targetLoginUrl must be a valid URL/,
    );
  });

  it('throws TypeError when targetLoginUrl is not a valid URL', async () => {
    const response = await setupRedirect('not-a-valid-url', {
      session_transfer_token: '__test_stt__',
      issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
    });
    assert.equal(response.statusCode, 500);
    assert.match(
      response.body.err.message,
      /targetLoginUrl must be a valid URL/,
    );
  });

  it('throws TypeError when organization is not a string', async () => {
    const response = await setupRedirect(
      'https://app.example.com/login',
      {
        session_transfer_token: '__test_stt__',
        issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
      },
      { organization: 123 },
    );
    assert.equal(response.statusCode, 500);
    assert.match(
      response.body.err.message,
      /organization must be a non-empty string/,
    );
  });

  it('throws TypeError when organization is a blank string', async () => {
    const response = await setupRedirect(
      'https://app.example.com/login',
      {
        session_transfer_token: '__test_stt__',
        issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
      },
      { organization: '   ' },
    );
    assert.equal(response.statusCode, 500);
    assert.match(
      response.body.err.message,
      /organization must be a non-empty string/,
    );
  });

  it('throws TypeError when result has wrong issued_token_type', async () => {
    const response = await setupRedirect('https://app.example.com/login', {
      session_transfer_token: '__test_stt__',
      issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    });
    assert.equal(response.statusCode, 500);
    assert.match(response.body.err.message, /issued_token_type/);
  });

  it('throws TypeError when result has no issued_token_type', async () => {
    const response = await setupRedirect('https://app.example.com/login', {
      session_transfer_token: '__test_stt__',
    });
    assert.equal(response.statusCode, 500);
    assert.match(response.body.err.message, /issued_token_type/);
  });

  it('throws TypeError when result has no session_transfer_token', async () => {
    const response = await setupRedirect('https://app.example.com/login', {
      issued_token_type: SESSION_TRANSFER_TOKEN_IDENTIFIER,
    });
    assert.equal(response.statusCode, 500);
    assert.match(
      response.body.err.message,
      /result must be a SessionTransferTokenResult with a session_transfer_token/,
    );
  });
});

const { assert } = require('chai');
const url = require('url');
const nock = require('nock');
const express = require('express');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
});

const { auth } = require('../..');
const { create: createServer } = require('../fixture/server');

const baseUrl = 'http://localhost:3000';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
  anonymousSession: { enabled: true },
};

const tokenResponse = {
  access_token: '__access_token__',
  session_token: '__session_token__',
  token_type: 'Bearer',
  expires_in: 604800,
  session_expires_in: 2592000,
};

describe('anonymousSession integration', () => {
  let server;

  afterEach(() => {
    nock.cleanAll();
    if (server) server.close();
  });

  const setup = async (config = defaultConfig) => {
    const router = express.Router();
    router.use(auth(config));
    router.get('/anon', async (req, res, next) => {
      try {
        res.json({
          isAnonymous: req.anonymousSession.isAnonymous,
          token: req.anonymousSession.token,
        });
      } catch (err) {
        next(err);
      }
    });
    router.get('/anon/start', async (req, res, next) => {
      try {
        const at = await req.anonymousSession.start({
          audience: 'https://api.example.com',
        });
        res.json(at);
      } catch (err) {
        next(err);
      }
    });
    server = await createServer(router);
  };

  it('attaches req.anonymousSession when enabled', async () => {
    await setup();
    const res = await request.get('/anon', { baseUrl, json: true });
    assert.deepEqual(res.body, { isAnonymous: false, token: null });
  });

  it('does not attach req.anonymousSession when disabled', async () => {
    await setup({ ...defaultConfig, anonymousSession: { enabled: false } });
    const res = await request.get('/anon', { baseUrl });
    // req.anonymousSession is undefined -> reading .isAnonymous throws -> 500
    assert.equal(res.statusCode, 500);
  });

  it('start() sets the encrypted auth0_anon cookie on the response', async () => {
    await setup();
    nock('https://op.example.com')
      .post('/anonymous/token')
      .reply(200, tokenResponse);

    const res = await request.get('/anon/start', { baseUrl, json: true });

    assert.equal(res.body.access_token, '__access_token__');
    const setCookie = res.headers['set-cookie'].join(';');
    assert.include(setCookie, 'auth0_anon=');
  });

  it('persisted cookie makes a subsequent request anonymous', async () => {
    await setup();
    nock('https://op.example.com')
      .post('/anonymous/token')
      .reply(200, tokenResponse);

    const jar = request.jar();
    await request.get('/anon/start', { baseUrl, jar, json: true });
    const res = await request.get('/anon', { baseUrl, jar, json: true });

    assert.isTrue(res.body.isAnonymous);
    assert.equal(res.body.token, '__session_token__');
  });

  it('injects session_token into the authorize URL on login', async () => {
    await setup();
    nock('https://op.example.com')
      .post('/anonymous/token')
      .reply(200, tokenResponse);

    const jar = request.jar();
    await request.get('/anon/start', { baseUrl, jar, json: true });

    const res = await request.get('/login', {
      baseUrl,
      jar,
      followRedirect: false,
    });
    const parsed = url.parse(res.headers.location, true);
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.query.session_token, '__session_token__');
  });

  it('does not add session_token to the authorize URL without a session', async () => {
    await setup();
    const res = await request.get('/login', { baseUrl, followRedirect: false });
    const parsed = url.parse(res.headers.location, true);
    assert.equal(parsed.pathname, '/authorize');
    assert.notProperty(parsed.query, 'session_token');
  });
});

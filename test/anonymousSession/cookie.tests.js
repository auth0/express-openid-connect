'use strict';

const { assert } = require('chai');
const { get: getConfig } = require('../../lib/config');
const makeCookieHandler = require('../../lib/anonymousSession/cookie');

const baseConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org',
  authRequired: false,
  anonymousSession: { enabled: true },
};

const state = {
  session_token: '__session_token__',
  access_token: '__access_token__',
  token_type: 'Bearer',
  expires_at: 1800000000,
  session_expires_at: 1900000000,
  audience: 'https://api.example.com',
  scope: 'read:cart',
};

// Minimal req/res doubles capturing cookie I/O.
const makeReq = (cookieHeader = '') => ({
  get: (name) => (name.toLowerCase() === 'cookie' ? cookieHeader : undefined),
});

const makeRes = () => {
  const set = [];
  const cleared = [];
  return {
    set,
    cleared,
    cookie: (name, value, options) => set.push({ name, value, options }),
    clearCookie: (name, options) => cleared.push({ name, options }),
  };
};

describe('anonymousSession cookie', () => {
  it('round-trips state through write then read', async () => {
    const handler = makeCookieHandler(getConfig(baseConfig));
    const res = makeRes();

    handler.write(res, state);
    assert.lengthOf(res.set, 1);
    assert.equal(res.set[0].name, 'auth0_anon');

    const req = makeReq(`auth0_anon=${res.set[0].value}`);
    const decrypted = await handler.read(req);
    assert.deepEqual(decrypted, state);
  });

  it('returns null when there is no cookie', async () => {
    const handler = makeCookieHandler(getConfig(baseConfig));
    assert.isNull(await handler.read(makeReq('')));
  });

  it('returns null when the cookie cannot be decrypted', async () => {
    const handler = makeCookieHandler(getConfig(baseConfig));
    const req = makeReq('auth0_anon=not-a-valid-jwe');
    assert.isNull(await handler.read(req));
  });

  it('sets cookie expiry from session_expires_at', async () => {
    const handler = makeCookieHandler(getConfig(baseConfig));
    const res = makeRes();

    handler.write(res, state);
    assert.deepEqual(
      res.set[0].options.expires,
      new Date(state.session_expires_at * 1000),
    );
  });

  it('honors a custom cookie name', async () => {
    const config = getConfig({
      ...baseConfig,
      anonymousSession: { enabled: true, cookie: { name: 'custom_anon' } },
    });
    const handler = makeCookieHandler(config);
    const res = makeRes();

    handler.write(res, state);
    assert.equal(res.set[0].name, 'custom_anon');
  });

  it('clears the cookie with the configured attributes', () => {
    const config = getConfig({
      ...baseConfig,
      anonymousSession: {
        enabled: true,
        cookie: { name: 'auth0_anon', sameSite: 'None', domain: 'example.org' },
      },
    });
    const handler = makeCookieHandler(config);
    const res = makeRes();

    handler.clear(res);
    assert.lengthOf(res.cleared, 1);
    assert.equal(res.cleared[0].name, 'auth0_anon');
    assert.equal(res.cleared[0].options.sameSite, 'None');
    assert.equal(res.cleared[0].options.domain, 'example.org');
  });
});

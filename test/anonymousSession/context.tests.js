'use strict';

const { assert } = require('chai');
const nock = require('nock');
const { get: getConfig } = require('../../lib/config');
const {
  RequestAnonymousContext,
  flush,
} = require('../../lib/anonymousSession/context');
const { AnonymousSessionError } = require('../../lib/anonymousSession/errors');
const { epoch } = require('../../lib/utils/epoch');

const baseConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org',
  authRequired: false,
  anonymousSession: { enabled: true },
};

const tokenResponse = (overrides = {}) => ({
  access_token: '__access_token__',
  session_token: '__session_token__',
  token_type: 'Bearer',
  expires_in: 604800,
  session_expires_in: 2592000,
  ...overrides,
});

const mockToken = (assertBody) =>
  nock('https://op.example.com').post('/anonymous/token', (body) => {
    if (assertBody) assertBody(body);
    return true;
  });

const config = () => getConfig(baseConfig);

// Build a context seeded with existing cookie state.
const withState = (state) => new RequestAnonymousContext(config(), state);

const validState = (overrides = {}) => ({
  session_token: '__session_token__',
  access_token: '__access_token__',
  token_type: 'Bearer',
  expires_at: epoch() + 3600,
  session_expires_at: epoch() + 2592000,
  audience: 'https://api.example.com',
  scope: 'read:cart',
  ...overrides,
});

describe('anonymousSession context', () => {
  afterEach(() => nock.cleanAll());

  describe('read accessors', () => {
    it('isAnonymous is false and token is null with no state', () => {
      const ctx = new RequestAnonymousContext(config(), null);
      assert.isFalse(ctx.isAnonymous);
      assert.isNull(ctx.token);
    });

    it('isAnonymous is true and token returns the session token with state', () => {
      const ctx = withState(validState());
      assert.isTrue(ctx.isAnonymous);
      assert.equal(ctx.token, '__session_token__');
    });
  });

  describe('start', () => {
    it('creates a session and returns the access token', async () => {
      let body;
      mockToken((b) => (body = b)).reply(200, tokenResponse());
      const ctx = new RequestAnonymousContext(config(), null);

      const at = await ctx.start({
        audience: 'https://api.example.com',
        scope: 'read:cart',
        metadata: { cart_id: 'c1' },
      });

      assert.equal(at.access_token, '__access_token__');
      assert.equal(at.token_type, 'Bearer');
      assert.isAbove(at.expires_in, 0);
      assert.equal(body.audience, 'https://api.example.com');
      assert.deepEqual(body.metadata, { cart_id: 'c1' });
      assert.isTrue(ctx.isAnonymous);
    });
  });

  describe('getAccessToken', () => {
    it('throws when there is no active session', async () => {
      const ctx = new RequestAnonymousContext(config(), null);
      const err = await ctx.getAccessToken().then(
        () => null,
        (e) => e,
      );
      assert.instanceOf(err, AnonymousSessionError);
      assert.equal(err.code, 'no_active_session');
    });

    it('returns the cached token when still valid (no network call)', async () => {
      // A one-shot mock that must NOT be consumed if the cache is used.
      const scope = mockToken().reply(200, tokenResponse());
      const ctx = withState(validState());

      const at = await ctx.getAccessToken();

      assert.equal(at.access_token, '__access_token__');
      assert.isFalse(scope.isDone(), 'should not call the token endpoint');
    });

    it('renews using the session token when the access token is expired', async () => {
      let body;
      mockToken((b) => (body = b)).reply(
        200,
        tokenResponse({
          access_token: '__renewed__',
          session_token: undefined,
        }),
      );
      const ctx = withState(validState({ expires_at: epoch() - 10 }));

      const at = await ctx.getAccessToken();

      assert.equal(at.access_token, '__renewed__');
      assert.equal(body.session_token, '__session_token__');
      assert.equal(body.audience, 'https://api.example.com');
    });

    it('preserves session_expires_at across a renewal (no lifetime extension)', async () => {
      mockToken().reply(
        200,
        tokenResponse({
          access_token: '__renewed__',
          session_token: undefined,
        }),
      );
      const original = validState({ expires_at: epoch() - 10 });
      const ctx = withState({ ...original });

      await ctx.getAccessToken();
      const res = captureWrite(ctx);
      assert.equal(res.session_expires_at, original.session_expires_at);
    });

    it('creates a new session silently when the session token is expired', async () => {
      let calls = 0;
      nock('https://op.example.com')
        .post('/anonymous/token')
        .times(2)
        .reply(function () {
          calls += 1;
          if (calls === 1) {
            return [400, { error: 'session_expired' }];
          }
          return [200, tokenResponse({ access_token: '__new_session_at__' })];
        });

      const ctx = withState(validState({ expires_at: epoch() - 10 }));
      const at = await ctx.getAccessToken();

      assert.equal(at.access_token, '__new_session_at__');
      assert.equal(calls, 2);
    });

    it('rethrows non-silent errors during renewal', async () => {
      nock('https://op.example.com')
        .post('/anonymous/token')
        .reply(500, { error: 'server_error' });

      const ctx = withState(validState({ expires_at: epoch() - 10 }));
      const err = await ctx.getAccessToken().then(
        () => null,
        (e) => e,
      );

      assert.instanceOf(err, AnonymousSessionError);
      assert.equal(err.code, 'server_error');
    });
  });

  describe('end', () => {
    it('calls logout and clears the session state', async () => {
      const scope = nock('https://op.example.com')
        .post('/anonymous/logout')
        .reply(200, {});
      const ctx = withState(validState());

      await ctx.end();

      assert.isTrue(scope.isDone());
      assert.isFalse(ctx.isAnonymous);
      assert.isNull(ctx.token);
    });

    it('clears state even if logout fails', async () => {
      nock('https://op.example.com')
        .post('/anonymous/logout')
        .reply(500, { error: 'server_error' });
      const ctx = withState(validState());

      await ctx.end();

      assert.isFalse(ctx.isAnonymous);
    });
  });

  describe('flush', () => {
    it('writes the cookie after start', async () => {
      mockToken().reply(200, tokenResponse());
      const ctx = new RequestAnonymousContext(config(), null);
      await ctx.start({ audience: 'https://api.example.com' });

      const written = captureWrite(ctx);
      assert.equal(written.access_token, '__access_token__');
    });

    it('clears the cookie after end', async () => {
      nock('https://op.example.com').post('/anonymous/logout').reply(200, {});
      const ctx = withState(validState());
      await ctx.end();

      let cleared = false;
      const handler = { write: () => {}, clear: () => (cleared = true) };
      flush(ctx, {}, handler);
      assert.isTrue(cleared);
    });

    it('does nothing when no change is pending', () => {
      const ctx = withState(validState());
      let touched = false;
      const handler = {
        write: () => (touched = true),
        clear: () => (touched = true),
      };
      flush(ctx, {}, handler);
      assert.isFalse(touched);
    });
  });
});

// Runs flush against a capturing cookie handler and returns the written state.
function captureWrite(ctx) {
  let written;
  const handler = {
    write: (res, state) => (written = state),
    clear: () => {},
  };
  flush(ctx, {}, handler);
  return written;
}

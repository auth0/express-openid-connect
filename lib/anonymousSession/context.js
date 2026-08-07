const weakRef = require('../weakCache');
const { requestToken, logout } = require('./client');
const { AnonymousSessionError } = require('./errors');
const { epoch } = require('../utils/epoch');
const debug = require('../debug')('anonymousSession');

const WRITE = 'write';
const CLEAR = 'clear';

// Session-token errors that must never surface to the developer; a fresh
// anonymous session is created transparently instead (metadata is lost).
const SILENT_CODES = ['session_expired', 'invalid_session_token'];

/**
 * Shapes the internal cookie state into the public access-token object.
 * A plain token object — unlike `req.oidc.accessToken`, there is no `refresh()`
 * (anonymous sessions have no refresh token; `getAccessToken()` renews itself).
 */
function toAccessToken(state) {
  return {
    access_token: state.access_token,
    token_type: state.token_type,
    expires_in: Math.max(0, state.expires_at - epoch()),
    isExpired: () => state.expires_at <= epoch(),
  };
}

/**
 * Builds the cookie state from an `/anonymous/token` response.
 *
 * On renewal the response omits `session_token` (keep the previous one) and the
 * anonymous session lifetime is not extended, so `session_expires_at` is
 * preserved from the previous state (NFR1). A brand-new session (no `prev`)
 * takes a fresh `session_expires_at` from the response.
 */
function stateFromResponse(response, { audience, scope }, prev) {
  const now = epoch();
  return {
    session_token: response.session_token || prev?.session_token,
    access_token: response.access_token,
    token_type: response.token_type,
    expires_at: now + response.expires_in,
    session_expires_at:
      prev?.session_expires_at ??
      (response.session_expires_in
        ? now + response.session_expires_in
        : undefined),
    audience,
    scope,
  };
}

/**
 * The anonymous session context attached to the request as
 * `req.anonymousSession` when `anonymousSession.enabled` is `true`.
 *
 * Reads are served from the decrypted cookie state loaded by the middleware.
 * `start`, `getAccessToken`, and `end` mutate that state and mark the cookie
 * dirty; the middleware persists it in an `onHeaders` hook (see `flush`), so no
 * method here writes to the response directly.
 */
class RequestAnonymousContext {
  constructor(config, state) {
    Object.assign(weakRef(this), { config, state, pending: null });
  }

  get isAnonymous() {
    const { state } = weakRef(this);
    return !!(state && state.session_token);
  }

  get token() {
    const { state } = weakRef(this);
    return state?.session_token ?? null;
  }

  /**
   * Creates a new anonymous session and returns its access token. The audience
   * and scope are fixed for the lifetime of the session.
   */
  async start({ audience, scope, metadata } = {}) {
    const ctx = weakRef(this);
    const response = await requestToken(ctx.config, {
      audience,
      scope,
      metadata,
    });
    ctx.state = stateFromResponse(response, { audience, scope });
    ctx.pending = WRITE;
    return toAccessToken(ctx.state);
  }

  /**
   * Returns a valid access token for the session's audience. Returns the cached
   * token when still valid, otherwise renews it. If the session token has
   * expired, a new session is created transparently.
   */
  async getAccessToken() {
    const ctx = weakRef(this);
    if (!this.isAnonymous) {
      throw new AnonymousSessionError(
        'no active anonymous session',
        'no_active_session',
      );
    }
    if (ctx.state.expires_at > epoch()) {
      return toAccessToken(ctx.state);
    }
    return renew.call(this);
  }

  /**
   * Ends the anonymous session (`POST /anonymous/logout`) and clears the cookie.
   */
  async end() {
    const ctx = weakRef(this);
    if (ctx.state?.session_token) {
      try {
        await logout(ctx.config, ctx.state.session_token);
      } catch (err) {
        // Best-effort: the cookie is cleared regardless.
        debug('logout failed: %s', err);
      }
    }
    ctx.state = null;
    ctx.pending = CLEAR;
  }
}

/**
 * Re-mints the access token from the stored session token. If the session token
 * has expired or is invalid, silently creates a brand-new session instead.
 */
async function renew() {
  const ctx = weakRef(this);
  const { session_token, audience, scope } = ctx.state;

  let response;
  try {
    response = await requestToken(ctx.config, {
      session_token,
      audience,
      scope,
    });
    ctx.state = stateFromResponse(response, { audience, scope }, ctx.state);
  } catch (err) {
    if (!SILENT_CODES.includes(err.code)) {
      throw err;
    }
    debug('session token %s, creating a new session', err.code);
    response = await requestToken(ctx.config, { audience, scope });
    ctx.state = stateFromResponse(response, { audience, scope });
  }

  ctx.pending = WRITE;
  return toAccessToken(ctx.state);
}

/**
 * Persists any pending cookie change to the response. Called by the middleware
 * from an `onHeaders` hook, so `req`-side methods never touch `res` directly.
 */
function flush(anonymousSession, res, cookieHandler) {
  const ctx = weakRef(anonymousSession);
  if (ctx.pending === WRITE) {
    cookieHandler.write(res, ctx.state);
  } else if (ctx.pending === CLEAR) {
    cookieHandler.clear(res);
  }
}

module.exports = { RequestAnonymousContext, flush };

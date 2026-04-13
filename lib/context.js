const url = require('url');
const urlJoin = require('url-join');
const { JWT } = require('jose');
const { TokenSet } = require('openid-client');
const clone = require('clone');

const { strict: assert } = require('assert');
const createError = require('http-errors');

const debug = require('./debug')('context');
const { once } = require('./once');
const { get: getClient } = require('./client');
const { encodeState, decodeState } = require('../lib/hooks/getLoginState');
const onLogin = require('./hooks/backchannelLogout/onLogIn');
const onLogoutToken = require('./hooks/backchannelLogout/onLogoutToken');
const {
  cancelSilentLogin,
  resumeSilentLogin,
} = require('../middleware/attemptSilentLogin');
const weakRef = require('./weakCache');
const {
  regenerateSessionStoreId,
  replaceSession,
} = require('../lib/appSession');

const TOKEN_EXCHANGE_GRANT_TYPE =
  'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_EXCHANGE_IDENTIFIER =
  'urn:ietf:params:oauth:token-type:access_token';

/**
 * OAuth parameter denylist — parameters that cannot be overridden via extras.
 *
 * Two categories:
 *
 * 1. SDK-controlled: params the SDK always sets internally, overriding would break
 *    OAuth protocol integrity or client authentication.
 *    - grant_type, client_id, client_secret, client_assertion, client_assertion_type
 *
 * 2. First-class params: params explicitly managed by the customTokenExchange API
 *    - subject_token, subject_token_type, audience, scope
 *
 * All other parameters — including RFC 8693 optional params (requested_token_type,
 * actor_token, actor_token_type), RFC 8707 resource indicators, and IdP-specific
 * params (connection, organization, login_hint) — are intentionally NOT blocked so they can be
 * passed freely via the `extra` option.
 */
const PARAM_DENYLIST = Object.freeze(
  new Set([
    'grant_type',
    'client_id',
    'client_secret',
    'client_assertion',
    'client_assertion_type',
    'subject_token',
    'subject_token_type',
    'audience',
    'aud',
    'scope',
  ]),
);

function validateTokenExchangeExtras(extra) {
  if (!extra) return {};
  const result = {};
  for (const [k, v] of Object.entries(extra)) {
    if (PARAM_DENYLIST.has(k)) {
      debug('customTokenExchange: extra param "%s" ignored (in denylist)', k);
    } else {
      result[k] = v;
    }
  }
  return result;
}

function isExpired() {
  return tokenSet.call(this).expired();
}

async function refresh({ tokenEndpointParams } = {}) {
  let { config, req } = weakRef(this);
  const { client, issuer } = await getClient(config);
  const oldTokenSet = tokenSet.call(this);

  let extras;
  if (config.tokenEndpointParams || tokenEndpointParams) {
    extras = {
      exchangeBody: { ...config.tokenEndpointParams, ...tokenEndpointParams },
    };
  }

  const newTokenSet = await client.refresh(oldTokenSet, {
    ...extras,
    clientAssertionPayload: {
      aud: issuer.issuer,
    },
  });

  // Update the session
  const session = req[config.session.name];
  Object.assign(session, {
    access_token: newTokenSet.access_token,
    // If no new ID token assume the current ID token is valid.
    id_token: newTokenSet.id_token || oldTokenSet.id_token,
    // If no new refresh token assume the current refresh token is valid.
    refresh_token: newTokenSet.refresh_token || oldTokenSet.refresh_token,
    token_type: newTokenSet.token_type,
    expires_at: newTokenSet.expires_at,
  });

  // Delete the old token set
  const cachedTokenSet = weakRef(session);
  delete cachedTokenSet.value;

  return this.accessToken;
}

function tokenSet() {
  const contextCache = weakRef(this);
  const session = contextCache.req[contextCache.config.session.name];

  if (!session || !('id_token' in session)) {
    return undefined;
  }

  const cachedTokenSet = weakRef(session);

  if (!('value' in cachedTokenSet)) {
    const { id_token, access_token, refresh_token, token_type, expires_at } =
      session;
    cachedTokenSet.value = new TokenSet({
      id_token,
      access_token,
      refresh_token,
      token_type,
      expires_at,
    });
  }

  return cachedTokenSet.value;
}

class RequestContext {
  constructor(config, req, res, next) {
    Object.assign(weakRef(this), { config, req, res, next });
  }

  isAuthenticated() {
    return !!this.idTokenClaims;
  }

  get idToken() {
    try {
      return tokenSet.call(this).id_token;
    } catch {
      return undefined;
    }
  }

  get refreshToken() {
    try {
      return tokenSet.call(this).refresh_token;
    } catch {
      return undefined;
    }
  }

  get accessToken() {
    try {
      const { access_token, token_type, expires_in } = tokenSet.call(this);

      if (!access_token || !token_type || typeof expires_in !== 'number') {
        return undefined;
      }

      return {
        access_token,
        token_type,
        expires_in,
        isExpired: isExpired.bind(this),
        refresh: refresh.bind(this),
      };
    } catch {
      return undefined;
    }
  }

  get idTokenClaims() {
    try {
      const {
        config: { session },
        req,
      } = weakRef(this);

      // The ID Token from Auth0's Refresh Grant doesn't contain a "sid"
      // so we should check the backup sid we stored at login.
      const { sid } = req[session.name];
      return { sid, ...clone(tokenSet.call(this).claims()) };
    } catch {
      return undefined;
    }
  }

  get user() {
    try {
      const {
        config: { identityClaimFilter },
      } = weakRef(this);
      const { idTokenClaims } = this;
      const user = clone(idTokenClaims);
      identityClaimFilter.forEach((claim) => {
        delete user[claim];
      });
      return user;
    } catch {
      return undefined;
    }
  }

  async fetchUserInfo() {
    const { config } = weakRef(this);

    const { client } = await getClient(config);
    return client.userinfo(tokenSet.call(this));
  }

  async customTokenExchange(options = {}) {
    const { config } = weakRef(this);
    const { audience: defaultAudience, scope: defaultScope } =
      config.authorizationParams;

    const {
      subject_token = this.accessToken && this.accessToken.access_token,
      subject_token_type = ACCESS_TOKEN_EXCHANGE_IDENTIFIER,
      audience = defaultAudience,
      scope = defaultScope,
      extra,
    } = options;

    if (!subject_token) {
      throw createError(400, 'subject_token is required for token exchange');
    }

    debug('customTokenExchange() audience=%s scope=%s', audience, scope);

    const { client, issuer } = await getClient(config);

    const body = {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token,
      subject_token_type,
      ...(audience !== undefined && { audience }),
      ...(scope !== undefined && { scope }),
      ...validateTokenExchangeExtras(extra),
    };

    try {
      const exchanged = await client.grant(body, {
        clientAssertionPayload: {
          aud: issuer.issuer,
        },
      });
      return Object.assign({}, exchanged);
    } catch (error) {
      debug(
        'customTokenExchange() failed: %s - %s',
        error.error,
        error.error_description,
      );
      const status = error.error === 'mfa_required' ? 401 : 400;
      throw createError(status, error.message, {
        error: error.error,
        error_description: error.error_description,
      });
    }
  }
}

class ResponseContext {
  constructor(config, req, res, next, transient) {
    Object.assign(weakRef(this), { config, req, res, next, transient });
  }

  get errorOnRequiredAuth() {
    return weakRef(this).config.errorOnRequiredAuth;
  }

  getRedirectUri() {
    const { config } = weakRef(this);
    if (config.routes.callback) {
      return urlJoin(config.baseURL, config.routes.callback);
    }
  }

  silentLogin(options = {}) {
    return this.login({
      ...options,
      silent: true,
      authorizationParams: { ...options.authorizationParams, prompt: 'none' },
    });
  }

  async login(options = {}) {
    let { config, req, res, next, transient } = weakRef(this);
    next = once(next);
    try {
      const { client, issuer } = await getClient(config);

      // Set default returnTo value, allow passed-in options to override or use originalUrl on GET
      let returnTo = config.baseURL;
      if (options.returnTo) {
        returnTo = options.returnTo;
        debug('req.oidc.login() called with returnTo: %s', returnTo);
      } else if (req.method === 'GET' && req.originalUrl) {
        // Collapse any leading slashes to a single slash to prevent Open Redirects
        returnTo = req.originalUrl.replace(/^\/+/, '/');
        debug('req.oidc.login() without returnTo, using: %s', returnTo);
      }

      options = {
        authorizationParams: {},
        returnTo,
        ...options,
      };

      // Ensure a redirect_uri, merge in configuration options, then passed-in options.
      options.authorizationParams = {
        redirect_uri: this.getRedirectUri(),
        ...config.authorizationParams,
        ...options.authorizationParams,
      };

      const stateValue = await config.getLoginState(req, options);
      if (typeof stateValue !== 'object') {
        next(new Error('Custom state value must be an object.'));
      }

      if (options.silent) {
        stateValue.attemptingSilentLogin = true;
      }

      const validResponseTypes = ['id_token', 'code id_token', 'code'];
      assert(
        validResponseTypes.includes(options.authorizationParams.response_type),
        `response_type should be one of ${validResponseTypes.join(', ')}`,
      );
      assert(
        /\bopenid\b/.test(options.authorizationParams.scope),
        'scope should contain "openid"',
      );

      const authVerification = {
        nonce: transient.generateNonce(),
        state: encodeState(stateValue),
        ...(options.authorizationParams.max_age
          ? {
              max_age: options.authorizationParams.max_age,
            }
          : undefined),
      };

      let authParams = {
        ...options.authorizationParams,
        ...authVerification,
      };

      const usePKCE =
        options.authorizationParams.response_type.includes('code');
      if (usePKCE) {
        debug(
          'response_type includes code, the authorization request will use PKCE',
        );
        authVerification.code_verifier = transient.generateCodeVerifier();

        authParams.code_challenge_method = 'S256';
        authParams.code_challenge = transient.calculateCodeChallenge(
          authVerification.code_verifier,
        );
      }

      if (config.pushedAuthorizationRequests) {
        const { request_uri } = await client.pushedAuthorizationRequest(
          authParams,
          {
            clientAssertionPayload: {
              aud: issuer.issuer,
            },
          },
        );
        authParams = { request_uri };
      }

      transient.store(config.transactionCookie.name, req, res, {
        sameSite:
          options.authorizationParams.response_mode === 'form_post'
            ? 'None'
            : config.transactionCookie.sameSite,
        value: JSON.stringify(authVerification),
      });

      const authorizationUrl = client.authorizationUrl(authParams);
      debug('redirecting to %s', authorizationUrl);
      res.redirect(authorizationUrl);
    } catch (err) {
      next(err);
    }
  }

  async logout(params = {}) {
    let { config, req, res, next } = weakRef(this);
    next = once(next);
    let returnURL = params.returnTo || config.routes.postLogoutRedirect;
    debug('req.oidc.logout() with return url: %s', returnURL);

    try {
      const { client } = await getClient(config);

      /**
       * Generates the logout URL.
       *
       * Depending on the configuration, this function will either perform a local only logout
       * or a federated logout by redirecting to the appropriate URL.
       *
       * @param {string} idTokenHint - The ID token hint to be used for the logout request.
       * @returns {string} The URL to redirect the user to for logout.
       */
      const getLogoutUrl = (idTokenHint) => {
        // if idpLogout is not configured, perform a local only logout
        if (!config.idpLogout) {
          debug('performing a local only logout, redirecting to %s', returnURL);
          return returnURL;
        }

        // if idpLogout is configured, perform a federated logout
        return client.endSessionUrl({
          ...config.logoutParams,
          ...(idTokenHint && { id_token_hint: idTokenHint }),
          post_logout_redirect_uri: returnURL,
          ...params.logoutParams,
        });
      };

      if (url.parse(returnURL).host === null) {
        returnURL = urlJoin(config.baseURL, returnURL);
      }

      cancelSilentLogin(req, res);

      if (!req.oidc.isAuthenticated()) {
        debug('end-user already logged out, redirecting to %s', returnURL);

        // perform idp logout with no token hint
        return res.redirect(getLogoutUrl(undefined));
      }

      const { idToken: id_token_hint } = req.oidc;
      req[config.session.name] = undefined;

      returnURL = getLogoutUrl(id_token_hint);
    } catch (err) {
      return next(err);
    }

    debug('logging out of identity provider, redirecting to %s', returnURL);
    res.redirect(returnURL);
  }

  async callback(options = {}) {
    let { config, req, res, transient, next } = weakRef(this);
    next = once(next);
    try {
      const { client, issuer } = await getClient(config);
      const redirectUri = options.redirectUri || this.getRedirectUri();

      let tokenSet;
      try {
        const callbackParams = client.callbackParams(req);
        const authVerification = transient.getOnce(
          config.transactionCookie.name,
          req,
          res,
        );

        if (!authVerification) {
          if (req.oidc.isAuthenticated()) {
            // User already has a valid session — this is a stale/replayed callback
            // (e.g., browser back button navigated back to a consumed /callback URL).
            debug(
              'stale callback detected, user already authenticated, redirecting to baseURL',
            );
            return res.redirect(config.baseURL);
          } else {
            /*
             * The transaction cookie is missing for an unauthenticated user. Possible causes:
             * 1. A request was made directly to the callback URL without going through the
             *    login route first — no cookie was ever set.
             * 2. The browser dropped the SameSite=None cookie during the IdP redirect
             *    (common in Safari/ITP, privacy mode, or browsers that reject SameSite=None
             *    without a Secure flag on non-HTTPS origins).
             * 3. legacySameSiteCookie is false and the browser does not support SameSite=None,
             *    so neither the primary nor the fallback cookie was sent back.
             * 4. Multiple apps share the same transactionCookie.name and cookie path on the
             *    same domain — a second app's login flow overwrote this app's cookie before
             *    the callback fired. Set a unique transactionCookie.name and session.cookie.path
             *    per app to isolate them.
             */
            throw new Error(
              `"${config.transactionCookie.name}" cookie not found. ` +
                `Ensure the login flow is initiated through the SDK's login route before ` +
                `the callback is processed. If using SameSite=None cookies, verify the ` +
                `origin is served over HTTPS and the Secure flag is set. For multi-app ` +
                `deployments on the same domain, configure a unique transactionCookie.name ` +
                `and session.cookie.path per application.`,
            );
          }
        }

        const checks = JSON.parse(authVerification);

        req.openidState = decodeState(checks.state);

        tokenSet = await client.callback(redirectUri, callbackParams, checks, {
          exchangeBody: {
            ...(config && config.tokenEndpointParams),
            ...options.tokenEndpointParams,
          },
          clientAssertionPayload: {
            aud: issuer.issuer,
          },
        });
      } catch (error) {
        throw createError(400, error.message, {
          error: error.error,
          error_description: error.error_description,
        });
      }

      let session = Object.assign({}, tokenSet); // Remove non-enumerable methods from the TokenSet
      const claims = tokenSet.claims();
      // Must store the `sid` separately as the ID Token gets overridden by
      // ID Token from the Refresh Grant which may not contain a sid (In Auth0 currently).
      session.sid = claims.sid;

      if (config.afterCallback) {
        session = await config.afterCallback(
          req,
          res,
          session,
          req.openidState,
        );
      }

      if (req.oidc.isAuthenticated()) {
        if (req.oidc.user.sub === claims.sub) {
          // If it's the same user logging in again, just update the existing session.
          Object.assign(req[config.session.name], session);
        } else {
          // If it's a different user, replace the session to remove any custom user
          // properties on the session
          replaceSession(req, session, config);
          // And regenerate the session id so the previous user wont know the new user's session id
          await regenerateSessionStoreId(req, config);
        }
      } else {
        // If a new user is replacing an anonymous session, update the existing session to keep
        // any anonymous session state (eg. checkout basket)
        Object.assign(req[config.session.name], session);
        // But update the session store id so a previous anonymous user wont know the new user's session id
        await regenerateSessionStoreId(req, config);
      }
      resumeSilentLogin(req, res);

      if (
        req.oidc.isAuthenticated() &&
        config.backchannelLogout &&
        config.backchannelLogout.onLogin !== false
      ) {
        await (config.backchannelLogout.onLogin || onLogin)(req, config);
      }
    } catch (err) {
      if (!req.openidState || !req.openidState.attemptingSilentLogin) {
        return next(err);
      }
    }
    res.redirect(req.openidState.returnTo || config.baseURL);
  }

  async backchannelLogout() {
    let { config, req, res } = weakRef(this);
    res.setHeader('cache-control', 'no-store');
    const logoutToken = req.body.logout_token;
    if (!logoutToken) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing logout_token',
      });
      return;
    }
    const onToken =
      (config.backchannelLogout && config.backchannelLogout.onLogoutToken) ||
      onLogoutToken;
    let token;
    try {
      const { issuer } = await getClient(config);
      const keyInput = await issuer.keystore();

      token = await JWT.LogoutToken.verify(logoutToken, keyInput, {
        issuer: issuer.issuer,
        audience: config.clientID,
        algorithms: [config.idTokenSigningAlg],
      });
    } catch (e) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: e.message,
      });
      return;
    }
    try {
      await onToken(token, config);
    } catch (e) {
      debug('req.oidc.backchannelLogout() failed with: %s', e.message);
      res.status(400).json({
        error: 'application_error',
        error_description: `The application failed to invalidate the session.`,
      });
      return;
    }
    res.status(204).send();
  }
}

module.exports = { RequestContext, ResponseContext };

const url = require('url');
const urlJoin = require('url-join');
const { TokenSet } = require('openid-client');
const clone = require('clone');
const { strict: assert } = require('assert');
const createError = require('http-errors');

const debug = require('./debug')('context');
const { once } = require('./once');
const { get: getClient } = require('./client');
const { encodeState, decodeState } = require('../lib/hooks/getLoginState');
const {
  cancelSilentLogin,
  resumeSilentLogin,
} = require('../middleware/attemptSilentLogin');
const weakRef = require('./weakCache');
const {
  regenerateSessionStoreId,
  replaceSession,
} = require('../lib/appSession');

function isExpired() {
  return tokenSet.call(this).expired();
}

async function refresh({ tokenEndpointParams } = {}) {
  let { config, req } = weakRef(this);
  const client = await getClient(config);
  const oldTokenSet = tokenSet.call(this);

  let extras;
  if (config.tokenEndpointParams || tokenEndpointParams) {
    extras = {
      exchangeBody: { ...config.tokenEndpointParams, ...tokenEndpointParams },
    };
  }

  const newTokenSet = await client.refresh(oldTokenSet, extras);

  // Update the session
  const session = req[config.session.name];
  Object.assign(session, {
    id_token: newTokenSet.id_token,
    access_token: newTokenSet.access_token,
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
    } catch (err) {
      return undefined;
    }
  }

  get refreshToken() {
    try {
      return tokenSet.call(this).refresh_token;
    } catch (err) {
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
    } catch (err) {
      return undefined;
    }
  }

  get idTokenClaims() {
    try {
      return clone(tokenSet.call(this).claims());
    } catch (err) {
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
    } catch (err) {
      return undefined;
    }
  }

  async fetchUserInfo() {
    const { config } = weakRef(this);

    const client = await getClient(config);
    return client.userinfo(tokenSet.call(this));
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
      const client = await getClient(config);

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
        `response_type should be one of ${validResponseTypes.join(', ')}`
      );
      assert(
        /\bopenid\b/.test(options.authorizationParams.scope),
        'scope should contain "openid"'
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
          'response_type includes code, the authorization request will use PKCE'
        );
        authVerification.code_verifier = transient.generateCodeVerifier();

        authParams.code_challenge_method = 'S256';
        authParams.code_challenge = transient.calculateCodeChallenge(
          authVerification.code_verifier
        );
      }

      if (config.pushedAuthorizationRequests) {
        const { request_uri } = await client.pushedAuthorizationRequest(
          authParams
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
      const client = await getClient(config);

      if (url.parse(returnURL).host === null) {
        returnURL = urlJoin(config.baseURL, returnURL);
      }

      cancelSilentLogin(req, res);

      if (!req.oidc.isAuthenticated()) {
        debug('end-user already logged out, redirecting to %s', returnURL);
        return res.redirect(returnURL);
      }

      const { idToken: id_token_hint } = req.oidc;
      req[config.session.name] = undefined;

      if (!config.idpLogout) {
        debug('performing a local only logout, redirecting to %s', returnURL);
        return res.redirect(returnURL);
      }

      returnURL = client.endSessionUrl({
        ...config.logoutParams,
        ...params.logoutParams,
        post_logout_redirect_uri: returnURL,
        id_token_hint,
      });
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
      const client = await getClient(config);
      const redirectUri = options.redirectUri || this.getRedirectUri();

      let tokenSet;
      try {
        const callbackParams = client.callbackParams(req);
        const authVerification = transient.getOnce(
          config.transactionCookie.name,
          req,
          res
        );

        const checks = authVerification ? JSON.parse(authVerification) : {};

        req.openidState = decodeState(checks.state);

        tokenSet = await client.callback(redirectUri, callbackParams, checks, {
          exchangeBody: {
            ...(config && config.tokenEndpointParams),
            ...options.tokenEndpointParams,
          },
        });
      } catch (error) {
        throw createError(400, error.message, {
          error: error.error,
          error_description: error.error_description,
        });
      }

      let session = Object.assign({}, tokenSet); // Remove non-enumerable methods from the TokenSet

      if (config.afterCallback) {
        session = await config.afterCallback(
          req,
          res,
          session,
          req.openidState
        );
      }

      if (req.oidc.isAuthenticated()) {
        if (req.oidc.user.sub === tokenSet.claims().sub) {
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
    } catch (err) {
      if (!req.openidState || !req.openidState.attemptingSilentLogin) {
        return next(err);
      }
    }
    res.redirect(req.openidState.returnTo || config.baseURL);
  }
}

module.exports = { RequestContext, ResponseContext };

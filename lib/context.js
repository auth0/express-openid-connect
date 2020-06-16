const cb = require('cb');
const url = require('url');
const urlJoin = require('url-join');
const { TokenSet } = require('openid-client');
const clone = require('clone');

const debug = require('./debug');
const { get: getClient } = require('./client');
const { encodeState } = require('../lib/hooks/getLoginState');
const weakRef = require('./weakCache');

function isExpired () {
  return tokenSet.call(this).expired();
}

function tokenSet () {
  const contextCache = weakRef(this);
  const session = contextCache.req[contextCache.config.session.name];

  if (!session || !('id_token' in session)) {
    return undefined;
  }

  const cachedTokenSet = weakRef(session);

  if (!('value' in cachedTokenSet)) {
    const { id_token, access_token, refresh_token, token_type, expires_at } = session;
    cachedTokenSet.value = new TokenSet({ id_token, access_token, refresh_token, token_type, expires_at });
  }

  return cachedTokenSet.value;
}

class RequestContext {
  constructor (config, req, res, next) {
    Object.assign(weakRef(this), { config, req, res, next });
  }

  isAuthenticated () {
    return !!this.idTokenClaims;
  }

  get idToken () {
    try {
      return tokenSet.call(this).id_token;
    } catch (err) {
      return undefined;
    }
  }

  get refreshToken () {
    try {
      return tokenSet.call(this).refresh_token;
    } catch (err) {
      return undefined;
    }
  }

  get accessToken () {
    try {
      const { access_token, token_type, expires_in } = tokenSet.call(this);

      if (!access_token || !token_type || typeof expires_in !== 'number') {
        return undefined;
      }

      return { access_token, token_type, expires_in, isExpired: isExpired.bind(this) };
    } catch (err) {
      return undefined;
    }
  }

  get idTokenClaims () {
    try {
      return clone(tokenSet.call(this).claims());
    } catch (err) {
      return undefined;
    }
  }

  get user () {
    try {
      const { config: { identityClaimFilter } } = weakRef(this);
      const { idTokenClaims } = this;
      const user = clone(idTokenClaims);
      identityClaimFilter.forEach(claim => {
        delete user[claim];
      });
      return user;
    } catch (err) {
      return undefined;
    }
  }
}

class ResponseContext {
  constructor (config, req, res, next, transient) {
    Object.assign(weakRef(this), { config, req, res, next, transient });
  }

  get errorOnRequiredAuth () {
    return weakRef(this).config.errorOnRequiredAuth;
  }

  getRedirectUri () {
    const { config } = weakRef(this);
    return urlJoin(config.baseURL, config.routes.callback);
  }

  async login (options = {}) {
    let { config, req, res, next, transient } = weakRef(this);
    next = cb(next).once();
    const client = await getClient(config);

    // Set default returnTo value, allow passed-in options to override or use originalUrl on GET
    let returnTo = config.baseURL;
    if (options.returnTo) {
      returnTo = options.returnTo;
      debug.trace('req.oidc.login() called with returnTo:', returnTo);
    } else if (req.method === 'GET' && req.originalUrl) {
      returnTo = req.originalUrl;
      debug.trace('req.oidc.login() without returnTo, using:', returnTo);
    }

    options = {
      authorizationParams: {},
      returnTo,
      ...options
    };

    // Ensure a redirect_uri, merge in configuration options, then passed-in options.
    options.authorizationParams = {
      redirect_uri: this.getRedirectUri(),
      ...config.authorizationParams,
      ...options.authorizationParams
    };

    const transientOpts = {
      sameSite: options.authorizationParams.response_mode === 'form_post' ? 'None' : 'Lax'
    };

    const stateValue = await config.getLoginState(req, options);
    if (typeof stateValue !== 'object') {
      next(new Error('Custom state value must be an object.'));
    }
    stateValue.nonce = transient.generateNonce();

    const usePKCE = options.authorizationParams.response_type.includes('code');
    if (usePKCE) {
      debug.trace('response_type includes code, the authorization request will use PKCE');
      stateValue.code_verifier = transient.generateCodeVerifier();
    }

    try {
      const authParams = {
        ...options.authorizationParams,
        nonce: transient.store('nonce', req, res, transientOpts),
        state: transient.store('state', req, res, { ...transientOpts, value: encodeState(stateValue) }),
        ...(usePKCE ? {
          code_challenge: transient.calculateCodeChallenge(transient.store('code_verifier', req, res, transientOpts)),
          code_challenge_method: 'S256',
        } : undefined)
      };

      // TODO: hook here

      if (authParams.max_age) {
        transient.store('max_age', req, res, { ...transientOpts, value: authParams.max_age });
      }

      // TODO: check openid is in the scope here

      const authorizationUrl = client.authorizationUrl(authParams);
      res.redirect(authorizationUrl);
    } catch (err) {
      next(err);
    }
  }

  async logout (params = {}) {
    let { config, req, res, next } = weakRef(this);
    next = cb(next).once();
    const client = await getClient(config);

    let returnURL = params.returnTo || config.routes.postLogoutRedirectUri;

    if (url.parse(returnURL).host === null) {
      returnURL = urlJoin(config.baseURL, returnURL);
    }

    if (!req.oidc.isAuthenticated()) {
      return res.redirect(returnURL);
    }

    const { idToken: id_token_hint } = req.oidc;
    req[config.session.name] = undefined;

    if (!config.idpLogout) {
      return res.redirect(returnURL);
    }

    try {
      returnURL = client.endSessionUrl({ post_logout_redirect_uri: returnURL, id_token_hint });
    } catch (err) {
      return next(err);
    }

    res.redirect(returnURL);
  }
}

module.exports = { RequestContext, ResponseContext };

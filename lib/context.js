const cb = require('cb');
const url = require('url');
const urlJoin = require('url-join');
const { TokenSet } = require('openid-client');

const transient = require('./transientHandler');
const { get: getClient } =  require('./client');
const { encodeState } = require('../lib/hooks/getLoginState');

class RequestContext {
  constructor(config, req, res, next) {
    this._config = config;
    this._req = req;
    this._res = res;
    this._next = next;
  }

  get isAuthenticated() {
    return !!this.user;
  }

  makeTokenSet(tokenSet) {
    return new TokenSet(tokenSet);
  }

  async load() {
    if (!this.client) {
      this.client = await getClient(this._config);
    }

    this.user = await this._config.getUser(this._req, this._config);
  }
}

class ResponseContext {
  constructor(config, req, res, next) {
    this._config = config;
    this._req = req;
    this._res = res;
    this._next = next;
  }

  get errorOnRequiredAuth() {
    return this._config.errorOnRequiredAuth;
  }

  getRedirectUri() {
    return urlJoin(this._config.baseURL, this._config.redirectUriPath);
  }

  async login(options = {}) {
    const next = cb(this._next).once();
    const req = this._req;
    const res = this._res;
    const config = this._config;
    const client = req.openid.client;

    // Set default returnTo value, allow passed-in options to override.
    options = {
      returnTo: this._config.baseURL,
      authorizationParams: {},
      ...options
    };

    // Ensure a redirect_uri, merge in configuration options, then passed-in options.
    options.authorizationParams = {
      redirect_uri: this.getRedirectUri(),
      ...config.authorizationParams,
      ...options.authorizationParams
    };

    const transientOpts = {
      legacySameSiteCookie: config.legacySameSiteCookie,
      sameSite: options.authorizationParams.response_mode === 'form_post' ? 'None' : 'Lax'
    };

    let stateValue = await config.getLoginState(req, options);
    if ( typeof stateValue !== 'object' ) {
      next(new Error( 'Custom state value must be an object.' ));
    }
    stateValue.nonce = transient.createNonce();

    const stateTransientOpts = {
      ...transientOpts,
      value: encodeState(stateValue)
    };

    try {
      const authParams = {
        ...options.authorizationParams,
        nonce: transient.store('nonce', res, transientOpts),
        state: transient.store('state', res, stateTransientOpts)
      };

      const authorizationUrl = client.authorizationUrl(authParams);
      res.redirect(authorizationUrl);
    } catch (err) {
      next(err);
    }
  }

  async logout(params = {}) {
    const next = cb(this._next).once();
    const req = this._req;
    const res = this._res;
    const config = this._config;

    let returnURL = params.returnTo || config.postLogoutRedirectUri;

    if (url.parse(returnURL).host === null) {
      returnURL = urlJoin(config.baseURL, returnURL);
    }

    if (!req.isAuthenticated()) {
      return res.redirect(returnURL);
    }

    if (config.appSession) {
      req[config.appSession.name] = undefined;
    }

    if (!config.idpLogout) {
      return res.redirect(returnURL);
    }

    const client = req.openid.client;
    try {
      returnURL = client.endSessionUrl({
        post_logout_redirect_uri: returnURL,
        id_token_hint: req.openid.tokens,
      });
    } catch(err) {
      return next(err);
    }

    res.redirect(returnURL);
  }

}

module.exports = { RequestContext, ResponseContext };

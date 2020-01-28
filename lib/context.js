const cb = require('cb');
const url = require('url');
const urlJoin = require('url-join');
const { TokenSet } = require('openid-client');
const { encode: base64encode, decode: base64decode } = require('base64url');

const transient = require('./transientHandler');
const { get: getClient } =  require('./client');

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

  /**
   * Prepare a state object to send.
   *
   * @param {object} stateObject
   */
  encodeState(stateObject) {
    return base64encode(JSON.stringify(stateObject));
  }

  /**
   * Decode a state value.
   *
   * @param {string} state
   */
  decodeState(state) {
    return JSON.parse(base64decode(state));
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

    options = {
      returnTo: this._config.baseURL,
      authorizationParams: {},
      ...options
    };

    options.authorizationParams = {
      redirect_uri: this.getRedirectUri(),
      ...config.authorizationParams,
      ...options.authorizationParams
    };

    const transientOpts = {
      legacySameSiteCookie: config.legacySameSiteCookie,
      sameSite: options.authorizationParams.response_mode === 'form_post' ? 'None' : 'Lax'
    };

    const stateTransientOpts = {
      ...transientOpts,
      value: config.getLoginState(req, options)
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

    let returnURL = params.returnTo || req.query.returnTo || this._config.postLogoutRedirectUri;

    if (url.parse(returnURL).host === null) {
      returnURL = urlJoin(this._config.baseURL, returnURL);
    }

    if (!req.isAuthenticated()) {
      return res.redirect(returnURL);
    }

    req[this._config.appSessionName] = undefined;

    if (!this._config.idpLogout) {
      return res.redirect(returnURL);
    }

    const client = this._req.openid.client;
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

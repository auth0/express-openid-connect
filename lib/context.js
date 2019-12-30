const cb = require('cb');
const urlJoin = require('url-join');
const transient = require('./transientHandler');
const { get: getClient } =  require('./client');
const { TokenSet } = require('openid-client');

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

  async login(params = {}) {
    const next = cb(this._next).once();
    const req = this._req;
    const res = this._res;
    const config = this._config;

    const client = req.openid.client;
    const authorizeParams = config.authorizationParams;
    const transientOpts = {
      legacySameSiteCookie: config.legacySameSiteCookie,
      sameSite: config.authorizationParams.response_mode === 'form_post' ? 'None' : 'Lax'
    };

    try {
      let returnTo;
      if (params.returnTo) {
        returnTo = params.returnTo;
      } else if (req.method === 'GET') {
        returnTo = req.originalUrl;
      } else {
        returnTo = this._config.baseURL;
      }

      // TODO: Store this in state
      transient.store('returnTo', res, Object.assign({value: returnTo}, transientOpts));

      const authParams = Object.assign({
        nonce: transient.store('nonce', res, transientOpts),
        state: transient.store('state', res, transientOpts),
        redirect_uri: this.getRedirectUri()
      }, authorizeParams, params.authorizationParams || {});

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
    const returnURL = params.returnTo || this._config.baseURL;

    req[this._config.appSessionName] = undefined;

    if (!this._config.idpLogout) {
      return res.redirect(returnURL);
    }

    try {
      const client = this._req.openid.client;
      const url = client.endSessionUrl({
        post_logout_redirect_uri: returnURL,
        id_token_hint: req.openid.tokens,
      });
      res.redirect(url);
    } catch(err) {
      next(err);
    }
  }

}

module.exports = { RequestContext, ResponseContext };

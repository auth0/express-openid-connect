const cb = require('cb');
const url = require('url');
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

    const returnTo = params.returnTo || req.query.returnTo; 

    if (
      returnTo && 
      !returnTo.startsWith(this._config.baseURL) && url.parse(returnTo).host &&
      !this._config.postLogoutRedirectUris.includes(returnTo)
    ) {
      const err = new Error(`returnTo (${returnTo}) URI was not registered in config's postLogoutRedirectUris.`);
      return next(err);
    }  
    
    let returnURL = returnTo || this._config.postLogoutRedirectUri;
    
    if (url.parse(returnURL).host === null) {
      returnURL = urlJoin(this._config.baseURL, returnURL);
    }
    
    if (!req.session || !req.openid) {
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

    if (typeof req.session.destroy === 'function') {
      req.session.destroy();
    } else {
      req.session = null;
    }

    res.redirect(returnURL);
  }

}

module.exports = { RequestContext, ResponseContext };

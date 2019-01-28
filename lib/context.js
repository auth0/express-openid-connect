const cb = require('cb');
const debug = require('debug');
const urlJoin = require('url-join');
const crypto = require('crypto');
const { get: getClient } =  require('./client');
const { TokenSet } = require('openid-client');
const package = require('../package.json');
const debugLogin = debug(`${package.name}:login`);

class RequestContext {
  constructor(config, req, res, next) {
    this._config = config;
    this._req = req;
    this._res = res;
    this._next = next;
  }

  get tokens() {
    if (!this._req.session || !this._req.session.openidTokens) {
      return undefined;
    }
    return new TokenSet(this._req.session.openidTokens);
  }

  set tokens(value) {
    this._req.session.openidTokens = value;
  }

  get isAuthenticated() {
    return !!this.user;
  }

  async load() {
    if (!this.client) {
      this.client = await getClient(this._config);
    }
    if (this.tokens) {
      this.user = await this._config.getUser(this.tokens);
    }
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
    const authorizeParams = this._config.authorizationParams;

    try {
      const redirect_uri = this.getRedirectUri();
      if (typeof req.session === 'undefined') {
        return next(new Error('This router needs the session middleware'));
      }
      const client = this._req.openid.client;

      req.session.nonce = crypto.randomBytes(8).toString('hex');
      req.session.state = crypto.randomBytes(10).toString('hex');

      if(params.returnTo) {
        req.session.returnTo = params.returnTo;
      } else if (req.method === 'GET') {
        req.session.returnTo = req.originalUrl;
      } else {
        req.session.returnTo = this._config.baseURL;
      }

      const authParams = Object.assign({
        nonce: req.session.nonce,
        state: req.session.state,
        redirect_uri
      }, authorizeParams, params.authorizationParams || {});

      debugLogin('building the authorization url %O', authParams);
      const authorizationUrl = client.authorizationUrl(authParams);

      debugLogin('redirecting to %s', authorizationUrl);
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

    if (!req.session || !req.openid) {
      return res.redirect(returnURL);
    }

    if (typeof req.session.destroy === 'function') {
      req.session.destroy();
    } else {
      req.session = null;
    }

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

const express = require('express');
const crypto = require('crypto');
const urlJoin = require('url-join');
const cb = require('cb');
const debug = require('debug');
const { TokenSet } = require('openid-client');
const createError = require('http-errors');
const { get: getConfig } = require('../lib/config');
const memoize = require('p-memoize');
const fs = require('fs');
const package = require('../package.json');
const { get: getClient } = require('../lib/client');
const requiresAuth = require('./requiresAuth');

const getRepostView = memoize(() => fs.readFileSync(__dirname + '/../views/repost.html'));

const debugLogin = debug(`${package.name}:login`);
const debugCallback = debug(`${package.name}:callback`);

/**
* Returns a router with two routes /login and /callback
*
* @param {Object} [params] The parameters object
* @param {string} [params.issuerBaseURL] The url address for the token issuer.
* @param {string} [params.baseURL] The url of the web application where you are installing the router.
* @param {string} [params.clientID] The client id.
* @param {string} [params.clientSecret] The client secret, only required for some grants.
* @param {string} [params.clockTolerance=5] The clock's tolerance in seconds for token verification.
* @param {Function} [params.getUser] An async function receiving a tokenset and returning the profile for req.user.
* @param {boolean|Function} [params.required=true] a boolean to indicate that every route after this middleware requires authentication or
* a function receiving a request and return a boolean to determine which routes needs authentication.
* @param {boolean} [handleUnauthorizedErrors=true] automatically handle unauthorized errors by triggering the authentication process
* @param {boolean|Function} [params.routes=true] a boolean indicating if the routes /login and /logout should be added to the application
* @param {Object} [params.authorizationParams] The parameters for the authorization call. Defaults to
* - response_type: "id_token"
* - reponse_mode: "form_post"
* - scope: "openid profile email"
* @param {string} params.authorizationParams.response_type The response type.
* @param {string} [params.authorizationParams.response_mode] The response mode.
* @param {string} [params.authorizationParams.scope=openid profile email] The scope.
*
* @returns {express.Router} the router
*/
module.exports = function (params) {
  const config = getConfig(params);
  const authorizeParams = config.authorizationParams;

  if (typeof express.Router === 'undefined') {
    throw new Error(`express-openid-connect needs express@^3, current installed version ${require('express/package').version}`);
  }

  const router = express.Router();

  function getRedirectUri(req) {
    return urlJoin(config.baseURL, req.baseUrl || '', '/callback');
  }

  function login(req, res, next) {
    return async function(params = {}) {
      next = cb(next).once();
      try {
        debugLogin('building the openid client %O', config);
        const client = await getClient(config);
        const redirect_uri = getRedirectUri(req);
        if (typeof req.session === 'undefined') {
          return next(new Error('This router needs the session middleware'));
        }
        req.session.nonce = crypto.randomBytes(8).toString('hex');
        req.session.state = crypto.randomBytes(10).toString('hex');

        if(params.returnTo) {
          req.session.returnTo = params.returnTo;
        } else if (req.method === 'GET') {
          req.session.returnTo = req.originalUrl;
        } else {
          req.session.returnTo = config.baseURL;
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
    };
  }

  function logout(req, res, next) {
    return async function(params = {}) {
      next = cb(next).once();
      const returnURL = params.returnTo || config.baseURL;
      if (req.session || !req.openid) {
        if (typeof req.session.destroy === 'function') {
          req.session.destroy();
        } else {
          req.session = null;
        }
      } else {
        return res.redirect(returnURL);
      }
      try {
        const client = await getClient(config);
        const url = client.endSessionUrl({
          post_logout_redirect_uri: returnURL,
          id_token_hint: req.openid.tokens,
        });
        res.redirect(url);
      } catch(err) {
        next(err);
      }
    };
  }

  router.use(async (req, res, next) => {
    res.openid = {
      login: login(req, res, next),
      logout: () => res.redirect(config.baseURL)
    };
    if (!req.session.openidTokens) { return next(); }
    try {
      const client  = await getClient(config);
      const tokens = new TokenSet(req.session.openidTokens);
      const user = await config.getUser(tokens);
      const refreshToken = async () => {
        if (!tokens.refresh_token) {
          throw new Error("The tokenset can't be refreshed because there isn't a refresh token. Try adding the offline_access scope.");
        }
        if (!tokens.expired()) { return; }
        const newTokens = await client.refresh(tokens);
        req.session.openidTokens = Object.assign(tokens, newTokens);
        const user = await config.getUser(tokens);
        Object.assign(req.openid, { user, tokens });
      };
      req.openid = { client, user, tokens, refreshToken };
      res.openid.logout = logout(req, res, next);
      next();
    } catch(err) {
      next(err);
    }
  });

  if (config.routes) {
    router.get('/login', (req, res) => {
      res.openid.login({ returnTo: config.baseURL });
    });
    router.get('/logout', (req, res) => res.openid.logout());
  }

  let callbackMethod;
  let repost;

  switch (authorizeParams.response_mode) {
    case 'form_post':
      callbackMethod = 'post';
      break;
    case 'query':
      callbackMethod = 'get';
      break;
    case 'fragment':
      callbackMethod = 'post';
      repost = true;
      break;
    default:
      if (/token/.test(authorizeParams.response_type)) {
        callbackMethod = 'post';
        repost = true;
      }
      else {
        callbackMethod = 'get';
      }
  }

  router[callbackMethod]('/callback', async (req, res, next) => {
    next = cb(next).once();
    try {
      const client = await getClient(config);
      const { nonce, state } = req.session;
      delete req.session.nonce;
      delete req.session.state;
      debugCallback('session parameters', { nonce, state });

      const redirect_uri = getRedirectUri(req);


      let tokenSet;

      try {
        const callbackParams = client.callbackParams(req);
        debugCallback('callback parameters: %O', callbackParams);

        tokenSet = await client.authorizationCallback(redirect_uri, callbackParams, {
          nonce,
          state,
          response_type: authorizeParams.response_type,
        });
      } catch (err) {
        debugCallback('error in the authorization callback: %s', err.message);
        throw createError.BadRequest(err.message);
      }

      debugCallback('tokens: %O', tokenSet);
      req.session.openidTokens = tokenSet;

      const returnTo = req.session.returnTo || '/';
      delete req.session.returnTo;
      debugCallback('redirecting to %s', returnTo);
      res.redirect(returnTo);
    } catch (err) {
      next(err);
    }
  });

  if (repost) {
    router.get('/callback', async (req, res) => {
      res.set('Content-Type', 'text/html');
      res.send(getRepostView());
    });
  }

  if (config.required) {
    const requiresAuthMiddleware = requiresAuth();
    if (typeof config.required === 'function') {
      router.use((req, res, next) => {
        if (!config.required(req)) { return next(); }
        requiresAuthMiddleware(req, res, next);
      });
    } else {
      router.use(requiresAuthMiddleware);
    }
  }

  if(config.handleUnauthorizedErrors) {
    router.use((err, req, res, next) => {
      if (err.statusCode === 401) {
        if(req.xhr) { return res.sendStatus(401); }
        return res.openid.login();
      }
      next(err);
    });
  }

  return router;
};

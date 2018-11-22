const package = require('./package.json');
const getClient = require('./lib/client').get;
const express = require('express');
const { Issuer } = require('openid-client');
const crypto = require('crypto');
const urlJoin = require('url-join');
const _ = require('lodash');
const cb = require('cb');
const fs = require('fs');
const paramsValidator = require('./lib/paramsValidator');
const ResponseMode = require('./lib/ResponseMode');
const getRepostView = _.memoize(() => fs.readFileSync(__dirname + '/views/repost.html'));

const debugLogin = require('debug')(`${package.name}:login`);
const debugCallback = require('debug')(`${package.name}:callback`);

Issuer.defaultHttpOptions = { timeout: 4000 };

/**
* Returns a middleware that verifies the existence of req.session.user.
* If "user" is not in the session it will redirect to /login,
* otherwise continue to the next middleware in the stack.
*/
module.exports.protect = function() {
  return function(req, res, next) {
    if (req.session.user) { return next(); }
    if (req.method === 'GET') {
      req.session.returnTo = req.originalUrl;
    }
    res.redirect('/login');
  };
};

/**
* Returns a router with two routes /login and /callback
*
* @param {Object} [params] The parameters object
* @param {string} [params.issuerBaseURL] The url address for the token issuer.
* @param {string} [params.baseURL] The url of the web application where you are installing the router.
* @param {string} [params.clientID] The client id.
* @param {string} [params.clientSecret] The client secret, only required for some grants.
* @param {Object} [params.authorizationParams] The parameters for the authorization call. Defaults to
* - response_type: "id_token"
* - reponse_mode: "form_post"
* - scope: "openid profile email"
*
* @param {string} params.authorizationParams.response_type The response type.
* @param {string} [params.authorizationParams.response_mode] The response mode.
* @param {string} [params.authorizationParams.scope=openid profile email] The scope.
*
* @returns {express.Router} the router
*/
module.exports.routes = function(params) {
  params = paramsValidator.validate(params);
  const authorizeParams = params.authorizationParams;

  if (typeof express.Router === 'undefined') {
    throw new Error(`express-openid-client needs express@^3, current installed version ${require('express/package').version}`);
  }

  const router = express.Router();

  function getRedirectUri(req) {
    return urlJoin(params.baseURL, req.baseUrl || '', '/callback');
  }
  router.get('/login', async (req, res, next) => {
    next = cb(next).once();
    try {
      debugLogin('building the openid client %O', params);
      const client = await getClient(params);
      const redirect_uri = getRedirectUri(req);
      if (typeof req.session === 'undefined') {
        return next(new Error('This router needs the session middleware'));
      }
      req.session.nonce = crypto.randomBytes(8).toString('hex');
      req.session.state = crypto.randomBytes(10).toString('hex');

      const authParams = Object.assign({
        nonce: req.session.nonce,
        state: req.session.state,
        redirect_uri
      }, authorizeParams);

      debugLogin('building the authorization url %O', authParams);
      const authorizationUrl = client.authorizationUrl(authParams);

      debugLogin('redirecting to %s', authorizationUrl);
      res.redirect(authorizationUrl);
    } catch(err) {
      next(err);
    }
  });

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
      } else {
        callbackMethod = 'get';
      }
  }

  router[callbackMethod]('/callback', async (req, res, next) => {
    next = cb(next).once();
    try {
      const client = await getClient(params);
      const { nonce, state } = req.session;
      delete req.session.nonce;
      delete req.session.state;

      const redirect_uri = getRedirectUri(req);

      debugCallback('parsing response for callback parameters');

      const callbackParams = client.callbackParams(req);
      debugCallback('callback parameters: %O', callbackParams);

      const tokenSet = await client.authorizationCallback(
        redirect_uri,
        callbackParams, {
          nonce,
          state,
          response_type: authorizeParams.response_type,
        });
      debugCallback('tokens: %O', tokenSet);

      req.session.tokens = tokenSet;
      req.session.user = tokenSet.claims;
      debugCallback('user: %O', req.session.user);

      const returnTo = req.session.returnTo || '/';
      delete req.session.returnTo;
      debugCallback('redirecting to %s', returnTo);
      res.redirect(returnTo);
    } catch(err) {
      next(err);
    }
  });

  if (repost) {
    router.get('/callback', async (req, res) => {
      res.set('Content-Type', 'text/html');
      res.send(getRepostView());
    });
  }

  return router;
};


module.exports.ResponseMode = ResponseMode;

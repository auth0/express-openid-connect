const express = require('express');
const crypto = require('crypto');
const urlJoin = require('url-join');
const cb = require('cb');
const debug = require('debug');
const { TokenSet } = require('openid-client');
const { get: getConfig } = require('../lib/config');
const UnauthorizedError = require('../lib/UnauthorizedError');
const _ = require('lodash');
const fs = require('fs');
const package = require('../package.json');
const { get: getClient } = require('../lib/client');

const getRepostView = _.memoize(() => fs.readFileSync(__dirname + '/../views/repost.html'));

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
* @param {function} [params.profileMapper] An async function receiving a tokenset and returning the profile for req.user.
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
    throw new Error(`express-openid-client needs express@^3, current installed version ${require('express/package').version}`);
  }

  const router = express.Router();

  function getRedirectUri(req) {
    return urlJoin(config.baseURL, req.baseUrl || '', '/callback');
  }

  router.get('/login', async (req, res, next) => {
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
      const authParams = Object.assign({
        nonce: req.session.nonce,
        state: req.session.state,
        redirect_uri
      }, authorizeParams);
      debugLogin('building the authorization url %O', authParams);
      const authorizationUrl = client.authorizationUrl(authParams);
      debugLogin('redirecting to %s', authorizationUrl);
      res.redirect(authorizationUrl);
    }
    catch (err) {
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

      const callbackParams = client.callbackParams(req);
      debugCallback('callback parameters: %O', callbackParams);

      let tokenSet;
      try {
        tokenSet = await client.authorizationCallback(redirect_uri, callbackParams, {
          nonce,
          state,
          response_type: authorizeParams.response_type,
        });
      } catch (err) {
        debugCallback('error in the authorization callback: %s', err.message);
        throw new UnauthorizedError(401, err);
      }

      debugCallback('tokens: %O', tokenSet);
      req.session.tokens = tokenSet;

      const returnTo = req.session.returnTo || '/';
      delete req.session.returnTo;
      debugCallback('redirecting to %s', returnTo);
      res.redirect(returnTo);
    }
    catch (err) {
      next(err);
    }
  });

  if (repost) {
    router.get('/callback', async (req, res) => {
      res.set('Content-Type', 'text/html');
      res.send(getRepostView());
    });
  }

  router.use(async (req, res, next) => {
    if (!req.session.tokens) { return next(); }
    try {
      const client = await getClient(config);
      req.tokens = new TokenSet(req.session.tokens);
      req.user = await config.profileMapper(req.tokens);
      req.openIDClient = client;
      next();
    } catch(err) {
      next(err);
    }
  });

  return router;
};

const express = require('express');
const { Issuer } = require('openid-client');
const crypto = require('crypto');
const urlJoin = require('url-join');
const _ = require('lodash');

Issuer.defaultHttpOptions = { timeout: 4000 };

module.exports.protect = function() {
  return function(req, res, next) {
    if (req.session.user) { return next(); }
    if (req.method === 'GET') {
      req.session.returnTo = req.originalUrl;
    }
    res.redirect('/login');
  };
};

const defaultAuthorizeParams = {
  response_type: 'id_token',
  response_mode: 'form_post',
  scope: 'openid profile email'
};

/**
* Returns a router with two routes /login and /callback
*
* @param {Object} params - The parameters object
* @param {string} params.issuer_url - The url address for the token issuer.
* @param {string} params.client_url - The url of the web application where you are installing the router.
* @param {string} params.client_id - The client id.
* @param {string} [params.client_secret] - The client secret, only required for some grants.
* @param {Object} [params.authorizationParams] - The parameters for the authorization call.
* @param {string} [params.authorizationParams.response_type=id_token] - The response type.
* @param {string} [params.authorizationParams.response_mode=form_post] - The response mode.
* @param {string} [params.authorizationParams.scope=openid profile email] - The scope.
* @returns {express.Router} the router
*/
module.exports.routes = function(params) {
  const authorizeParams = Object.assign({ },
    defaultAuthorizeParams,
    params.authorizationParams || {});

  const router = express.Router();

  const getClient = _.memoize(async function() {
    const issuer = await Issuer.discover(params.issuer_url);
    return new issuer.Client({
      client_id: params.client_id,
      client_secret: params.client_secret
    });
  });

  function getRedirectUri(req) {
    return urlJoin(params.client_url, req.baseUrl || '', '/callback');
  }

  router.get('/login', async (req, res, next) => {
    const client = await getClient();
    const redirect_uri = getRedirectUri(req);
    if (typeof req.session === 'undefined') {
      return next(new Error('This router needs the session middleware'));
    }
    req.session.nonce = crypto.randomBytes(8).toString('hex');
    req.session.state = crypto.randomBytes(10).toString('hex');
    const authorizationUrl = client.authorizationUrl(Object.assign({
      nonce: req.session.nonce,
      state: req.session.state,
      redirect_uri
    }, authorizeParams));
    res.redirect(authorizationUrl);
  });

  const callbackMethod = authorizeParams.response_mode === 'form_post' ? 'post' : 'get';

  router[callbackMethod]('/callback', async (req, res) => {
    const client = await getClient();
    const { nonce, state } = req.session;
    delete req.session.nonce;
    delete req.session.state;

    const redirect_uri = getRedirectUri(req);

    const callbackParams = client.callbackParams(req); // => parsed url query or body object
    const tokenSet = await client.authorizationCallback(
      redirect_uri,
      callbackParams, {
        nonce,
        state,
        response_type: authorizeParams.response_type,
      });

    req.session.user = tokenSet.claims;
    const returnTo = req.session.returnTo || '/';
    res.redirect(returnTo);
  });

  return router;
};



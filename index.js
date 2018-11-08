const express = require('express');
const { Issuer } = require('openid-client');
const crypto = require('crypto');
Issuer.defaultHttpOptions = { timeout: 4000 };

module.exports.protect = function() {
  return function(req, res, next) {
    if (req.session.user) { return next(); }
    if (req.method === 'GET') {
      req.session.returnTo = req.originalUrl;
    }
    res.redirect('/login');
  }
};

const defaultAuthorizeParams = {
  response_type: 'id_token',
  response_mode: 'form_post',
};

module.exports.routes = function(params) {
  const authorizeParams = Object.assign({}, defaultAuthorizeParams, params.authorizationParams);

  const router = express.Router();

  async function getClient() {
    const issuer = await Issuer.discover(params.issuer_url);
    return new issuer.Client({
      client_id: params.client_id,
      client_secret: params.client_secret
    });
  }

  router.get('/login', async (req, res, next) => {
    const client = await getClient();
    const nonce = crypto.randomBytes(8).toString('hex');
    if (typeof req.session === 'undefined') {
      return next(new Error('This router needs the session middleware'));
    }
    req.session.nonce = nonce;
    const authorizationUrl = client.authorizationUrl(Object.assign({ nonce }, authorizeParams));
    res.redirect(authorizationUrl);
  });

  router.use('/callback', async (req, res, next) => {
    const client = await getClient();
    const { nonce } = req.session;

    const callbackParams = client.callbackParams(req); // => parsed url query or body object
    const tokenSet = await client.authorizationCallback(
      authorizeParams.redirect_uri,
      callbackParams, {
        nonce,
        response_type: authorizeParams.response_type
      });

    req.session.user = tokenSet.claims;
    const returnTo = req.session.returnTo || '/';
    res.redirect(returnTo);
  });

  return router;
}



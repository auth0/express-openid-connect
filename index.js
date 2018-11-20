const express = require('express');
const { Issuer } = require('openid-client');
const crypto = require('crypto');
const urlJoin = require('url-join');
const _ = require('lodash');
const deprecate = require('deprecate');
const cb = require('cb');
const Joi = require('joi');

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

const defaultAuthorizeParams = {
  response_type: 'id_token',
  response_mode: 'form_post',
  scope: 'openid profile email'
};

const fieldsEnvMap = {
  'issuer_base_url': 'ISSUER_BASE_URL',
  'base_url': 'BASE_URL',
  'client_id': 'CLIENT_ID',
  'client_secret': 'CLIENT_SECRET',
};

function loadFromEnv(params) {
  Object.keys(fieldsEnvMap).forEach(k => {
    if (params[k]) { return; }
    params[k] = process.env[fieldsEnvMap[k]];
  });

  if (!params.base_url &&
      !process.env.BASE_URL &&
      process.env.PORT &&
      process.env.NODE_ENV !== 'production') {
    params.base_url = `http://localhost:${process.env.PORT}`;
  }
}

function buildAutorizeParams(params) {
  const authorizationParams = Object.assign({}, defaultAuthorizeParams, params.authorizationParams || {});
  const authParamsValidation = Joi.validate(authorizationParams, authorizationParamsSchema);
  if(authParamsValidation.error) {
    throw authParamsValidation.error;
  }
  return authorizationParams;
}

async function buildClient(params, authorizeParams) {
  const issuer = await Issuer.discover(params.issuer_base_url);
  if (Array.isArray(issuer.response_types_supported) &&
    !issuer.response_types_supported.includes(authorizeParams.response_type)) {
    throw new Error(`The issuer doesn't support the response_type ${authorizeParams.response_type}
Supported types:
- ${issuer.response_types_supported.sort().join('\n- ')}
`);
  }

  if (Array.isArray(issuer.response_modes_supported) &&
    !issuer.response_modes_supported.includes(authorizeParams.response_mode)) {
    throw new Error(`The issuer doesn't support the response_mode ${authorizeParams.response_mode}
Supported response modes:
- ${issuer.response_modes_supported.sort().join('\n- ')}
`);
  }

  return new issuer.Client({
    client_id: params.client_id,
    client_secret: params.client_secret
  });
}


// const requiredParams = ['issuer_base_url', 'base_url', 'client_id'];
const paramsSchema = Joi.object().keys({
  issuer_base_url: Joi.string().uri().required(),
  base_url: Joi.string().uri().required(),
  client_id: Joi.string().required(),
  client_secret: Joi.string().optional(),
  authorizationParams: Joi.object().optional()
});

const authorizationParamsSchema = Joi.object().keys({
  response_type: Joi.string().required(),
  response_mode: Joi.string().required(),
  scope: Joi.string().required()
});

/**
* Returns a router with two routes /login and /callback
*
* @param {Object} [params] - The parameters object
* @param {string} [params.issuer_base_url] - The url address for the token issuer.
* @param {string} [params.base_url] - The url of the web application where you are installing the router.
* @param {string} [params.client_id] - The client id.
* @param {string} [params.client_secret] - The client secret, only required for some grants.
* @param {Object} [params.authorizationParams] - The parameters for the authorization call.
* @param {string} [params.authorizationParams.response_type=id_token] - The response type.
* @param {string} [params.authorizationParams.response_mode=form_post] - The response mode.
* @param {string} [params.authorizationParams.scope=openid profile email] - The scope.
* @returns {express.Router} the router
*/
module.exports.routes = function(params) {
  params = typeof params == 'object' ? _.cloneDeep(params) : {};

  //TODO: remove this next major version.
  if (typeof params.client_url !== 'undefined') {
    deprecate('client_url', 'the parameter is deprecated, please use base_url instead');
    params.base_url = params.client_url;
  }

  //TODO: remove this next major version.
  if (typeof params.issuer_url !== 'undefined') {
    deprecate('issuer_url', 'the parameter is deprecated, please use issuer_base_url instead');
    params.issuer_base_url = params.issuer_url;
  }

  loadFromEnv(params);

  const paramsValidation = Joi.validate(params, paramsSchema);

  if(paramsValidation.error) {
    throw new Error(paramsValidation.error.details[0].message);
  }

  const authorizeParams = buildAutorizeParams(params);

  const router = express.Router();

  const getClient = _.memoize(async function() {
    return await buildClient(params, authorizeParams);
  });

  function getRedirectUri(req) {
    return urlJoin(params.base_url, req.baseUrl || '', '/callback');
  }

  router.get('/login', async (req, res, next) => {
    next = cb(next).once();
    try {
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
    } catch(err) {
      next(err);
    }
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

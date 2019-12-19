const express = require('express');
const cb = require('cb');
const createError = require('http-errors');
const cookieParser = require('cookie-parser');

const { get: getConfig } = require('../lib/config');
const { get: getClient } = require('../lib/client');
const requiresAuth = require('./requiresAuth');
const transient =  require('../lib/transientHandler');
const { RequestContext, ResponseContext } = require('../lib/context');
const idSession = require('../lib/session');

/**
* Returns a router with two routes /login and /callback
*
* @param {Object} [params] The parameters object
* @param {string} [params.issuerBaseURL] The url address for the token issuer.
* @param {string} [params.baseURL] The url of the web application where you are installing the router.
* @param {string} [params.clientID] The client id.
* @param {string} [params.clientSecret] The client secret, only required for some grants.
* @param {string} [params.clockTolerance] The clock's tolerance in seconds for token verification.
* @param {Function} [params.getUser] An async function receiving a tokenset and returning the profile for req.user.
* @param {boolean|Function} [params.required=true] a boolean to indicate that every route after this middleware requires authentication or
* a function receiving a request and return a boolean to determine which routes needs authentication.
* @param {boolean} [params.errorOnRequiredAuth=false] automatically handle unauthorized errors by triggering the authentication process
* @param {boolean} [params.idpLogout=false] logout the user from the identity provider on logout
* @param {boolean} [params.auth0Logout=false] use the auth0's logout mechanism if OpenID Connect session management is not supported
* @param {boolean|Function} [params.routes=true] a boolean indicating if the routes /login and /logout should be added to the application
* @param {string} [params.redirectUriPath=/callback] The path for the redirect uri, defaults to /callback.
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

  // Only use the internal cookie-based session if sessionSecret is provided.
  if (config.sessionSecret) {
    router.use(idSession({
      cookieName: config.sessionName,
      propertyName: config.sessionName,
      secret: config.sessionSecret,
      duration: config.sessionLength,
      ephemeral: config.sessionEphemeral,
      // TODO: cookieOptions: { domain, httpOnly, path, secure, sameSite }
    }));
  }

  router.use(async (req, res, next) => {
    req.openid = new RequestContext(config, req, res, next);
    try {
      await req.openid.load();
    } catch(err) {
      next(err);
    }
    res.openid = new ResponseContext(config, req, res, next);
    req.isAuthenticated = () => req.openid.isAuthenticated;
    next();
  });

  if (config.routes) {
    router.get(config.loginPath, express.urlencoded({ extended: false }), (req, res) => {
      res.openid.login({ returnTo: config.baseURL });
    });
    router.get(config.logoutPath, (req, res) => res.openid.logout());
  }

  let callbackMethod;

  switch (authorizeParams.response_mode) {
    case 'form_post':
      callbackMethod = 'post';
      break;
    case 'query':
      callbackMethod = 'get';
      break;
    default:
      callbackMethod = 'get';
  }

  router[callbackMethod](config.redirectUriPath, express.urlencoded({ extended: false }), cookieParser(), async (req, res, next) => {
    next = cb(next).once();
    try {
      const redirect_uri = res.openid.getRedirectUri();
      const client = req.openid.client;
      const transientOpts = { legacySameSiteCookie: config.legacySameSiteCookie };

      let tokenSet;

      try {
        const callbackParams = client.callbackParams(req);
        tokenSet = await client.callback(redirect_uri, callbackParams, {
          nonce: transient.getOnce('nonce', req, res, transientOpts),
          state: transient.getOnce('state', req, res, transientOpts),
          response_type: authorizeParams.response_type,
        });
      } catch (err) {
        throw createError.BadRequest(err.message);
      }

      req.openIdTokens = tokenSet;

      if (config.sessionSecret) {
        let identityClaims = tokenSet.claims();
        // Remove validation claims to reduce stored size.
        ['aud', 'iss', 'exp', 'nonce', 'azp', 'auth_time'].forEach(claim => delete identityClaims[claim]);
        req[config.sessionName].claims = tokenSet.claims();
      }

      next();
    } catch (err) {
      next(err);
    }
  },
  config.handleCallback,
  function (req, res) {
    const transientOpts = { legacySameSiteCookie: config.legacySameSiteCookie };
    const returnTo = transient.getOnce('returnTo', req, res, transientOpts) || config.baseURL;
    res.redirect(returnTo);
  });

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

  //We do this to either speed up the first request
  // or fail fast, the first request
  getClient(config);

  return router;
};

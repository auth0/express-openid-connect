const express = require('express');
const cb = require('cb');
const createError = require('http-errors');
const cookieParser = require('cookie-parser');

const { get: getConfig } = require('../lib/config');
const { get: getClient } = require('../lib/client');
const requiresAuth = require('./requiresAuth');
const transient =  require('../lib/transientHandler');
const { RequestContext, ResponseContext } = require('../lib/context');
const appSession = require('../lib/appSession');
const { decodeState } = require('../lib/hooks/getLoginState');

const enforceLeadingSlash = (path) => {
  return '/' === path.split('')[0] ? path : '/' + path;
};

/**
* Returns a router with two routes /login and /callback
*
* @param {Object} [params] The parameters object; see index.d.ts for types and descriptions.
*
* @returns {express.Router} the router
*/
module.exports = function (params) {
  const config = getConfig(params);
  const authorizeParams = config.authorizationParams;
  const router = express.Router();
  const useAppSession = config.appSession && config.appSession.secret;

  // Only use the internal cookie-based session if appSession secret is provided.
  if (useAppSession) {
    router.use(appSession(config.appSession));
  }

  // Express context and OpenID Issuer discovery.
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

    // Login route, configurable with loginPath.
    router.get(
      enforceLeadingSlash(config.loginPath),
      express.urlencoded({ extended: false }),
      (req, res) => {
        res.openid.login({ returnTo: config.baseURL });
      }
    );

    // Logout route, configured with logoutPath.
    router.get(
      enforceLeadingSlash(config.logoutPath),
      (req, res) => res.openid.logout()
    );
  }

  const callbackMethod = ('form_post' === authorizeParams.response_mode ? 'post' : 'get');
  const transientOpts = { legacySameSiteCookie: config.legacySameSiteCookie };

  // Callback route, configured with redirectUriPath.
  router[callbackMethod](
    enforceLeadingSlash(config.redirectUriPath),
    express.urlencoded({ extended: false }),
    cookieParser(),
    async (req, res, next) => {
      next = cb(next).once();
      try {
        const redirectUri = res.openid.getRedirectUri();
        const client = req.openid.client;

        const returnedState = transient.getOnce('state', req, res, transientOpts);

        let tokenSet;
        try {
          const callbackParams = client.callbackParams(req);
          tokenSet = await client.callback(redirectUri, callbackParams, {
            nonce: transient.getOnce('nonce', req, res, transientOpts),
            state: returnedState,
            response_type: authorizeParams.response_type,
          });
        } catch (err) {
          throw createError.BadRequest(err.message);
        }

        req.openidState = decodeState(returnedState);
        req.openidTokens = tokenSet;

        if (useAppSession) {
          let identityClaims = tokenSet.claims();

          config.identityClaimFilter.forEach(claim => {
            delete identityClaims[claim];
          });

          req[config.appSession.name].claims = identityClaims;
        }

        next();
      } catch (err) {
        next(err);
      }
    },
    config.handleCallback,
    function (req, res) {
      res.redirect(req.openidState.returnTo || config.baseURL);
    }
  );

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

  // Fail on initialization if config is invalid.
  getClient(config);

  return router;
};

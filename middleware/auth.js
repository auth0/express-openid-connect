const express = require('express');

const debug = require('../lib/debug')('auth');
const { get: getConfig } = require('../lib/config');
const { requiresAuth } = require('./requiresAuth');
const attemptSilentLogin = require('./attemptSilentLogin');
const TransientCookieHandler = require('../lib/transientHandler');
const { RequestContext, ResponseContext } = require('../lib/context');
const appSession = require('../lib/appSession');
const isLoggedOut = require('../lib/hooks/backchannelLogout/isLoggedOut');

const enforceLeadingSlash = (path) => {
  return path.split('')[0] === '/' ? path : '/' + path;
};

/**
 * Returns a router with two routes /login and /callback
 *
 * @param {Object} [params] The parameters object; see index.d.ts for types and descriptions.
 *
 * @returns {express.Router} the router
 */
const auth = function (params) {
  const config = getConfig(params);
  debug('configuration object processed, resulting configuration: %O', config);
  const router = new express.Router();
  const transient = new TransientCookieHandler(config);

  router.use(appSession(config));

  // Express context and OpenID Issuer discovery.
  router.use(async (req, res, next) => {
    req.oidc = new RequestContext(config, req, res, next);
    res.oidc = new ResponseContext(config, req, res, next, transient);
    next();
  });

  // Login route, configurable with routes.login
  if (config.routes.login) {
    const path = enforceLeadingSlash(config.routes.login);
    debug('adding GET %s route', path);
    router.get(path, express.urlencoded({ extended: false }), (req, res) =>
      res.oidc.login({ returnTo: config.baseURL })
    );
  } else {
    debug('login handling route not applied');
  }

  // Logout route, configurable with routes.logout
  if (config.routes.logout) {
    const path = enforceLeadingSlash(config.routes.logout);
    debug('adding GET %s route', path);
    router.get(path, (req, res) => res.oidc.logout());
  } else {
    debug('logout handling route not applied');
  }

  // Callback route, configured with routes.callback.
  if (config.routes.callback) {
    const path = enforceLeadingSlash(config.routes.callback);
    debug('adding GET %s route', path);
    router.get(path, (req, res) => res.oidc.callback());
    debug('adding POST %s route', path);
    router.post(path, express.urlencoded({ extended: false }), (req, res) =>
      res.oidc.callback()
    );
  } else {
    debug('callback handling route not applied');
  }

  if (config.backchannelLogout) {
    const path = enforceLeadingSlash(config.routes.backchannelLogout);
    debug('adding POST %s route', path);
    router.post(path, express.urlencoded({ extended: false }), (req, res) =>
      res.oidc.backchannelLogout()
    );

    if (config.backchannelLogout.isLoggedOut !== false) {
      const isLoggedOutFn = config.backchannelLogout.isLoggedOut || isLoggedOut;
      router.use(async (req, res, next) => {
        if (!req.oidc.isAuthenticated()) {
          next();
          return;
        }
        try {
          const loggedOut = await isLoggedOutFn(req, config);
          if (loggedOut) {
            req[config.session.name] = undefined;
          }
          next();
        } catch (e) {
          next(e);
        }
      });
    }
  }

  if (config.authRequired) {
    debug(
      'authentication is required for all routes this middleware is applied to'
    );
    router.use(requiresAuth());
  } else {
    debug(
      'authentication is not required for any of the routes this middleware is applied to ' +
        'see and apply `requiresAuth` middlewares to your protected resources'
    );
  }
  if (config.attemptSilentLogin) {
    debug("silent login will be attempted on end-user's initial HTML request");
    router.use(attemptSilentLogin());
  }

  return router;
};

/**
 * Used for instantiating a custom session store. eg
 *
 * ```js
 * const { auth } = require('express-openid-connect');
 * const MemoryStore = require('memorystore')(auth);
 * ```
 *
 * @constructor
 */
auth.Store = function () {};

module.exports = auth;

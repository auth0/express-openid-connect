const express = require('express');
const cb = require('cb');
const createError = require('http-errors');

const debug = require('../lib/debug')('auth');
const { get: getConfig } = require('../lib/config');
const { get: getClient } = require('../lib/client');
const { requiresAuth } = require('./requiresAuth');
const attemptSilentLogin = require('./attemptSilentLogin');
const TransientCookieHandler = require('../lib/transientHandler');
const { RequestContext, ResponseContext } = require('../lib/context');
const appSession = require('../lib/appSession');
const { regenerateSessionStoreId, replaceSession } = appSession;
const { decodeState } = require('../lib/hooks/getLoginState');

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
  {
    let client;
    const path = enforceLeadingSlash(config.routes.callback);
    const callbackStack = [
      (req, res, next) => {
        debug('%s %s called', req.method, path);
        next();
      },
      async (req, res, next) => {
        next = cb(next).once();

        client =
          client ||
          (await getClient(config).catch((err) => {
            next(err);
          }));

        if (!client) {
          return;
        }

        try {
          const redirectUri = res.oidc.getRedirectUri();

          let tokenSet;

          try {
            const callbackParams = client.callbackParams(req);
            const authVerification = transient.getOnce(
              config.transactionCookie.name,
              req,
              res
            );

            const { max_age, code_verifier, nonce, state } = authVerification
              ? JSON.parse(authVerification)
              : {};

            req.openidState = decodeState(state);
            const checks = {
              max_age,
              code_verifier,
              nonce,
              state,
            };

            let extras;
            if (config.tokenEndpointParams) {
              extras = { exchangeBody: config.tokenEndpointParams };
            }

            tokenSet = await client.callback(
              redirectUri,
              callbackParams,
              checks,
              extras
            );
          } catch (err) {
            throw createError(400, err.message, {
              error: err.error,
              error_description: err.error_description,
            });
          }

          let session = Object.assign({}, tokenSet); // Remove non-enumerable methods from the TokenSet

          if (config.afterCallback) {
            session = await config.afterCallback(
              req,
              res,
              session,
              req.openidState
            );
          }

          if (req.oidc.isAuthenticated()) {
            if (req.oidc.user.sub === tokenSet.claims().sub) {
              // If it's the same user logging in again, just update the existing session.
              Object.assign(req[config.session.name], session);
            } else {
              // If it's a different user, replace the session to remove any custom user
              // properties on the session
              replaceSession(req, session, config);
              // And regenerate the session id so the previous user wont know the new user's session id
              regenerateSessionStoreId(req, config);
            }
          } else {
            // If a new user is replacing an anonymous session, update the existing session to keep
            // any anonymous session state (eg. checkout basket)
            Object.assign(req[config.session.name], session);
            // But update the session store id so a previous anonymous user wont know the new user's session id
            regenerateSessionStoreId(req, config);
          }
          attemptSilentLogin.resumeSilentLogin(req, res);

          next();
        } catch (err) {
          // Swallow errors if this is a silentLogin
          if (req.openidState && req.openidState.attemptingSilentLogin) {
            next();
          } else {
            next(err);
          }
        }
      },
      (req, res) => res.redirect(req.openidState.returnTo || config.baseURL),
    ];

    debug('adding GET %s route', path);
    router.get(path, ...callbackStack);
    debug('adding POST %s route', path);
    router.post(
      path,
      express.urlencoded({ extended: false }),
      ...callbackStack
    );
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

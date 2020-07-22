const express = require('express');
const cb = require('cb');
const createError = require('http-errors');

const debug = require('../lib/debug');
const { get: getConfig } = require('../lib/config');
const { get: getClient } = require('../lib/client');
const { requiresAuth } = require('./requiresAuth');
const TransientCookieHandler = require('../lib/transientHandler');
const { RequestContext, ResponseContext } = require('../lib/context');
const appSession = require('../lib/appSession');
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
module.exports = function (params) {
  const config = getConfig(params);
  debug.trace(
    'configuration object processed, resulting configuration:',
    config
  );
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
    debug.trace(`adding GET ${path} route`);
    router.get(path, express.urlencoded({ extended: false }), (req, res) =>
      res.oidc.login({ returnTo: config.baseURL })
    );
  } else {
    debug.trace('login handling route not applied');
  }

  // Logout route, configurable with routes.logout
  if (config.routes.logout) {
    const path = enforceLeadingSlash(config.routes.logout);
    debug.trace(`adding GET ${path} route`);
    router.get(path, (req, res) => res.oidc.logout());
  } else {
    debug.trace('logout handling route not applied');
  }

  // Callback route, configured with routes.callback.
  {
    let client;
    const path = enforceLeadingSlash(config.routes.callback);
    const callbackStack = [
      (req, res, next) => {
        debug.trace(`${req.method} ${path} called`);
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

          let expectedState;
          let tokenSet;
          try {
            const callbackParams = client.callbackParams(req);
            expectedState = transient.getOnce('state', req, res);
            const max_age = parseInt(
              transient.getOnce('max_age', req, res),
              10
            );
            const code_verifier = transient.getOnce('code_verifier', req, res);
            const nonce = transient.getOnce('nonce', req, res);

            tokenSet = await client.callback(redirectUri, callbackParams, {
              max_age,
              code_verifier,
              nonce,
              state: expectedState,
            });
          } catch (err) {
            throw createError.BadRequest(err.message);
          }

          // TODO:?
          req.openidState = decodeState(expectedState);

          // intentional clone of the properties on tokenSet
          Object.assign(req[config.session.name], {
            id_token: tokenSet.id_token,
            access_token: tokenSet.access_token,
            refresh_token: tokenSet.refresh_token,
            token_type: tokenSet.token_type,
            expires_at: tokenSet.expires_at,
          });

          next();
        } catch (err) {
          next(err);
        }
      },
      (req, res) => res.redirect(req.openidState.returnTo || config.baseURL),
    ];

    debug.trace(`adding GET ${path} route`);
    router.get(path, ...callbackStack);
    debug.trace(`adding POST ${path} route`);
    router.post(
      path,
      express.urlencoded({ extended: false }),
      ...callbackStack
    );
  }

  if (config.authRequired) {
    debug.trace(
      'authentication is required for all routes this middleware is applied to'
    );
    router.use(requiresAuth());
  } else {
    debug.trace(
      'authentication is not required for any of the routes this middleware is applied to ' +
        'see and apply `requiresAuth` middlewares to your protected resources'
    );
  }

  return router;
};

const url = require('url');
const urlJoin = require('url-join');
const { JWT } = require('jose');
const { TokenSet } = require('openid-client');
const clone = require('clone');

const { strict: assert } = require('assert');
const createError = require('http-errors');

const debug = require('./debug')('context');
const { once } = require('./once');
const { get: getClient } = require('./client');
const { getIssuerManager } = require('./issuerManager');
const { encodeState, decodeState } = require('../lib/hooks/getLoginState');
const onLogin = require('./hooks/backchannelLogout/onLogIn');
const onLogoutToken = require('./hooks/backchannelLogout/onLogoutToken');
const {
  cancelSilentLogin,
  resumeSilentLogin,
} = require('../middleware/attemptSilentLogin');
const weakRef = require('./weakCache');
const {
  regenerateSessionStoreId,
  replaceSession,
} = require('../lib/appSession');

/**
 * Normalize issuer URL for comparison.
 * Removes trailing slashes to handle cases where resolver returns
 * 'https://tenant.auth0.com' but discovery metadata returns
 * 'https://tenant.auth0.com/' (or vice versa).
 *
 * @param {string} issuerUrl - The issuer URL to normalize
 * @returns {string} Normalized URL without trailing slash
 */
function normalizeIssuerUrl(issuerUrl) {
  if (!issuerUrl) return issuerUrl;
  return issuerUrl.replace(/\/+$/, '');
}

function isExpired() {
  return tokenSet.call(this).expired();
}

async function refresh({ tokenEndpointParams } = {}) {
  let { config, req } = weakRef(this);
  const session = req[config.session.name];
  const oldTokenSet = tokenSet.call(this);

  // MCD: Use session's issuer for token refresh
  // Tokens issued by Tenant A can only be refreshed by Tenant A's token endpoint
  let client, issuer;
  const sessionIssuer = session.issuer;

  if (sessionIssuer) {
    // Session has issuer - use it for refresh (MCD mode or new sessions)
    debug('refreshing token using session issuer: %s', sessionIssuer);
    const issuerManager = getIssuerManager();
    ({ client, issuer } = await issuerManager.getClient(sessionIssuer, config));
  } else if (typeof config.issuerBaseURL === 'function') {
    // MCD mode but session missing issuer - this shouldn't happen for valid sessions
    throw new Error('Cannot refresh token: session missing issuer in MCD mode');
  } else {
    // Static issuer mode (backward compatible)
    ({ client, issuer } = await getClient(config));
  }

  let extras;
  if (config.tokenEndpointParams || tokenEndpointParams) {
    extras = {
      exchangeBody: { ...config.tokenEndpointParams, ...tokenEndpointParams },
    };
  }

  const newTokenSet = await client.refresh(oldTokenSet, {
    ...extras,
    clientAssertionPayload: {
      aud: issuer.issuer,
    },
  });

  // Update the session
  Object.assign(session, {
    access_token: newTokenSet.access_token,
    // If no new ID token assume the current ID token is valid.
    id_token: newTokenSet.id_token || oldTokenSet.id_token,
    // If no new refresh token assume the current refresh token is valid.
    refresh_token: newTokenSet.refresh_token || oldTokenSet.refresh_token,
    token_type: newTokenSet.token_type,
    expires_at: newTokenSet.expires_at,
  });

  // MCD: Preserve issuer in session after refresh
  if (sessionIssuer) {
    session.issuer = sessionIssuer;
  }

  // Delete the old token set
  const cachedTokenSet = weakRef(session);
  delete cachedTokenSet.value;

  return this.accessToken;
}

function tokenSet() {
  const contextCache = weakRef(this);
  const session = contextCache.req[contextCache.config.session.name];

  if (!session || !('id_token' in session)) {
    return undefined;
  }

  const cachedTokenSet = weakRef(session);

  if (!('value' in cachedTokenSet)) {
    const { id_token, access_token, refresh_token, token_type, expires_at } =
      session;
    cachedTokenSet.value = new TokenSet({
      id_token,
      access_token,
      refresh_token,
      token_type,
      expires_at,
    });
  }

  return cachedTokenSet.value;
}

class RequestContext {
  constructor(config, req, res, next) {
    Object.assign(weakRef(this), { config, req, res, next });
  }

  isAuthenticated() {
    return !!this.idTokenClaims;
  }

  get idToken() {
    try {
      return tokenSet.call(this).id_token;
    } catch {
      return undefined;
    }
  }

  get refreshToken() {
    try {
      return tokenSet.call(this).refresh_token;
    } catch {
      return undefined;
    }
  }

  get accessToken() {
    try {
      const { access_token, token_type, expires_in } = tokenSet.call(this);

      if (!access_token || !token_type || typeof expires_in !== 'number') {
        return undefined;
      }

      return {
        access_token,
        token_type,
        expires_in,
        isExpired: isExpired.bind(this),
        refresh: refresh.bind(this),
      };
    } catch {
      return undefined;
    }
  }

  get idTokenClaims() {
    try {
      const {
        config: { session },
        req,
      } = weakRef(this);

      // The ID Token from Auth0's Refresh Grant doesn't contain a "sid"
      // so we should check the backup sid we stored at login.
      const { sid } = req[session.name];
      return { sid, ...clone(tokenSet.call(this).claims()) };
    } catch {
      return undefined;
    }
  }

  get user() {
    try {
      const {
        config: { identityClaimFilter },
      } = weakRef(this);
      const { idTokenClaims } = this;
      const user = clone(idTokenClaims);
      identityClaimFilter.forEach((claim) => {
        delete user[claim];
      });
      return user;
    } catch {
      return undefined;
    }
  }

  async fetchUserInfo() {
    const { config, req } = weakRef(this);
    const session = req[config.session.name];

    // Use session's issuer for userinfo request (same pattern as refresh)
    // In MCD mode, config.issuerBaseURL is a function, so we must use the
    // issuer stored in the session to call the correct userinfo endpoint.
    let client;
    const sessionIssuer = session && session.issuer;

    if (sessionIssuer) {
      // Session has issuer - use it for userinfo (MCD mode or new sessions)
      const issuerManager = getIssuerManager();
      ({ client } = await issuerManager.getClient(sessionIssuer, config));
    } else if (typeof config.issuerBaseURL === 'function') {
      // MCD mode but session missing issuer - this shouldn't happen for valid sessions
      throw new Error(
        'Cannot fetch user info: session missing issuer in dynamic issuer mode',
      );
    } else {
      // Static issuer mode (backward compatible)
      ({ client } = await getClient(config));
    }

    return client.userinfo(tokenSet.call(this));
  }
}

class ResponseContext {
  constructor(config, req, res, next, transient) {
    Object.assign(weakRef(this), { config, req, res, next, transient });
  }

  get errorOnRequiredAuth() {
    return weakRef(this).config.errorOnRequiredAuth;
  }

  /**
   * Get the base URL for redirects.
   *
   * In MCD mode (issuerBaseURL is a function), derives the base URL from the request
   * to support multi-domain deployments. In static mode, uses config.baseURL.
   *
   * @returns {string} The base URL
   */
  getBaseUrl() {
    const { config, req } = weakRef(this);
    if (typeof config.issuerBaseURL === 'function') {
      // MCD mode: derive base URL from request to support multi-domain deployments
      const protocol = req.protocol || (req.secure ? 'https' : 'http');
      const host = req.get('host') || req.hostname;
      return `${protocol}://${host}`;
    }
    // Static mode: use configured baseURL
    return config.baseURL;
  }

  /**
   * Get the redirect URI for OIDC callback.
   *
   * In MCD mode (issuerBaseURL is a function), the redirect_uri is derived from the
   * request to support multi-domain deployments where users access the app via different
   * domains (e.g., us.myapp.com, eu.myapp.com). This ensures:
   * 1. Transaction cookies are sent correctly (cookies are domain-specific)
   * 2. The redirect_uri matches what's registered in Auth0 for each domain
   *
   * In static mode, uses config.baseURL for backward compatibility.
   *
   * @returns {string} The redirect URI
   */
  getRedirectUri() {
    const { config } = weakRef(this);
    if (config.routes.callback) {
      return urlJoin(this.getBaseUrl(), config.routes.callback);
    }
  }

  silentLogin(options = {}) {
    return this.login({
      ...options,
      silent: true,
      authorizationParams: { ...options.authorizationParams, prompt: 'none' },
    });
  }

  async login(options = {}) {
    let { config, req, res, next, transient } = weakRef(this);
    next = once(next);
    try {
      // MCD: Dynamically resolve issuer based on request context
      let client, issuer, resolvedIssuerUrl;

      if (typeof config.issuerBaseURL === 'function') {
        // Dynamic issuer resolution (MCD mode)
        const issuerManager = getIssuerManager();

        const context = {
          req,
        };

        debug('resolving issuer dynamically from request context');
        resolvedIssuerUrl = await issuerManager.resolveIssuer(config, context);
        debug('resolved issuer: %s', resolvedIssuerUrl);

        ({ client, issuer } = await issuerManager.getClient(
          resolvedIssuerUrl,
          config,
        ));
      } else {
        // Static issuer (backward compatible)
        resolvedIssuerUrl = config.issuerBaseURL;
        ({ client, issuer } = await getClient(config));
      }

      // Set default returnTo value, allow passed-in options to override or use originalUrl on GET
      let returnTo = this.getBaseUrl();
      if (options.returnTo) {
        returnTo = options.returnTo;
        debug('req.oidc.login() called with returnTo: %s', returnTo);
      } else if (req.method === 'GET' && req.originalUrl) {
        // Collapse any leading slashes to a single slash to prevent Open Redirects
        returnTo = req.originalUrl.replace(/^\/+/, '/');
        debug('req.oidc.login() without returnTo, using: %s', returnTo);
      }

      options = {
        authorizationParams: {},
        returnTo,
        ...options,
      };

      // Ensure a redirect_uri, merge in configuration options, then passed-in options.
      options.authorizationParams = {
        redirect_uri: this.getRedirectUri(),
        ...config.authorizationParams,
        ...options.authorizationParams,
      };

      const stateValue = await config.getLoginState(req, options);
      if (typeof stateValue !== 'object') {
        next(new Error('Custom state value must be an object.'));
      }

      if (options.silent) {
        stateValue.attemptingSilentLogin = true;
      }

      const validResponseTypes = ['id_token', 'code id_token', 'code'];
      assert(
        validResponseTypes.includes(options.authorizationParams.response_type),
        `response_type should be one of ${validResponseTypes.join(', ')}`,
      );
      assert(
        /\bopenid\b/.test(options.authorizationParams.scope),
        'scope should contain "openid"',
      );

      const authVerification = {
        nonce: transient.generateNonce(),
        state: encodeState(stateValue),
        ...(options.authorizationParams.max_age
          ? {
              max_age: options.authorizationParams.max_age,
            }
          : undefined),
        // MCD: Store the resolved issuer URL for validation in callback
        origin_issuer: resolvedIssuerUrl,
      };

      // Build auth params - exclude origin_issuer as it's only for local storage
      const { origin_issuer, ...authVerificationForRequest } = authVerification;
      let authParams = {
        ...options.authorizationParams,
        ...authVerificationForRequest,
      };

      const usePKCE =
        options.authorizationParams.response_type.includes('code');
      if (usePKCE) {
        debug(
          'response_type includes code, the authorization request will use PKCE',
        );
        authVerification.code_verifier = transient.generateCodeVerifier();

        authParams.code_challenge_method = 'S256';
        authParams.code_challenge = transient.calculateCodeChallenge(
          authVerification.code_verifier,
        );
      }

      if (config.pushedAuthorizationRequests) {
        const { request_uri } = await client.pushedAuthorizationRequest(
          authParams,
          {
            clientAssertionPayload: {
              aud: issuer.issuer,
            },
          },
        );
        authParams = { request_uri };
      }

      transient.store(config.transactionCookie.name, req, res, {
        sameSite:
          options.authorizationParams.response_mode === 'form_post'
            ? 'None'
            : config.transactionCookie.sameSite,
        value: JSON.stringify(authVerification),
      });

      const authorizationUrl = client.authorizationUrl(authParams);
      debug('redirecting to %s', authorizationUrl);
      res.redirect(authorizationUrl);
    } catch (err) {
      next(err);
    }
  }

  async logout(params = {}) {
    let { config, req, res, next } = weakRef(this);
    next = once(next);
    let returnURL = params.returnTo || config.routes.postLogoutRedirect;
    debug('req.oidc.logout() with return url: %s', returnURL);

    try {
      // MCD: Use session's issuer for logout
      // Logout should go to the issuer that created the session
      let client;
      const session = req[config.session.name];
      const sessionIssuer = session && session.issuer;

      if (sessionIssuer) {
        // Session has issuer - use it for logout (MCD mode or new sessions)
        debug('logging out using session issuer: %s', sessionIssuer);
        const issuerManager = getIssuerManager();
        ({ client } = await issuerManager.getClient(sessionIssuer, config));
      } else if (typeof config.issuerBaseURL === 'function') {
        // MCD mode but no session or session missing issuer
        // Resolve current issuer for logout URL (user may not be authenticated)
        debug('MCD mode: resolving current issuer for logout');
        const issuerManager = getIssuerManager();
        const context = { req };
        const currentIssuer = await issuerManager.resolveIssuer(
          config,
          context,
        );
        ({ client } = await issuerManager.getClient(currentIssuer, config));
      } else {
        // Static issuer mode (backward compatible)
        ({ client } = await getClient(config));
      }

      /**
       * Generates the logout URL.
       *
       * Depending on the configuration, this function will either perform a local only logout
       * or a federated logout by redirecting to the appropriate URL.
       *
       * @param {string} idTokenHint - The ID token hint to be used for the logout request.
       * @returns {string} The URL to redirect the user to for logout.
       */
      const getLogoutUrl = (idTokenHint) => {
        // if idpLogout is not configured, perform a local only logout
        if (!config.idpLogout) {
          debug('performing a local only logout, redirecting to %s', returnURL);
          return returnURL;
        }

        // if idpLogout is configured, perform a federated logout
        return client.endSessionUrl({
          ...config.logoutParams,
          ...(idTokenHint && { id_token_hint: idTokenHint }),
          post_logout_redirect_uri: returnURL,
          ...params.logoutParams,
        });
      };

      if (url.parse(returnURL).host === null) {
        returnURL = urlJoin(this.getBaseUrl(), returnURL);
      }

      cancelSilentLogin(req, res);

      if (!req.oidc.isAuthenticated()) {
        debug('end-user already logged out, redirecting to %s', returnURL);

        // perform idp logout with no token hint
        return res.redirect(getLogoutUrl(undefined));
      }

      const { idToken: id_token_hint } = req.oidc;
      req[config.session.name] = undefined;

      returnURL = getLogoutUrl(id_token_hint);
    } catch (err) {
      return next(err);
    }

    debug('logging out of identity provider, redirecting to %s', returnURL);
    res.redirect(returnURL);
  }

  async callback(options = {}) {
    let { config, req, res, transient, next } = weakRef(this);
    next = once(next);
    try {
      // IMPORTANT: Transaction cookie must be consumed early to determine which issuer to use.
      //
      // For dynamic issuer resolution, we need the origin_issuer from the transaction state
      // BEFORE we can create the OIDC client (since different issuers have different clients).
      //
      // Trade-off: This changes error recovery behavior. Previously, if an error occurred
      // before the cookie was read, the user could retry. Now, the cookie is consumed
      // immediately - if discovery fails or issuer validation throws, the transaction
      // cookie is gone and the user must restart the entire login flow.
      //
      // This is an inherent design constraint for dynamic issuer resolution and cannot
      // be avoided without storing the origin_issuer elsewhere (which would require
      // additional state management complexity).
      const authVerification = transient.getOnce(
        config.transactionCookie.name,
        req,
        res,
      );

      const checks = authVerification ? JSON.parse(authVerification) : {};

      // Determine issuer - use origin_issuer from transaction or resolve dynamically
      let client, issuer;
      const originIssuer = checks.origin_issuer;

      if (originIssuer) {
        // Use the issuer from the transaction state (MCD mode or static mode with origin_issuer)
        debug('using origin_issuer from transaction: %s', originIssuer);

        if (typeof config.issuerBaseURL === 'function') {
          // Dynamic issuer mode - get client from IssuerManager
          const issuerManager = getIssuerManager();
          ({ client, issuer } = await issuerManager.getClient(
            originIssuer,
            config,
          ));
        } else {
          // Static issuer mode - validate origin_issuer matches config
          if (originIssuer !== config.issuerBaseURL) {
            throw createError(
              400,
              'Issuer mismatch: transaction was started with a different issuer',
              {
                error: 'issuer_mismatch',
                error_description:
                  'The transaction was started with a different issuer than configured',
              },
            );
          }
          ({ client, issuer } = await getClient(config));
        }

        // Validate issuer matches what we expected (normalize URLs for comparison)
        // This handles cases where resolver returns 'https://tenant.auth0.com'
        // but discovery metadata returns 'https://tenant.auth0.com/' (with trailing slash)
        if (
          normalizeIssuerUrl(issuer.issuer) !== normalizeIssuerUrl(originIssuer)
        ) {
          throw createError(
            400,
            'Issuer mismatch: potential issuer substitution attack',
            {
              error: 'issuer_mismatch',
              error_description:
                'The issuer in the metadata does not match the expected issuer',
            },
          );
        }
      } else {
        // No origin_issuer in transaction - backward compatibility for static issuer mode
        // In MCD mode (issuerBaseURL is a function), we cannot proceed without origin_issuer
        // because getClient() would pass the function to Issuer.discover() which only accepts strings.
        // This path is reached when: transaction cookie is missing, signature verification fails,
        // or user replays the callback URL.
        if (typeof config.issuerBaseURL === 'function') {
          throw createError(
            400,
            'Invalid or missing transaction state for callback in dynamic issuer mode',
            {
              error: 'invalid_request',
              error_description:
                'The authentication transaction has expired or is invalid. Please start the login process again.',
            },
          );
        }
        debug('no origin_issuer in transaction, using default client');
        ({ client, issuer } = await getClient(config));
      }

      const redirectUri = options.redirectUri || this.getRedirectUri();

      let tokenSet;
      try {
        const callbackParams = client.callbackParams(req);

        req.openidState = decodeState(checks.state);

        tokenSet = await client.callback(redirectUri, callbackParams, checks, {
          exchangeBody: {
            ...(config && config.tokenEndpointParams),
            ...options.tokenEndpointParams,
          },
          clientAssertionPayload: {
            aud: issuer.issuer,
          },
        });
      } catch (error) {
        throw createError(400, error.message, {
          error: error.error,
          error_description: error.error_description,
        });
      }

      let session = Object.assign({}, tokenSet); // Remove non-enumerable methods from the TokenSet
      const claims = tokenSet.claims();
      // Must store the `sid` separately as the ID Token gets overridden by
      // ID Token from the Refresh Grant which may not contain a sid (In Auth0 currently).
      session.sid = claims.sid;

      // MCD: Store the issuer in session for token refresh and logout
      session.issuer = issuer.issuer;

      if (config.afterCallback) {
        session = await config.afterCallback(
          req,
          res,
          session,
          req.openidState,
        );
      }

      if (req.oidc.isAuthenticated()) {
        if (req.oidc.user.sub === claims.sub) {
          // If it's the same user logging in again, just update the existing session.
          Object.assign(req[config.session.name], session);
        } else {
          // If it's a different user, replace the session to remove any custom user
          // properties on the session
          replaceSession(req, session, config);
          // And regenerate the session id so the previous user wont know the new user's session id
          await regenerateSessionStoreId(req, config);
        }
      } else {
        // If a new user is replacing an anonymous session, update the existing session to keep
        // any anonymous session state (eg. checkout basket)
        Object.assign(req[config.session.name], session);
        // But update the session store id so a previous anonymous user wont know the new user's session id
        await regenerateSessionStoreId(req, config);
      }
      resumeSilentLogin(req, res);

      if (
        req.oidc.isAuthenticated() &&
        config.backchannelLogout &&
        config.backchannelLogout.onLogin !== false
      ) {
        await (config.backchannelLogout.onLogin || onLogin)(req, config);
      }
    } catch (err) {
      if (!req.openidState || !req.openidState.attemptingSilentLogin) {
        return next(err);
      }
    }
    res.redirect(req.openidState.returnTo || this.getBaseUrl());
  }

  async backchannelLogout() {
    let { config, req, res } = weakRef(this);
    res.setHeader('cache-control', 'no-store');
    const logoutToken = req.body.logout_token;
    if (!logoutToken) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing logout_token',
      });
      return;
    }
    const onToken =
      (config.backchannelLogout && config.backchannelLogout.onLogoutToken) ||
      onLogoutToken;
    let token;
    try {
      let issuer;

      if (typeof config.issuerBaseURL === 'function') {
        // MCD mode: Extract issuer from unverified token to determine which issuer to verify against.
        // This is safe because we still verify the token signature after getting the issuer's keys.
        // If the token was tampered with, verification will fail.
        const parts = logoutToken.split('.');
        if (parts.length !== 3) {
          res.status(400).json({
            error: 'invalid_request',
            error_description: 'Invalid logout_token format',
          });
          return;
        }

        let payload;
        try {
          payload = JSON.parse(
            Buffer.from(parts[1], 'base64url').toString('utf8'),
          );
        } catch {
          res.status(400).json({
            error: 'invalid_request',
            error_description: 'Invalid logout_token payload',
          });
          return;
        }

        const tokenIssuer = payload.iss;
        if (!tokenIssuer || typeof tokenIssuer !== 'string') {
          res.status(400).json({
            error: 'invalid_request',
            error_description: 'logout_token missing iss claim',
          });
          return;
        }

        // Get the client for this issuer
        const issuerManager = getIssuerManager();
        ({ issuer } = await issuerManager.getClient(tokenIssuer, config));
      } else {
        // Static issuer mode (backward compatible)
        ({ issuer } = await getClient(config));
      }

      const keyInput = await issuer.keystore();

      token = await JWT.LogoutToken.verify(logoutToken, keyInput, {
        issuer: issuer.issuer,
        audience: config.clientID,
        algorithms: [config.idTokenSigningAlg],
      });
    } catch (e) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: e.message,
      });
      return;
    }
    try {
      await onToken(token, config);
    } catch (e) {
      debug('req.oidc.backchannelLogout() failed with: %s', e.message);
      res.status(400).json({
        error: 'application_error',
        error_description: `The application failed to invalidate the session.`,
      });
      return;
    }
    res.status(204).send();
  }
}

module.exports = { RequestContext, ResponseContext };

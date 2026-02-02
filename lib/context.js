import url from 'url';
import urlJoin from 'url-join';
import * as jose from 'jose';
import clone from 'clone';

import { strict as assert } from 'assert';

import debug from './debug.js';
import { once } from './once.js';
import { get as getClient } from './client.js';
import { encodeState, decodeState } from '../lib/hooks/getLoginState.js';
import onLogin from './hooks/backchannelLogout/onLogIn.js';
import onLogoutToken from './hooks/backchannelLogout/onLogoutToken.js';
import {
  cancelSilentLogin,
  resumeSilentLogin,
} from '../middleware/attemptSilentLogin.js';
import weakRef from './weakCache.js';
import { regenerateSessionStoreId, replaceSession } from '../lib/appSession.js';

const debugContext = debug('context');

// Simple helper for token expiration check
function isExpired() {
  const session = weakRef(this).req[weakRef(this).config.session.name];
  if (!session || !session.expires_at) return false;
  return Date.now() >= session.expires_at * 1000;
}

// Refresh token helper - delegates to client
async function refresh({ tokenEndpointParams } = {}) {
  let { config, req } = weakRef(this);

  const { client } = await getClient(config);
  const session = req[config.session.name];

  if (!session || !session.refresh_token) {
    throw new Error('No refresh token available');
  }

  let parameters = {};
  if (config.tokenEndpointParams || tokenEndpointParams) {
    parameters = { ...config.tokenEndpointParams, ...tokenEndpointParams };
  }

  // Use client.refresh - delegates to openid-client v6
  const newTokenSet = await client.refresh(session.refresh_token, parameters);

  // Preserve SID from original session if new ID token doesn't have one
  let preservedSid = session.sid;

  if (newTokenSet.id_token) {
    try {
      const newClaims = jose.decodeJwt(newTokenSet.id_token);
      // Only use new SID if it exists, otherwise keep the original
      if (newClaims.sid) {
        preservedSid = newClaims.sid;
      }
    } catch {
      // If we can't decode the new token, keep the original SID
    }
  }

  // Update session with new tokens
  let sessionUpdate = {
    access_token: newTokenSet.access_token,
    id_token: newTokenSet.id_token || session.id_token,
    refresh_token: newTokenSet.refresh_token || session.refresh_token,
    token_type: newTokenSet.token_type || session.token_type,
    expires_at: newTokenSet.expires_at,
    sid: preservedSid, // Preserve SID across token refresh
  };

  if (newTokenSet.expires_in && typeof newTokenSet.expires_in === 'number') {
    sessionUpdate.expires_at =
      Math.floor(Date.now() / 1000) + newTokenSet.expires_in;
  }

  Object.assign(session, sessionUpdate);

  return {
    access_token: newTokenSet.access_token,
    token_type: newTokenSet.token_type || 'Bearer',
    expires_in: newTokenSet.expires_in,
    isExpired: isExpired.bind(this),
    refresh: refresh.bind(this),
  };
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
      const { config, req } = weakRef(this);
      const session = req[config.session.name];
      return session?.id_token;
    } catch {
      return undefined;
    }
  }

  get refreshToken() {
    try {
      const session = weakRef(this).req[weakRef(this).config.session.name];
      return session?.refresh_token;
    } catch {
      return undefined;
    }
  }

  get accessToken() {
    try {
      const session = weakRef(this).req[weakRef(this).config.session.name];

      if (!session?.access_token || !session?.token_type) {
        return undefined;
      }

      const expires_in = session.expires_at
        ? Math.max(0, session.expires_at - Math.floor(Date.now() / 1000))
        : undefined;

      return {
        access_token: session.access_token,
        token_type: session.token_type,
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
      const { config, req } = weakRef(this);
      const session = req[config.session.name];

      if (!session?.id_token) {
        return undefined;
      }

      // Only decode JWT to read claims - validation was done by openid-client
      const claims = jose.decodeJwt(session.id_token);
      // Use preserved SID from session if available, otherwise use claims SID
      return { ...clone(claims), sid: session.sid || claims.sid };
    } catch {
      return undefined;
    }
  }

  get user() {
    try {
      const { config } = weakRef(this);
      const { idTokenClaims } = this;
      if (!idTokenClaims) {
        return undefined;
      }
      const user = clone(idTokenClaims);
      config.identityClaimFilter.forEach((claim) => {
        delete user[claim];
      });
      return user;
    } catch {
      return undefined;
    }
  }

  async fetchUserInfo() {
    const { config } = weakRef(this);
    const { client } = await getClient(config);

    const accessToken = this.accessToken;
    if (!accessToken) {
      throw new Error('No access token available');
    }

    const expectedSubject = this.idTokenClaims?.sub;

    // Delegate to client.userinfo - handles v6 API internally
    return await client.userinfo(accessToken.access_token, { expectedSubject });
  }
}

class ResponseContext {
  constructor(config, req, res, next, transient) {
    Object.assign(weakRef(this), { config, req, res, next, transient });
  }

  get errorOnRequiredAuth() {
    return weakRef(this).config.errorOnRequiredAuth;
  }

  getRedirectUri() {
    const { config } = weakRef(this);
    if (config.routes.callback) {
      return urlJoin(config.baseURL, config.routes.callback);
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
      const { client, issuer } = await getClient(config);

      // Set default returnTo value, allow passed-in options to override or use originalUrl on GET
      let returnTo = config.baseURL;
      if (options.returnTo) {
        returnTo = options.returnTo;
        debugContext('req.oidc.login() called with returnTo: %s', returnTo);
      } else if (req.method === 'GET' && req.originalUrl) {
        // Collapse any leading slashes to a single slash to prevent Open Redirects
        returnTo = req.originalUrl.replace(/^\/+/, '/');
        debugContext('req.oidc.login() without returnTo, using: %s', returnTo);
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
      };

      let authParams = {
        ...options.authorizationParams,
        ...authVerification,
      };

      const usePKCE =
        options.authorizationParams.response_type.includes('code');
      if (usePKCE) {
        debugContext(
          'response_type includes code, the authorization request will use PKCE',
        );
        authVerification.code_verifier = transient.generateCodeVerifier();

        authParams.code_challenge_method = 'S256';
        authParams.code_challenge = await transient.calculateCodeChallenge(
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
      debugContext('redirecting to %s', authorizationUrl);
      res.redirect(authorizationUrl);
    } catch (err) {
      next(err);
    }
  }

  async logout(params = {}) {
    let { config, req, res, next } = weakRef(this);
    next = once(next);
    let returnURL = params.returnTo || config.routes.postLogoutRedirect;
    debugContext('req.oidc.logout() with return url: %s', returnURL);

    try {
      const { client } = await getClient(config);

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
          debugContext(
            'performing a local only logout, redirecting to %s',
            returnURL,
          );
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
        returnURL = urlJoin(config.baseURL, returnURL);
      }

      cancelSilentLogin(req, res);

      if (!req.oidc.isAuthenticated()) {
        debugContext(
          'end-user already logged out, redirecting to %s',
          returnURL,
        );

        // perform idp logout with no token hint
        return res.redirect(getLogoutUrl(undefined));
      }

      const { idToken: id_token_hint } = req.oidc;
      replaceSession(req, {}, config);

      returnURL = getLogoutUrl(id_token_hint);
    } catch (err) {
      return next(err);
    }

    debugContext(
      'logging out of identity provider, redirecting to %s',
      returnURL,
    );
    res.redirect(returnURL);
  }

  async callback(options = {}) {
    let { config, req, res, transient, next } = weakRef(this);
    next = once(next);

    try {
      const { client, issuer } = await getClient(config);
      const redirectUri = options.redirectUri || this.getRedirectUri();

      // Get callback parameters - trust client.callback() to handle all formats
      const callbackParams = req.method === 'POST' ? req.body : req.query;

      // Get auth verification for checks
      const authVerification = transient.getOnce(
        config.transactionCookie.name,
        req,
        res,
      );

      const checks = authVerification ? JSON.parse(authVerification) : {};
      req.openidState = decodeState(checks.state);

      // Determine if this is a form_post response (POST method)
      const isFormPost = req.method === 'POST';

      // Trust openid-client v6 to handle all OAuth/OIDC validation and flows
      let tokenSet;
      try {
        tokenSet = await client.callback(redirectUri, callbackParams, checks, {
          exchangeBody: {
            ...(config && config.tokenEndpointParams),
            ...options.tokenEndpointParams,
          },
          clientAssertionPayload: {
            aud: issuer.issuer,
          },
          isFormPost,
        });
      } catch (error) {
        // Transform openid-client errors to HTTP errors
        debugContext('openid-client callback error: %O', error);
        const httpError = new Error(error.message);
        httpError.status = 400;
        httpError.error = error.error;
        httpError.error_description = error.error_description;
        throw httpError;
      }

      // Create session from validated tokenSet - it's a plain object in v6
      let session = Object.assign({}, tokenSet);

      // Calculate expires_at from expires_in if present
      if (session.expires_in && typeof session.expires_in === 'number') {
        session.expires_at = Math.floor(Date.now() / 1000) + session.expires_in;
      }

      // Read claims from already-validated ID token (openid-client validated it)
      const claims = jose.decodeJwt(tokenSet.id_token);

      // For SID preservation: In hybrid flows, the authorization endpoint ID token
      // may contain SID even if the token endpoint ID token doesn't
      let sessionSid = claims.sid;
      if (!sessionSid && options.params && options.params.id_token) {
        try {
          // Check if the authorization endpoint ID token has SID
          const authEndpointClaims = jose.decodeJwt(options.params.id_token);
          sessionSid = authEndpointClaims.sid;
        } catch {
          // Ignore errors decoding authorization endpoint ID token
        }
      }

      session.sid = sessionSid;

      // Handle session replacement logic
      const existingSession = req[config.session.name];
      const existingUser =
        existingSession && existingSession.id_token
          ? jose.decodeJwt(existingSession.id_token).sub
          : null;
      const newUser = claims.sub;

      // Session replacement logic - preserve existing semantics
      if (existingSession && existingUser && newUser !== existingUser) {
        // Different user - replace session and regenerate ID
        replaceSession(req, session, config);
        if (config.session.store) {
          await regenerateSessionStoreId(req, config);
        }
      } else if (existingSession && !existingUser && newUser) {
        // New user over anonymous session - preserve session, regenerate ID
        Object.assign(existingSession, session);
        if (config.session.store) {
          await regenerateSessionStoreId(req, config);
        }
      } else {
        // New session or same user - assign session data
        if (!existingSession) {
          req[config.session.name] = {};
        }
        Object.assign(req[config.session.name], session);
      }

      // Call afterCallback hook - preserve existing behavior
      if (config.afterCallback) {
        const updatedSession = await config.afterCallback(
          req,
          res,
          req[config.session.name],
          req.openidState,
        );
        Object.assign(req[config.session.name], updatedSession);
      }

      resumeSilentLogin(req, res);

      // Handle backchannel logout onLogin hook
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
      // Silent login failed - redirect to base URL
      const redirectTo =
        (req.openidState && req.openidState.returnTo) || config.baseURL;
      return res.redirect(redirectTo);
    }

    const redirectTo = req.openidState.returnTo || config.baseURL;
    res.redirect(redirectTo);
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

    // Check if insecure mode is explicitly enabled for testing
    if (config.backchannelLogout && config.backchannelLogout.isInsecure) {
      // INSECURE MODE - Only for testing, requires explicit configuration
      debugContext(
        'Using insecure backchannel logout mode - DO NOT USE IN PRODUCTION',
      );
      const token = jose.decodeJwt(logoutToken);
      const onToken = config.backchannelLogout.onLogoutToken || onLogoutToken;
      try {
        await onToken(token, config);
        res.status(204).send();
      } catch (e) {
        debugContext('req.oidc.backchannelLogout() failed with: %s', e.message);
        res.status(400).json({
          error: 'application_error',
          error_description:
            'The application failed to invalidate the session.',
        });
      }
      return;
    }

    // SECURE MODE - Proper JWT verification using openid-client v6
    try {
      // Get client configuration and discovered issuer metadata
      const { issuer } = await getClient(config);

      // Verify the logout token JWT
      let verifiedToken;
      let protectedHeader;
      try {
        // Create JWKS from discovered metadata (not hardcoded URL)
        const jwksUri = issuer.jwks_uri;
        if (!jwksUri) {
          throw new Error('No JWKS URI found in issuer metadata');
        }
        const jwks = jose.createRemoteJWKSet(new URL(jwksUri));

        // Verify JWT signature, issuer, audience, and other claims
        // Do not require typ in jwtVerify options - validate manually if present
        const { payload, protectedHeader: header } = await jose.jwtVerify(
          logoutToken,
          jwks,
          {
            issuer: issuer.issuer, // Use discovered issuer value, not config.issuerBaseURL
            audience: config.clientID,
            clockTolerance: config.clockTolerance || 60,
          },
        );

        verifiedToken = payload;
        protectedHeader = header;

        // Manually validate typ if present in the protected header
        if (protectedHeader.typ && protectedHeader.typ !== 'logout+jwt') {
          throw new Error(
            `Invalid token type: expected 'logout+jwt', got '${protectedHeader.typ}'`,
          );
        }

        // Validate required logout token claims
        if (
          !verifiedToken.events ||
          !verifiedToken.events[
            'http://schemas.openid.net/event/backchannel-logout'
          ]
        ) {
          throw new Error(
            'Invalid logout token: missing backchannel logout event',
          );
        }

        // Must have either sid or sub
        if (!verifiedToken.sid && !verifiedToken.sub) {
          throw new Error('Invalid logout token: missing sid or sub claim');
        }

        debugContext('Logout token verified successfully');
      } catch (verificationError) {
        debugContext(
          'Logout token verification failed: %s',
          verificationError.message,
        );
        res.status(400).json({
          error: 'invalid_token',
          error_description: 'Invalid logout token',
        });
        return;
      }

      // Process the verified logout token
      const onToken = config.backchannelLogout.onLogoutToken || onLogoutToken;
      try {
        await onToken(verifiedToken, config);
        res.status(204).send();
      } catch (e) {
        debugContext('req.oidc.backchannelLogout() failed with: %s', e.message);
        res.status(400).json({
          error: 'application_error',
          error_description:
            'The application failed to invalidate the session.',
        });
      }
    } catch (err) {
      debugContext('Backchannel logout error: %s', err.message);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error processing logout token',
      });
    }
  }
}

export { RequestContext, ResponseContext };

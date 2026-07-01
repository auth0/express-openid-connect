const url = require('url');
const urlJoin = require('url-join');
const {
  jwtVerify,
  createRemoteJWKSet,
  customFetch: joseCustomFetch,
  decodeJwt,
} = require('jose');
const TokenSet = require('./tokenset');
const clone = require('clone');

const { strict: assert } = require('assert');
const createError = require('http-errors');

const debug = require('./debug')('context');
const { once } = require('./once');
const {
  get: getClient,
  buildEndSessionUrl,
  client: oidcClient,
} = require('./client');
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
const { SessionExpiredError } = require('./errors');
const { epoch } = require('./utils/epoch');
const {
  extractSessionExpiry,
  isSessionExpiryReached,
  isSessionExpiryInPast,
} = require('./utils/sessionExpiry');

// Caches one RemoteJWKSet instance per auth() configuration for backchannel logout token verification.
const jwksClientCache = new Map();

/**
 * Returns a RemoteJWKSet for verifying backchannel logout tokens.
 *
 * Creates the instance on first call and caches it against the config reference so
 * subsequent backchannel logout requests reuse the same instance. This means the
 * internal JWKS key cache built up over time is preserved across requests, avoiding
 * a redundant fetch to the IdP's JWKS endpoint on every logout.
 */
async function getRemoteJWKSet(config) {
  if (jwksClientCache.has(config)) {
    return jwksClientCache.get(config);
  }
  const { serverMetadata } = await getClient(config);
  if (!serverMetadata.jwks_uri) {
    throw new Error('No JWKS URI available for token verification');
  }
  const pkg = require('../package.json');
  const headers = new Headers();
  headers.set(
    'User-Agent',
    config.httpUserAgent || `${pkg.name}/${pkg.version}`,
  );
  if (config.enableTelemetry) {
    headers.set(
      'Auth0-Client',
      Buffer.from(
        JSON.stringify({ name: pkg.name, version: pkg.version }),
      ).toString('base64'),
    );
  }
  const fetchFn = config.customFetch || fetch;
  const JWKS = createRemoteJWKSet(new URL(serverMetadata.jwks_uri), {
    timeoutDuration: config.httpTimeout,
    headers,
    [joseCustomFetch]: (url, options) =>
      fetchFn(url, {
        ...options,
        signal: AbortSignal.timeout(config.httpTimeout),
      }),
  });
  jwksClientCache.set(config, JWKS);
  return JWKS;
}

const TOKEN_EXCHANGE_GRANT_TYPE =
  'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_EXCHANGE_IDENTIFIER =
  'urn:ietf:params:oauth:token-type:access_token';

/**
 * Parameters that cannot be supplied via the `extra` option.
 *
 * 1. SDK-controlled — always set by the SDK; allowing overrides would break
 *    OAuth protocol integrity or client authentication.
 *
 * 2. First-class params — have dedicated, named fields in the options object.
 *    Accepting them again via `extra` would create ambiguity about precedence
 *    and hide intent (e.g. actor_token/actor_token_type must be paired and
 *    validated together; organization affects tenant context and must be explicit).
 *
 * Anything not listed here (e.g. `connection`, `resource`, `login_hint`) can be
 * passed freely via `extra`.
 */
const PARAM_DENYLIST = Object.freeze(
  new Set([
    // SDK-controlled
    'grant_type',
    'client_id',
    'client_secret',
    'client_assertion',
    'client_assertion_type',
    // First-class params
    'subject_token',
    'subject_token_type',
    'actor_token',
    'actor_token_type',
    'requested_token_type',
    'organization',
    'audience',
    'aud',
    'scope',
  ]),
);

function validateTokenExchangeExtras(extra) {
  if (!extra) return {};
  const result = {};
  for (const [k, v] of Object.entries(extra)) {
    if (PARAM_DENYLIST.has(k)) {
      debug('customTokenExchange: extra param "%s" ignored (in denylist)', k);
    } else {
      result[k] = v;
    }
  }
  return result;
}

/**
 * Fails fast on common subject_token mistakes before hitting the network.
 */
function validateSubjectToken(token) {
  if (typeof token !== 'string' || token.trim().length === 0) {
    throw createError(400, 'subject_token is required for token exchange');
  }
  if (token !== token.trim()) {
    throw createError(
      400,
      'subject_token must not include leading or trailing whitespace',
    );
  }
  if (/^bearer\s+/i.test(token)) {
    throw createError(
      400,
      "subject_token must not include the 'Bearer ' prefix",
    );
  }
}

/**
 * Extracts the `act` claim for delegation flows.
 * Prefers the id_token claims (via the helper openid-client attaches to every
 * TokenEndpointResponse), then falls back to decoding the access_token JWT
 * directly for M2M flows where no id_token is returned.
 * Returns undefined silently when the access token is opaque or neither
 * source carries the claim.
 */
function extractActClaim(exchanged) {
  const idTokenClaims = exchanged.claims(); // undefined when no id_token
  if (idTokenClaims && idTokenClaims.act) {
    return idTokenClaims.act;
  }
  if (exchanged.access_token) {
    try {
      const decoded = decodeJwt(exchanged.access_token);
      if (decoded.act) return decoded.act;
    } catch {
      // opaque access token — act claim not available
    }
  }
  return undefined;
}

function isExpired() {
  return tokenSet.call(this).expired();
}

/**
 * Normalizes token_type to 'Bearer' for consistency with v4 behavior.
 * openid-client v6 returns lowercase 'bearer', but we normalize to 'Bearer'
 * to maintain backward compatibility in sessions and afterCallback.
 */
function normalizeTokenType(tokenType) {
  return tokenType?.toLowerCase() === 'bearer' ? 'Bearer' : tokenType;
}

async function refresh({ tokenEndpointParams } = {}) {
  let { config, req } = weakRef(this);
  const session = req[config.session.name];

  // Pre-check: do not call /oauth/token if the IdP session ceiling has passed.
  // The authorization server has already revoked the session server-side at this point, so a
  // refresh attempt would fail with invalid_grant anyway. Surfacing a clean
  // SessionExpiredError is better than a confusing token-endpoint error.
  if (isSessionExpiryReached(session?.sessionExpiresAt)) {
    throw new SessionExpiredError();
  }

  const { configuration } = await getClient(config);
  const oldTokenSet = tokenSet.call(this);

  let parameters;
  if (config.tokenEndpointParams || tokenEndpointParams) {
    parameters = { ...config.tokenEndpointParams, ...tokenEndpointParams };
  }

  const newTokenSet = await oidcClient.refreshTokenGrant(
    configuration,
    oldTokenSet.refresh_token,
    parameters,
  );

  // Update the session, preserving sessionExpiresAt — the refresh-token grant
  // does not return a session_expiry claim, so we must not overwrite the ceiling
  // that was set at login.
  Object.assign(session, {
    access_token: newTokenSet.access_token,
    // If no new ID token assume the current ID token is valid.
    id_token: newTokenSet.id_token || oldTokenSet.id_token,
    // If no new refresh token assume the current refresh token is valid.
    refresh_token: newTokenSet.refresh_token || oldTokenSet.refresh_token,
    token_type: normalizeTokenType(newTokenSet.token_type),
    expires_at: newTokenSet.expires_in
      ? epoch() + newTokenSet.expires_in
      : undefined,
    // Preserve the IdP session ceiling across refreshes — do not re-derive
    // from the refresh response (it won't contain session_expiry).
    ...(session.sessionExpiresAt !== undefined && {
      sessionExpiresAt: session.sessionExpiresAt,
    }),
  });

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
    const { config } = weakRef(this);

    const { configuration } = await getClient(config);
    const ts = tokenSet.call(this);

    if (!ts || !ts.access_token) {
      throw new Error(
        `Access token is required to fetch user info but none was found in the session.\n`,
      );
    }

    const claims = ts.claims();
    const sub = claims?.sub;
    return oidcClient.fetchUserInfo(configuration, ts.access_token, sub);
  }

  async customTokenExchange(options = {}) {
    const { config } = weakRef(this);
    const { audience: defaultAudience, scope: defaultScope } =
      config.authorizationParams;

    const {
      subject_token = this.accessToken && this.accessToken.access_token,
      subject_token_type = ACCESS_TOKEN_EXCHANGE_IDENTIFIER,
      actor_token,
      actor_token_type,
      requested_token_type,
      organization,
      audience = defaultAudience,
      scope = defaultScope,
      extra,
    } = options;

    validateSubjectToken(subject_token);

    if (organization !== undefined && !organization.trim()) {
      throw createError(400, 'organization must not be blank');
    }

    if (actor_token !== undefined && actor_token_type === undefined) {
      throw createError(
        400,
        'actor_token_type is required when actor_token is provided',
      );
    }

    debug('customTokenExchange() audience=%s scope=%s', audience, scope);

    const { configuration } = await getClient(config);

    const parameters = {
      subject_token,
      subject_token_type,
      ...(actor_token !== undefined && { actor_token }),
      ...(actor_token_type !== undefined && { actor_token_type }),
      ...(requested_token_type !== undefined && { requested_token_type }),
      ...(organization !== undefined && { organization }),
      ...(audience !== undefined && { audience }),
      ...(scope !== undefined && { scope }),
      ...validateTokenExchangeExtras(extra),
    };

    try {
      const exchanged = await oidcClient.genericGrantRequest(
        configuration,
        TOKEN_EXCHANGE_GRANT_TYPE,
        parameters,
      );
      const result = Object.assign({}, exchanged);
      if (actor_token !== undefined) {
        const act = extractActClaim(exchanged);
        if (act !== undefined) {
          result.act = act;
        }
      }
      return result;
    } catch (error) {
      debug(
        'customTokenExchange() failed: %s - %s',
        error.error,
        error.error_description,
      );
      const status = error.error === 'mfa_required' ? 401 : 400;
      throw createError(status, error.message, {
        error: error.error,
        error_description: error.error_description,
      });
    }
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
      const { configuration } = await getClient(config);

      // Set default returnTo value, allow passed-in options to override or use originalUrl on GET
      let returnTo = config.baseURL;
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
      };

      let authParams = {
        ...options.authorizationParams,
        ...authVerification,
      };

      const usePKCE =
        options.authorizationParams.response_type.includes('code');
      if (usePKCE) {
        debug(
          'response_type includes code, the authorization request will use PKCE',
        );
        authVerification.code_verifier = transient.generateCodeVerifier();

        authParams.code_challenge_method = 'S256';
        authParams.code_challenge = await transient.calculateCodeChallenge(
          authVerification.code_verifier,
        );
      }

      await transient.store(config.transactionCookie.name, req, res, {
        sameSite:
          options.authorizationParams.response_mode === 'form_post'
            ? 'None'
            : config.transactionCookie.sameSite,
        value: JSON.stringify(authVerification),
      });

      let authorizationUrl;
      if (config.pushedAuthorizationRequests) {
        authorizationUrl = await oidcClient.buildAuthorizationUrlWithPAR(
          configuration,
          authParams,
        );
      } else {
        authorizationUrl = oidcClient.buildAuthorizationUrl(
          configuration,
          authParams,
        );
      }

      debug('redirecting to %s', authorizationUrl.toString());
      res.redirect(authorizationUrl.toString());
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
      const clientResult = await getClient(config);

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
        return buildEndSessionUrl(config, clientResult, {
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
      const { configuration } = await getClient(config);

      let tokenResponse;
      let claims;
      try {
        const authVerification = await transient.getOnce(
          config.transactionCookie.name,
          req,
          res,
        );

        if (!authVerification) {
          if (req.oidc.isAuthenticated()) {
            // User already has a valid session — this is a stale/replayed callback
            // (e.g., browser back button navigated back to a consumed /callback URL).
            debug(
              'stale callback detected, user already authenticated, redirecting to baseURL',
            );
            return res.redirect(config.baseURL);
          } else {
            /*
             * The transaction cookie is missing for an unauthenticated user. Possible causes:
             * 1. A request was made directly to the callback URL without going through the
             *    login route first — no cookie was ever set.
             * 2. The browser dropped the SameSite=None cookie during the IdP redirect
             *    (common in Safari/ITP, privacy mode, or browsers that reject SameSite=None
             *    without a Secure flag on non-HTTPS origins).
             * 3. legacySameSiteCookie is false and the browser does not support SameSite=None,
             *    so neither the primary nor the fallback cookie was sent back.
             * 4. Multiple apps share the same transactionCookie.name and cookie path on the
             *    same domain — a second app's login flow overwrote this app's cookie before
             *    the callback fired. Set a unique transactionCookie.name and session.cookie.path
             *    per app to isolate them.
             */
            throw new Error(
              `"${config.transactionCookie.name}" cookie not found. ` +
                `Ensure the login flow is initiated through the SDK's login route before ` +
                `the callback is processed. If using SameSite=None cookies, verify the ` +
                `origin is served over HTTPS and the Secure flag is set. For multi-app ` +
                `deployments on the same domain, configure a unique transactionCookie.name ` +
                `and session.cookie.path per application.`,
            );
          }
        }

        const checks = JSON.parse(authVerification);

        req.openidState = decodeState(checks.state);

        const responseType = config.authorizationParams.response_type;

        // Build a Request object for openid-client v6
        const protocol = req.protocol;

        // Use req.hostname (respects X-Forwarded-Host when trust proxy is enabled)
        const hostname = req.hostname;

        // Determine port from X-Forwarded-Port or Host header
        // req.hostname respects trust proxy for host, but strips port
        // So we need to check X-Forwarded-Port for reverse proxy scenarios
        let port;
        const xForwardedPort = req.get('x-forwarded-port');
        const xForwardedHost = req.get('x-forwarded-host');

        // Use regex to extract port, handles IPv6 addresses
        if (xForwardedPort) {
          // Explicit X-Forwarded-Port header from reverse proxy
          port = xForwardedPort;
        } else if (xForwardedHost) {
          // Port included in X-Forwarded-Host header
          port = /:(\d+)$/.exec(xForwardedHost)?.[1];
        } else {
          const hostHeader = req.get('host');
          if (hostHeader) {
            port = /:(\d+)$/.exec(hostHeader)?.[1];
          }
        }

        // Don't include standard ports in URL
        const standardPorts = { http: '80', https: '443' };
        const needsPort = port && port !== standardPorts[protocol];

        // Build host with port if needed
        const host = needsPort ? `${hostname}:${port}` : hostname;

        const currentUrl = new URL(
          `${protocol}://${host}${req.originalUrl ?? req.url}`,
        );

        /*
         * Use options.redirectUri if explicitly provided, otherwise fall back to
         * the configured callback URL (baseURL + routes.callback).
         * Only use the raw currentUrl if neither is available.
         * This restores the pre-v6 behavior where redirect_uri was always passed
         * explicitly to the token endpoint rather than inferred from the request URL,
         * ensuring apps with proxy path rewriting or dynamic redirect URIs work correctly.
         */
        const configuredRedirectUri =
          options.redirectUri || this.getRedirectUri();
        let callbackUrl;
        if (configuredRedirectUri) {
          /*
           * Use the configured URI as origin+path, but take the query string from
           * the actual request — it carries code, state and other callback params
           * for GET flows. For POST flows the params come from the body, so the
           * query string is effectively empty.
           */
          callbackUrl = new URL(configuredRedirectUri);
          callbackUrl.search = currentUrl.search;
        } else {
          callbackUrl = currentUrl;
        }

        let request = callbackUrl;
        if (req.method === 'POST') {
          // Build headers using headersDistinct for proper multi-value header support
          const headers = Object.entries(req.headersDistinct).reduce(
            (acc, [key, values]) => {
              for (const value of values) {
                acc.append(key, value);
              }
              return acc;
            },
            new Headers(),
          );

          if (req.body && typeof req.body === 'object') {
            // Body already parsed - serialize back to URLSearchParams
            request = new Request(callbackUrl.href, {
              method: 'POST',
              headers,
              body: new URLSearchParams(req.body).toString(),
            });
          } else {
            // Body not parsed - pass the stream as duplex
            request = new Request(callbackUrl.href, {
              method: 'POST',
              headers,
              body: req,
              duplex: 'half',
            });
          }
        }

        if (responseType === 'id_token') {
          // Implicit flow - use implicitAuthentication
          claims = await oidcClient.implicitAuthentication(
            configuration,
            request,
            checks.nonce,
            {
              expectedState: checks.state,
              maxAge: checks.max_age,
            },
          );
          // For implicit flow, we only get id_token claims, no access_token
          tokenResponse = {
            id_token: req.body?.id_token,
            claims: () => claims,
          };
        } else {
          // code or code id_token - use authorizationCodeGrant
          tokenResponse = await oidcClient.authorizationCodeGrant(
            configuration,
            request,
            {
              expectedNonce: checks.nonce,
              expectedState: checks.state,
              pkceCodeVerifier: checks.code_verifier,
              maxAge: checks.max_age,
            },
            {
              ...(config && config.tokenEndpointParams),
              ...options.tokenEndpointParams,
            },
          );
          claims = tokenResponse.claims();
        }
      } catch (error) {
        // Handle v6 error types
        const errorData = {
          error: error.error || error.code || 'unknown_error',
          error_description:
            error.error_description || error.message || 'An error occurred',
        };
        throw createError(400, error.message, errorData);
      }

      // Build session from token response
      let session = {
        id_token: tokenResponse.id_token,
        access_token: tokenResponse.access_token,
        refresh_token: tokenResponse.refresh_token,
        token_type: normalizeTokenType(tokenResponse.token_type),
        expires_at: tokenResponse.expires_in
          ? epoch() + tokenResponse.expires_in
          : undefined,
      };

      // Must store the `sid` separately as the ID Token gets overridden by
      // ID Token from the Refresh Grant which may not contain a sid (In Auth0 currently).
      session.sid = claims?.sid;

      // Persist the session_expiry claim from the ID token as sessionExpiresAt.
      // This is the IdP-asserted ceiling on the RP session lifetime (IPSIE SL1).
      // Only set when the claim is present — absence means the connection does not
      // have id_token_session_expiry_supported enabled, and existing behavior applies.
      const sessionExpiresAt = extractSessionExpiry(claims);
      if (sessionExpiresAt) {
        // Lockout guard: reject a session whose ceiling was already in the past when the IdP
        // issued the token. We compare against claims.iat so a token that arrives late does
        // not get incorrectly rejected.
        if (isSessionExpiryInPast(sessionExpiresAt, claims.iat)) {
          throw createError(
            400,
            'The session_expiry claim is in the past at login time.',
            { error: 'invalid_session_expiry' },
          );
        }
        session.sessionExpiresAt = sessionExpiresAt;
      }

      // Check if user was previously authenticated BEFORE we modify the session
      const wasAuthenticated = req.oidc.isAuthenticated();
      const previousSub = wasAuthenticated ? req.oidc.user.sub : null;

      if (config.afterCallback) {
        // Temporarily set the session so that req.oidc methods can access token data.
        // Note: This is a behavioral change from previous versions where req.oidc
        // inside afterCallback reflected the old session state. Now it reflects
        // the new tokens from the current authentication.
        const originalSession = req[config.session.name]
          ? { ...req[config.session.name] }
          : {};
        Object.assign(req[config.session.name], session);

        try {
          session = await config.afterCallback(
            req,
            res,
            session,
            req.openidState,
          );
        } finally {
          // Restore original session state (will be properly set below)
          Object.keys(req[config.session.name]).forEach(
            (key) => delete req[config.session.name][key],
          );
          Object.assign(req[config.session.name], originalSession);
        }
      }

      if (wasAuthenticated) {
        if (previousSub === claims?.sub) {
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
    res.redirect(req.openidState.returnTo || config.baseURL);
  }

  async backchannelLogout() {
    let { config, req, res } = weakRef(this);
    res.setHeader('cache-control', 'no-store');
    const logoutToken = req.body?.logout_token;
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
      const { serverMetadata } = await getClient(config);
      const JWKS = await getRemoteJWKSet(config);

      // Verify the logout token
      const { payload } = await jwtVerify(logoutToken, JWKS, {
        issuer: serverMetadata.issuer,
        audience: config.clientID,
        algorithms: [config.idTokenSigningAlg],
      });

      // Logout Token specific validations per OpenID Connect Back-Channel Logout spec
      // Must have 'events' claim with the logout event
      if (
        !payload.events ||
        typeof payload.events !== 'object' ||
        !payload.events['http://schemas.openid.net/event/backchannel-logout']
      ) {
        throw new Error(
          'Logout Token must contain events claim with backchannel-logout event',
        );
      }

      // Must NOT have 'nonce' claim
      if (payload.nonce !== undefined) {
        throw new Error('Logout Token must not contain nonce claim');
      }

      // Must have either 'sub' or 'sid' claim
      if (!payload.sub && !payload.sid) {
        throw new Error('Logout Token must contain sub or sid claim');
      }

      token = payload;
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

// Type definitions for express-openid-connect

import {
  AuthorizationParameters,
  IdTokenClaims,
  UserinfoResponse,
} from 'openid-client';
import { Request, Response, RequestHandler } from 'express';

/**
 * Session object
 */
interface Session {
  /**
   * Values stored in an authentication session
   */
  id_token: string;
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_at: string;
  [key: string]: any;
}

/**
 * The Express.js Request with `oidc` context added by the `auth` middleware.
 *
 * ```js
 * app.use(auth());
 *
 * app.get('/profile', (req, res) => {
 *   const user = req.oidc.user;
 *   ...
 * })
 * ```
 *
 * @deprecated use the native the `Request` interface of `express` instead; it has
 * been extended and now includes a built in `oidc` param.
 */
interface OpenidRequest extends Request {
  /**
   * Library namespace for authentication methods and data.
   */
  oidc: RequestContext;
}

/**
 * The Express.js Response with `oidc` context added by the `auth` middleware.
 *
 * ```js
 * app.use(auth());
 *
 * app.get('/login', (req, res) => {
 *   res.oidc.login();
 * })
 * ```
 *
 * @deprecated use the native the `Response` interface of `express` instead; it has
 * been extended and now includes a built in `oidc` param.
 */
interface OpenidResponse extends Response {
  /**
   * Library namespace for authentication methods and data.
   */
  oidc: ResponseContext;
}

/**
 * The request authentication context found on the Express request when
 * OpenID Connect auth middleware is added to your application.
 *
 * ```js
 * app.use(auth());
 *
 * app.get('/profile', (req, res) => {
 *   const user = req.oidc.user;
 *   ...
 * })
 * ```
 */
interface RequestContext {
  /**
   * Method to check the user's authenticated state, returns `true` if logged in.
   */
  isAuthenticated: () => boolean;

  /**
   * The OpenID Connect ID Token.
   *
   * See: https://auth0.com/docs/protocols/oidc#id-tokens
   */
  idToken?: string;

  /**
   * Credentials that can be used by an application to access an API.
   *
   * See: https://auth0.com/docs/protocols/oidc#access-tokens
   */
  accessToken?: AccessToken;

  /**
   * Credentials that can be used to refresh an access token.
   *
   * See: https://auth0.com/docs/tokens/concepts/refresh-tokens
   */
  refreshToken?: string;

  /**
   * An object containing all the claims of the ID Token.
   */
  idTokenClaims?: IdTokenClaims;

  /**
   * An object containing all the claims of the ID Token with the claims
   * specified in {@link ConfigParams.identityClaimFilter identityClaimFilter} removed.
   */
  user?: Record<string, any>;

  /**
   * Fetches the OIDC userinfo response.
   *
   * ```js
   * app.use(auth());
   *
   * app.get('/user-info', async (req, res) => {
   *   const userInfo = await req.oidc.fetchUserInfo();
   *   res.json(userInfo);
   * })
   * ```
   *
   */
  fetchUserInfo(): Promise<UserinfoResponse>;
}

/**
 * The response authentication context found on the Express response when
 * OpenID Connect auth middleware is added to your application.
 *
 * ```js
 * app.use(auth());
 *
 * app.get('/admin-login', (req, res) => {
 *   res.oidc.login({ returnTo: '/admin' })
 * })
 * ```
 */
interface ResponseContext {
  /**
   * Provided by default via the `/login` route. Call this to override or have other
   * login routes with custom {@link ConfigParams.authorizationParams authorizationParams} or returnTo
   *
   * ```js
   * app.get('/admin-login', (req, res) => {
   *   res.oidc.login({
   *     returnTo: '/admin',
   *     authorizationParams: {
   *       scope: 'openid profile email admin:user',
   *     }
   *   });
   * });
   * ```
   */
  login: (opts?: LoginOptions) => Promise<void>;

  /**
   * Provided by default via the `/logout` route. Call this to override or have other
   * logout routes with custom returnTo
   *
   * ```js
   * app.get('/admin-logout', (req, res) => {
   *   res.oidc.logout({ returnTo: '/admin-welcome' })
   * });
   * ```
   */
  logout: (opts?: LogoutOptions) => Promise<void>;
}

/**
 * Extend express interfaces (Response/Request) to support oidc param
 */
declare global {
  namespace Express {
    interface Request {
      oidc: RequestContext;
    }

    interface Response {
      oidc: ResponseContext;
    }
  }
}

/**
 * Custom options to pass to login.
 */
interface LoginOptions {
  /**
   * Override the default {@link ConfigParams.authorizationParams authorizationParams}
   */
  authorizationParams?: AuthorizationParameters;

  /**
   *  URL to return to after login, overrides the Default is {@link Request.originalUrl}
   */
  returnTo?: string;

  /**
   *  Used by {@link ConfigParams.attemptSilentLogin} to swallow callback errors on silent login.
   */
  silent?: boolean;
}

/**
 * Custom options to pass to logout.
 */
interface LogoutOptions {
  /**
   *  URL to returnTo after logout, overrides the Default in {@link ConfigParams.routes.postLogoutRedirect routes.postLogoutRedirect}
   */
  returnTo?: string;
}

/**
 * Configuration parameters passed to the `auth()` middleware.
 *
 * {@link ConfigParams.issuerBaseURL issuerBaseURL}, {@link ConfigParams.baseURL baseURL}, {@link ConfigParams.clientID clientID}
 * and {@link ConfigParams.secret secret} are required but can be configured with environmental variables. {@link ConfigParams.clientSecret clientSecret} is not required but can also be configured this way.
 *
 * ```js
 * # Required
 * ISSUER_BASE_URL=https://YOUR_DOMAIN
 * BASE_URL=https://YOUR_APPLICATION_ROOT_URL
 * CLIENT_ID=YOUR_CLIENT_ID
 * SECRET=LONG_RANDOM_VALUE
 *
 * # Not required
 * CLIENT_SECRET=YOUR_CLIENT_SECRET
 * ```
 */
interface ConfigParams {
  /**
   * REQUIRED. The secret(s) used to derive an encryption key for the user identity in a session cookie and
   * to sign the transient cookies used by the login callback.
   * Use a single string key or array of keys for an encrypted session cookie.
   * Can use env key SECRET instead.
   */
  secret?: string | Array<string>;

  /**
   * Object defining application session cookie attributes.
   */
  session?: SessionConfigParams;

  /**
   * Boolean value to enable idpLogout with an Auth0 custom domain
   */
  auth0Logout?: boolean;

  /**
   *  URL parameters used when redirecting users to the authorization server to log in.
   *
   *  If this property is not provided by your application, its default values will be:
   *
   * ```js
   * {
   *   response_type: 'id_token',
   *   response_mode: 'form_post',
   *   scope: 'openid profile email'
   * }
   * ```
   *
   * New values can be passed in to change what is returned from the authorization server depending on your specific scenario.
   *
   * For example, to receive an access token for an API, you could initialize like the sample below. Note that `response_mode` can be omitted because the OAuth2 default mode of `query` is fine:
   *
   * ```js
   * app.use(
   *   auth({
   *     authorizationParams: {
   *       response_type: 'code',
   *       scope: 'openid profile email read:reports',
   *       audience: 'https://your-api-identifier',
   *     },
   *   })
   * );
   * ```
   *
   * Additional custom parameters can be added as well:
   *
   * ```js
   * app.use(auth({
   *   authorizationParams: {
   *     // Note: you need to provide required parameters if this object is set.
   *     response_type: "id_token",
   *     response_mode: "form_post",
   *     scope: "openid profile email"
   *    // Additional parameters
   *    acr_value: "tenant:test-tenant",
   *    custom_param: "custom-value"
   *   }
   * }));
   * ```
   */
  authorizationParams?: AuthorizationParameters;

  /**
   * REQUIRED. The root URL for the application router, eg https://localhost
   * Can use env key BASE_URL instead.
   */
  baseURL?: string;

  /**
   * REQUIRED. The Client ID for your application.
   * Can use env key CLIENT_ID instead.
   */
  clientID?: string;

  /**
   * The Client Secret for your application.
   * Required when requesting access tokens.
   * Can use env key CLIENT_SECRET instead.
   */
  clientSecret?: string;

  /**
   * Integer value for the system clock's tolerance (leeway) in seconds for ID token verification.`
   * Default is 60
   */
  clockTolerance?: number;

  /**
   * To opt-out of sending the library and node version to your authorization server
   * via the `Auth0-Client` header. Default is `true
   */
  enableTelemetry?: boolean;

  /**
   * Throw a 401 error instead of triggering the login process for routes that require authentication.
   * Default is `false`
   */
  errorOnRequiredAuth?: boolean;

  /**
   * Attempt silent login (`prompt: 'none'`) on the first unauthenticated route the user visits.
   * For protected routes this can be useful if your Identity Provider does not default to
   * `prompt: 'none'` and you'd like to attempt this before requiring the user to interact with a login prompt.
   * For unprotected routes this can be useful if you want to check the user's logged in state on their IDP, to
   * show them a login/logout button for example.
   * Default is `false`
   */
  attemptSilentLogin?: boolean;

  /**
   * Function that returns an object with URL-safe state values for `res.oidc.login()`.
   * Used for passing custom state parameters to your authorization server.
   *
   * ```js
   * app.use(auth({
   *   ...
   *   getLoginState(req, options) {
   *     return {
   *       returnTo: options.returnTo || req.originalUrl,
   *       customState: 'foo'
   *     };
   *   }
   * }))
   * ``
   */
  getLoginState?: (req: OpenidRequest, options: LoginOptions) => object;

  /**
   * Function for custom callback handling after receiving and validating the ID Token and before redirecting.
   * This can be used for handling token storage, making userinfo calls, claim validation, etc.
   *
   * ```js
   * app.use(auth({
   *   ...
   *   afterCallback: async (req, res, session, decodedState) => {
   *     const userProfile = await request(`${issuerBaseURL}/userinfo`);
   *     return {
   *       ...session,
   *       userProfile // access using `req.appSession.userProfile`
   *     };
   *   }
   * }))
   * ``
   */
  afterCallback?: (
    req: OpenidRequest,
    res: OpenidResponse,
    session: Session,
    decodedState: { [key: string]: any }
  ) => Promise<Session> | Session;

  /**
   * Array value of claims to remove from the ID token before storing the cookie session.
   * Default is `['aud', 'iss', 'iat', 'exp', 'nbf', 'nonce', 'azp', 'auth_time', 's_hash', 'at_hash', 'c_hash' ]`
   */
  identityClaimFilter?: string[];

  /**
   * Boolean value to log the user out from the identity provider on application logout. Default is `false`
   */
  idpLogout?: boolean;

  /**
   * String value for the expected ID token algorithm. Default is 'RS256'
   */
  idTokenSigningAlg?: string;

  /**
   * REQUIRED. The root URL for the token issuer with no trailing slash.
   * Can use env key ISSUER_BASE_URL instead.
   */
  issuerBaseURL?: string;

  /**
   * Set a fallback cookie with no SameSite attribute when response_mode is form_post.
   * Default is true
   */
  legacySameSiteCookie?: boolean;

  /**
   * Require authentication for all routes.
   */
  authRequired?: boolean;

  /**
   * Boolean value to automatically install the login and logout routes.
   */
  routes?: {
    /**
     * Relative path to application login.
     */
    login?: string | false;

    /**
     * Relative path to application logout.
     */
    logout?: string | false;

    /**
     * Either a relative path to the application or a valid URI to an external domain.
     * This value must be registered on the authorization server.
     * The user will be redirected to this after a logout has been performed.
     */
    postLogoutRedirect?: string;

    /**
     * Relative path to the application callback to process the response from the authorization server.
     */
    callback?: string;
  };

  /**
   * String value for the client's authentication method. Default is `none` when using response_type='id_token', otherwise `client_secret_basic`.
   */
  clientAuthMethod?: string;

  /**
   * Additional request body properties to be sent to the `token_endpoint` during authorization code exchange or token refresh.
   */
  tokenEndpointParams?: TokenParameters;

  /**
   * Http timeout for oidc client requests in milliseconds.  Default is 5000.   Minimum is 500.
   */
  httpTimeout?: number;
}

interface SessionStorePayload {
  header: {
    /**
     * timestamp (in secs) when the session was created.
     */
    iat: number;
    /**
     * timestamp (in secs) when the session was last touched.
     */
    uat: number;
    /**
     * timestamp (in secs) when the session expires.
     */
    exp: number;
  };

  /**
   * The session data.
   */
  data: Session;
}

interface SessionStore {
  /**
   * Gets the session from the store given a session ID and passes it to `callback`.
   */
  get(
    sid: string,
    callback: (err: any, session?: SessionStorePayload | null) => void
  ): void;

  /**
   * Upsert a session in the store given a session ID and `SessionData`
   */
  set(
    sid: string,
    session: SessionStorePayload,
    callback?: (err?: any) => void
  ): void;

  /**
   * Destroys the session with the given session ID.
   */
  destroy(sid: string, callback?: (err?: any) => void): void;

  [key: string]: any;
}

/**
 * Configuration parameters used for the application session.
 */
interface SessionConfigParams {
  /**
   * String value for the cookie name used for the internal session.
   * This value must only include letters, numbers, and underscores.
   * Default is `appSession`.
   */
  name?: string;

  /**
   * By default the session is stored in an encrypted cookie. But when the session
   * gets too large it can bump up against the limits of cookie storage.
   * In these instances you can use a custom session store. The store should
   * have `get`, `set` and `destroy` methods, making it compatible
   * with [express-session stores](https://github.com/expressjs/session#session-store-implementation).
   */
  store?: SessionStore;

  /**
   * A Function for generating a session id when using a custom session store.
   * For full details see the documentation for express-session
   * at [genid](https://github.com/expressjs/session/blob/master/README.md#genid).
   * If encrypted cookie storage is used or no value is provided, a default implementation is used.
   * Be aware the default implmentation is  slightly different in this library as compared to the
   * default session id generation used express-session.
   */
  genid?: (req: OpenidRequest) => string;

  /**
   * If you want your session duration to be rolling, eg reset everytime the
   * user is active on your site, set this to a `true`. If you want the session
   * duration to be absolute, where the user is logged out a fixed time after login,
   * regardless of activity, set this to `false`
   * Default is `true`.
   */
  rolling?: boolean;

  /**
   * Integer value, in seconds, for application session rolling duration.
   * The amount of time for which the user must be idle for then to be logged out.
   * Default is 86400 seconds (1 day).
   */
  rollingDuration?: number;

  /**
   * Integer value, in seconds, for application absolute rolling duration.
   * The amount of time after the user has logged in that they will be logged out.
   * Set this to `false` if you don't want an absolute duration on your session.
   * Default is 604800 seconds (7 days).
   */
  absoluteDuration?: boolean | number;

  /**
   * Configuration parameters used for the session cookie and transient cookies.
   */
  cookie?: CookieConfigParams;
}

interface CookieConfigParams {
  /**
   * Domain name for the cookie.
   * Passed to the [Response cookie](https://expressjs.com/en/api.html#res.cookie) as `domain`
   */
  domain?: string;

  /**
   * Path for the cookie.
   * Passed to the [Response cookie](https://expressjs.com/en/api.html#res.cookie) as `path`
   */
  path?: string;

  /**
   * Set to true to use a transient cookie (cookie without an explicit expiration).
   * Default is `false`
   */
  transient?: boolean;

  /**
   * Flags the cookie to be accessible only by the web server.
   * Passed to the [Response cookie](https://expressjs.com/en/api.html#res.cookie) as `httponly`.
   * Defaults to `true`.
   */
  httpOnly?: boolean;

  /**
   * Marks the cookie to be used over secure channels only.
   * Passed to the [Response cookie](https://expressjs.com/en/api.html#res.cookie) as `secure`.
   * Defaults to the protocol of {@link ConfigParams.baseURL}.
   */
  secure?: boolean;

  /**
   * Value of the SameSite Set-Cookie attribute.
   * Passed to the [Response cookie](https://expressjs.com/en/api.html#res.cookie) as `samesite`.
   * Defaults to "Lax" but will be adjusted based on {@link AuthorizationParameters.response_type}.
   */
  sameSite?: string;
}

interface AccessToken {
  /**
   * The access token itself, can be an opaque string, JWT, or non-JWT token.
   */
  access_token: string;

  /**
   * The type of access token, Usually "Bearer".
   */
  token_type: string;

  /**
   * Number of seconds until the access token expires.
   */
  expires_in: number;

  /**
   * Returns `true` if the access_token has expired.
   */
  isExpired: () => boolean;

  /**
   * Performs refresh_token grant type exchange and updates the session's access token.
   *
   * ```js
   * let accessToken = req.oidc.accessToken;
   * if (accessToken.isExpired()) {
   *   accessToken = await accessToken.refresh();
   * }
   * ```
   */
  refresh(params?: TokenParameters): Promise<AccessToken>;
}

interface TokenParameters {
  [key: string]: unknown;
}

/**
 * Express JS middleware implementing sign on for Express web apps using OpenID Connect.
 *
 * The `auth()` middleware requires {@link ConfigParams.secret secret}, {@link ConfigParams.baseURL baseURL}, {@link ConfigParams.clientID clientID}
 * and {@link ConfigParams.issuerBaseURL issuerBaseURL}.
 *
 * If you are using a response type that includes `code`, you will also need: {@link ConfigParams.clientSecret clientSecret}
 * ```
 * const express = require('express');
 * const { auth } = require('express-openid-connect');
 *
 * const app = express();
 *
 * app.use(
 *   auth({
 *      issuerBaseURL: 'https://YOUR_DOMAIN',
 *      baseURL: 'https://YOUR_APPLICATION_ROOT_URL',
 *      clientID: 'YOUR_CLIENT_ID',
 *      secret: 'LONG_RANDOM_STRING',
 *   })
 * );
 *
 * app.get('/', (req, res) => {
 *   res.send(`hello ${req.oidc.user.name}`);
 * });
 *
 *  app.listen(3000, () => console.log('listening at http://localhost:3000'))
 * ```
 */
export function auth(params?: ConfigParams): RequestHandler;

/**
 * Set {@link ConfigParams.authRequired authRequired} to `false` then require authentication
 * on specific routes.
 *
 * ```js
 * const { auth, requiresAuth } = require('express-openid-connect');
 *
 * app.use(
 *   auth({
 *      ...
 *      authRequired: false
 *   })
 * );
 *
 * app.get('/profile', requiresAuth(), (req, res) => {
 *   res.send(`hello ${req.oidc.user.name}`);
 * });
 *
 * ```
 */
export function requiresAuth(
  requiresLoginCheck?: (req: OpenidRequest) => boolean
): RequestHandler;

/**
 * Use this MW to protect a route based on the value of a specific claim.
 *
 * ```js
 * const { claimEquals } = require('express-openid-connect');
 *
 * app.get('/admin', claimEquals('isAdmin', true), (req, res) => {
 *   res.send(...);
 * });
 *
 * ```
 *
 * @param claim The name of the claim
 * @param value The value of the claim, should be a primitive
 */
export function claimEquals(
  claim: string,
  value: boolean | number | string | null
): RequestHandler;

/**
 * Use this MW to protect a route, checking that _all_ values are in a claim.
 *
 * ```js
 * const { claimIncludes } = require('express-openid-connect');
 *
 * app.get('/admin/delete', claimIncludes('roles', 'admin', 'superadmin'), (req, res) => {
 *   res.send(...);
 * });
 *
 * ```
 *
 * @param claim The name of the claim
 * @param args Claim values that must all be included
 */
export function claimIncludes(
  claim: string,
  ...args: (boolean | number | string | null)[]
): RequestHandler;

/**
 * Use this MW to protect a route, providing a custom function to check.
 *
 * ```js
 * const { claimCheck } = require('express-openid-connect');
 *
 * app.get('/admin/community', claimCheck((req, claims) => {
 *   return claims.isAdmin && claims.roles.includes('community');
 * }), (req, res) => {
 *   res.send(...);
 * });
 *
 * ```
 */
export function claimCheck(
  checkFn: (req: OpenidRequest, claims: IdTokenClaims) => boolean
): RequestHandler;

/**
 * Use this MW to attempt silent login (`prompt=none`) but not require authentication.
 *
 * See {@link ConfigParams.attemptSilentLogin attemptSilentLogin}
 *
 * ```js
 * const { attemptSilentLogin } = require('express-openid-connect');
 *
 * app.get('/', attemptSilentLogin(), (req, res) => {
 *   res.render('homepage', {
 *     isAuthenticated: req.isAuthenticated() // show a login or logout button
 *   });
 * });
 *
 * ```
 */
export function attemptSilentLogin(): RequestHandler;

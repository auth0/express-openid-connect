// Type definitions for express-openid-connect

import { AuthorizationParameters, TokenSet, UserinfoResponse } from 'openid-client';
import { Request, Response, NextFunction, RequestHandler, ErrorRequestHandler } from 'express';

interface OpenidRequest extends Request {
    /**
     * Library namespace for methods and data.
     * See RequestContext and ResponseContext for how this is used.
     */
    openid: object;

    /**
     * Decoded state for use in config.handleCallback().
     */
    openidState: object;

    /**
     * Tokens for use in config.handleCallback().
     */
    openidTokens: TokenSet;
}

/**
 * Configuration parameters passed to the auth() middleware.
 */
interface ConfigParams {
    /**
     * Object defining application session cookie attributes.
     */
    appSession: boolean | AppSessionConfigParams;

    /**
     * Boolean value to enable Auth0's logout feature.
     */
    auth0Logout?: boolean;

    /**
     *  URL parameters used when redirecting users to the authorization server to log in.
     */
    authorizationParams?: AuthorizationParameters

    /**
     * REQUIRED. The root URL for the application router.
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
     * Integer value for the system clock's tolerance (leeway) in seconds for ID token verification.
     */
    clockTolerance?: number;

    /**
     * Opt-in to sending the library and node version to your authorization server
     * via the `Auth0-Client` header.
     */
    enableTelemetry?: boolean;

    /**
     * Throw a 401 error instead of triggering the login process for routes that require authentication.
     */
    errorOnRequiredAuth?: boolean;

    /**
     * Function that returns a URL-safe state value for `res.openid.login()`.
     */
    getLoginState?: (req: OpenidRequest, config: object) => object;

    /**
     * Function that returns the profile for `req.openid.user`.
     */
    getUser?: (req: OpenidRequest, config: ConfigParams) => undefined | UserinfoResponse;

    /**
     * Function that runs on the callback route, after callback processing but before redirection.
     */
    handleCallback?: (req: OpenidRequest, res: Response, next: NextFunction) => void;

    /**
     * Default options object used for all HTTP calls made by the library.
     */
    httpOptions?: object;

    /**
     * Array value of claims to remove from the ID token before storing the cookie session.
     */
    identityClaimFilter?: string[];

    /**
     * Boolean value to log the user out from the identity provider on application logout.
     */
    idpLogout?: boolean;

    /**
     * String value for the expected ID token algorithm.
     */
    idTokenAlg?: string;

    /**
     * REQUIRED. The root URL for the token issuer with no trailing slash.
     * Can use env key ISSUER_BASE_URL instead.
     */
    issuerBaseURL?: string;

    /**
     * Set a fallback cookie with no SameSite attribute when response_mode is form_post.
     */
    legacySameSiteCookie?: boolean;

    /**
     * Relative path to application login.
     */
    loginPath?: string;

    /**
     * Relative path to application logout.
     */
    logoutPath?: string;

    /**
     * Either a relative path to the application or a valid URI to an external domain.
     * This value must be registered on the authorization server.
     * The user will be redirected to this after a logout has been performed.
     */
    postLogoutRedirectUri?: string;

    /**
     * Relative path to the application callback to process the response from the authorization server.
     */
    redirectUriPath?: string;

    /**
     * Require authentication for all routes.
     */
    required?: boolean | ((request: Request) => boolean);

    /**
     * Boolean value to automatically install the login and logout routes.
     */
    routes?: boolean;
}

/**
 * Configuration parameters used for the application session.
 */
interface AppSessionConfigParams {
    /**
     * REQUIRED. The secret(s) used to derive an encryption key for the user identity in a session cookie.
     * Use a single string key or array of keys for an encrypted session cookie.
     * Can use env key APP_SESSION_SECRET instead.
     */
    secret?: string | Array<string>;

    /**
     * String value for the cookie name used for the internal session.
     * This value must only include letters, numbers, and underscores.
     * Default is `appSession`.
     */
    name?: string;

    /**
     * Integer value, in seconds, for application session duration.
     * Default is 86400 seconds (1 day).
     */
    duration?: number

    /**
     * Domain name for the cookie.
     */
    cookieDomain?: string;

    /**
     * Set to true to use a transient cookie (cookie without an explicit expiration).
     * Defaults to `false` which will use appSession.duration as the cookie expiration.
     */
    cookieTransient?: boolean;

    /**
     * Flags the cookie to be accessible only by the web server.
     * Defaults to `true`.
     */
    cookieHttpOnly?: boolean;

    /**
     * Path for the cookie.
     */
    cookiePath?: string;

    /**
     * Marks the cookie to be used over secure channels only.
     */
    cookieSecure?: boolean;

    /**
     * Value of the SameSite Set-Cookie attribute.
     * Defaults to "Lax" but will be adjusted based on response_type.
     */
    cookieSameSite?: string;
}

export function auth(params?: ConfigParams): RequestHandler;
export function requiresAuth(): RequestHandler;
export function unauthorizedHandler(): ErrorRequestHandler;

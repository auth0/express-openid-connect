// Type definitions for express-openid-connect

import { AuthorizationParameters, TokenSet, UserinfoResponse } from 'openid-client';
import { Request, Response, NextFunction, RequestHandler, ErrorRequestHandler } from 'express';

interface ConfigParams {
    /**
     * Object defining application session cookie attributes.
     */
    appSessionCookie?: SessionCookieConfigParams;

    /**
     * Integer value, in seconds, for application session duration.
     */
    appSessionDuration?: number;

    /**
     * String value for the cookie name used for the internal session.
     */
    appSessionName?: string;

    /**
     * REQUIRED. The secret(s) used to derive an encryption key for the user identity in a session cookie.
     * Can use env key APP_SESSION_SECRET instead.
     */
    appSessionSecret: boolean | string | string[];

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
     * Throw a 401 error instead of triggering the login process for routes that require authentication.
     */
    errorOnRequiredAuth?: boolean;

    /**
     * Function that returns the profile for `req.openid.user`.
     */
    getUser?: (req: Request, config: ConfigParams) => undefined | UserinfoResponse;

    /**
     * Function that runs on the callback route, after callback processing but before redirection.
     */
    handleCallback?: RequestHandler;

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

interface SessionCookieConfigParams {
    domain?: string;
    httpOnly?: boolean;
    path?: string;
    sameSite?: string;
    secure?: boolean;
}

export function auth(params?: ConfigParams): RequestHandler;
export function requiresAuth(): RequestHandler;
export function unauthorizedHandler(): ErrorRequestHandler;

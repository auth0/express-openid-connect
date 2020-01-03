// Type definitions for express-openid-connect

import { AuthorizationParameters, TokenSet, UserinfoResponse } from 'openid-client';
import { Request, Response, NextFunction, RequestHandler } from 'express';

interface ConfigParams {
    appSessionCookie?: SessionCookieConfigParams;
    appSessionDuration?: number;
    appSessionName?: string;
    appSessionSecret: boolean | string | string[];
    auth0Logout?: boolean;
    authorizationParams?: AuthorizationParameters
    baseURL?: string;
    clientID?: string;
    clientSecret?: string;
    clockTolerance?: number;
    errorOnRequiredAuth?: boolean;
    getUser?: (req: Request, config: ConfigParams) => undefined | UserinfoResponse;
    handleCallback?: RequestHandler;
    httpOptions?: object;
    identityClaimFilter?: string[];
    idpLogout?: boolean;
    idTokenAlg?: string;
    issuerBaseURL?: string;
    legacySameSiteCookie?: boolean;
    loginPath?: string;
    logoutPath?: string;
    redirectUriPath?: string;
    required?: boolean | ((request: Request) => boolean);
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
export function unauthorizedHandler(): RequestHandler;

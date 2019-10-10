// Type definitions for express-openid-connect

import { AuthorizationParameters, TokenSet, UserinfoResponse } from 'openid-client';
import { Request, RequestHandler } from 'express';

interface ConfigParams {
    auth0Logout?: boolean;
    authorizationParams?: AuthorizationParameters
    baseURL?: string;
    clientID?: string;
    clientSecret?: string;
    clockTolerance?: number;
    errorOnRequiredAuth?: boolean;
    getUser?: (tokenSet: TokenSet) => undefined | UserinfoResponse;
    idpLogout?: boolean;
    idTokenAlg?: string;
    issuerBaseURL?: string;
    loginPath?: string;
    logoutPath?: string;
    redirectUriPath?: string;
    required?: boolean | ((request: Request) => boolean);
    routes?: boolean;
}

export function auth(params?: ConfigParams): RequestHandler;
export function requiresAuth(): RequestHandler;
export function unauthorizedHandler(): RequestHandler;

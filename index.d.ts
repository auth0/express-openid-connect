// Type definitions for express-openid-connect

import { AuthorizationParameters, TokenSet } from 'openid-client';
import { Request, RequestHandler } from 'express';

interface AuthParams {
    issuerBaseURL?: string;
    baseURL?: string;
    clientID?: string;
    clientSecret?: string;
    clockTolerance?: number;
    getUser?: (tokenSet: TokenSet) => any;
    required?: boolean | ((request: Request) => boolean);
    errorOnRequiredAuth?: boolean;
    idpLogout?: boolean;
    auth0Logout?: boolean;
    routes?: boolean;
    redirectUriPath?: string;
    authorizationParams?: AuthorizationParameters
}

export function auth(params?: AuthParams): RequestHandler;
export function requiresAuth(): RequestHandler;
export function unauthorizedHandler(): RequestHandler;

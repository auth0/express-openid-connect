// @ts-check

const createError = require('http-errors');
const debug = require('../lib/debug')('requiresAuth');
const legacyArgs = require('./requiresAuthLegacyArgs');
const { TokenSets } = require('../lib/tokenSets');

/** @type {import('..').RequiresLoginCheck} */
const defaultRequiresLoginCheck = (req) => !req.oidc.isAuthenticated();

/**
 * @typedef {object} RequiresLoginMiddlewareParams
 * @property {(req: import('express').Request) => boolean} [requiresLoginCheck]
 * @property {import('..').AuthorizationParameters} [authorizationParams]
 */

/**
 * @param {RequiresLoginMiddlewareParams} params
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function forceLogin(params, req, res, next) {
  if (!res.oidc.errorOnRequiredAuth && req.accepts('html')) {
    debug(
      'authentication requirements not met with errorOnRequiredAuth() returning false, calling res.oidc.login()'
    );
    return res.oidc.login({ authorizationParams: params.authorizationParams });
  }
  debug(
    'authentication requirements not met with errorOnRequiredAuth() returning true, calling next() with an Unauthorized error'
  );
  next(
    createError.Unauthorized('Authentication is required for this route.')
  );
  return;
}

/**
 * Returns a middleware that checks whether an end-user is authenticated.
 * If end-user is not authenticated `res.oidc.login()` is triggered for an HTTP
 * request that can perform a redirect.
 * 
 * @param {RequiresLoginMiddlewareParams} params
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
async function requiresLoginMiddleware(params, req, res, next) {
  if (!req.oidc) {
    next(
      new Error('req.oidc is not found, did you include the auth middleware?')
    );
    return;
  }

  const compatibleTokenSet = await TokenSets.findCompatible(req, params.authorizationParams);

  if (compatibleTokenSet) {
    TokenSets.setCurrent(req, compatibleTokenSet);
  } else {
    return forceLogin(params, req, res, next);
  }

  const requiresLoginCheck = params.requiresLoginCheck || defaultRequiresLoginCheck;

  if (requiresLoginCheck(req)) {
    return forceLogin(params, req, res, next);
  }

  debug('authentication requirements met, calling next()');

  next();
}

/**
 * @typedef {object} RequiresAuthParams
 * @property {import('..').RequiresLoginCheck} [requiresLoginCheck]
 * @property {import('..').AuthorizationParameters} [authorizationParams]
 */

/**
 * @param {import('..').RequiresLoginCheck | RequiresAuthParams} [authCheckOrParams]
 */
module.exports.requiresAuth = function requiresAuth(authCheckOrParams) {
  const {
    requiresLoginCheck,
    authorizationParams,
  } = legacyArgs.requiresAuth.normalize(authCheckOrParams);

  return requiresLoginMiddleware.bind(undefined, { requiresLoginCheck, authorizationParams });
};

function checkJSONprimitive(value) {
  if (
    typeof value !== 'string' &&
    typeof value !== 'number' &&
    typeof value !== 'boolean' &&
    value !== null
  ) {
    throw new TypeError('"expected" must be a string, number, boolean or null');
  }
}

/**
 * @typedef {object} ClaimEqualsParams
 * @property {string} claim
 * @property {boolean | number | string | null} value
 * @property {import('..').AuthorizationParameters} [authorizationParams]
 */

/**
 * @param {string | ClaimEqualsParams} claimOrParams
 * @param {boolean | number | string | null} [value]
 */
module.exports.claimEquals = function claimEquals(claimOrParams, value) {
  const {
    claim,
    value: expected,
    authorizationParams,
  } = legacyArgs.claimEquals.normalize(claimOrParams, value);

  // check that claim is a string value
  if (typeof claim !== 'string') {
    throw new TypeError('"claim" must be a string');
  }
  // check that expected is a JSON supported primitive
  checkJSONprimitive(expected);

  const requiresLoginCheck = (req) => {
    if (defaultRequiresLoginCheck(req)) {
      return true;
    }
    const { idTokenClaims } = req.oidc;
    if (!(claim in idTokenClaims)) {
      return true;
    }
    const actual = idTokenClaims[claim];
    if (actual !== expected) {
      return true;
    }

    return false;
  };
  return requiresLoginMiddleware.bind(undefined, { requiresLoginCheck, authorizationParams });
};

/**
 * @typedef {object} ClaimIncludesParamsBase
 * @property {string} claim
 * @property {import('..').AuthorizationParameters} [authorizationParams]
 */

/**
 * @typedef {ClaimIncludesParamsBase & { values: (boolean | number | string | null)[] }} ClaimIncludesParamsMulti
 */

/**
 * @typedef {ClaimIncludesParamsBase & { value: boolean | number | string | null }} ClaimIncludesParamsSingle
 */

/**
 * @typedef {ClaimIncludesParamsSingle | ClaimIncludesParamsMulti} ClaimIncludesParams
 */

/**
 * @param {string | ClaimIncludesParams} claimOrParams
 * @param {(boolean | number | string | null)[]} args
 */
module.exports.claimIncludes = function claimIncludes(claimOrParams, ...args) {
  const {
    claim,
    values: expected,
    authorizationParams,
  } = legacyArgs.claimIncludes.normalize(claimOrParams, ...args);

  // check that claim is a string value
  if (typeof claim !== 'string') {
    throw new TypeError('"claim" must be a string');
  }
  // check that all expected are JSON supported primitives
  expected.forEach(checkJSONprimitive);

  const requiresLoginCheck = (req) => {
    if (defaultRequiresLoginCheck(req)) {
      return true;
    }
    const { idTokenClaims } = req.oidc;
    if (!(claim in idTokenClaims)) {
      return true;
    }

    let actual = idTokenClaims[claim];
    if (typeof actual === 'string') {
      actual = actual.split(' ');
    } else if (!Array.isArray(actual)) {
      debug(
        'unexpected claim type. expected array or string, got %o',
        typeof actual
      );
      return true;
    }

    actual = new Set(actual);

    return !expected.every(Set.prototype.has.bind(actual));
  };
  return requiresLoginMiddleware.bind(undefined, { requiresLoginCheck, authorizationParams });
};

/**
 * @typedef {(req: import('express').Request, claims: Record<string, unknown>) => boolean} ClaimCheckFunction
 */

/**
 * @typedef {object} ClaimCheckParams
 * @property {ClaimCheckFunction} predicate
 * @property {import('..').AuthorizationParameters} [authorizationParams]
 */

/**
 * @param {ClaimCheckFunction | ClaimCheckParams} predicateOrParams
 */
module.exports.claimCheck = function claimCheck(predicateOrParams) {
  const {
    predicate: func,
    authorizationParams,
  } = legacyArgs.claimCheck.normalize(predicateOrParams);

  // check that func is a function
  if (typeof func !== 'function' || func.constructor.name !== 'Function') {
    throw new TypeError('"claimCheck" expects a function');
  }
  const requiresLoginCheck = (req) => {
    if (defaultRequiresLoginCheck(req)) {
      return true;
    }

    const { idTokenClaims } = req.oidc;

    return !func(req, idTokenClaims);
  };
  return requiresLoginMiddleware.bind(undefined, { requiresLoginCheck, authorizationParams });
};

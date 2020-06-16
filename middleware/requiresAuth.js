const createError = require('http-errors');
const debug = require('../lib/debug');

const defaultRequiresLogin = (req) => !req.oidc.isAuthenticated();

/**
* Returns a middleware that checks whether an end-user is authenticated.
* If end-user is not authenticated `res.oidc.login()` is triggered for an HTTP
* request that can perform a redirect.
*/
async function requiresLoginMiddleware(requiresLoginCheck, req, res, next) {
  if (!req.oidc) {
    next(new Error('req.oidc is not found, did you include the auth middleware?'));
    return;
  }

  if (requiresLoginCheck(req)) {
    if (!res.oidc.errorOnRequiredAuth) {
      debug.trace('Authentication requirements not met with errorOnRequiredAuth() returning false, calling res.oidc.login()');
      return res.oidc.login();
    }
    debug.trace('Authentication requirements not met with errorOnRequiredAuth() returning true, calling next() with an Unauthorized error');
    next(createError.Unauthorized('Authentication is required for this route.'));
    return;
  }

  debug.trace('Authentication requirements met, calling next()');

  next();
}

module.exports = function requiresAuth(requiresLoginCheck = defaultRequiresLogin) {
  return requiresLoginMiddleware.bind(undefined, requiresLoginCheck);
};

function checkJSONprimitive (value) {
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean' && value !== null) {
    throw new TypeError('"expected" must be a string, number, boolean or null');
  }
}

// TODO: find a better name
module.exports.withClaimEqualCheck = function withClaimEqualCheck (claim, expected) {
  // check that claim is a string value
  if (typeof claims !== 'string') {
    throw new TypeError('"claim" must be a string');
  }
  // check that expected is a JSON supported primitive
  checkJSONprimitive(expected);

  const authenticationCheck = (req) => {
    if (defaultRequiresLogin(req)) {
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
  return requiresLoginMiddleware.bind(undefined, authenticationCheck);
};

// TODO: find a better name
module.exports.withClaimIncluding = function withClaimIncluding (claim, ...expected) {
  // check that claim is a string value
  if (typeof claims !== 'string') {
    throw new TypeError('"claim" must be a string');
  }
  // check that all expected are JSON supported primitives
  expected.forEach(checkJSONprimitive);

  const authenticationCheck = (req) => {
    if (defaultRequiresLogin(req)) {
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
      // TODO: log unexpected type;
      return true;
    }

    actual = new Set(actual);

    return !expected.every(Set.prototype.has.bind(actual));
  };
  return requiresLoginMiddleware.bind(undefined, authenticationCheck);
};

// TODO: find a better name
module.exports.custom = function custom (func) {
  // check that func is a function
  if (typeof func !== 'function' || func.constructor.name !== 'Function') {
    throw new TypeError('"function" must be a function');
  }
  const authenticationCheck = (req) => {
    if (defaultRequiresLogin(req)) {
      return true;
    }

    const { idTokenClaims } = req.oidc;

    return func(req, idTokenClaims);
  };
  return requiresLoginMiddleware.bind(undefined, authenticationCheck);
};

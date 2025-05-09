// @ts-check

/**
 * For a better DX and easier future changes, we're changing all middleware
 * arguments to be an object with properties. But since we're doing this
 * in a minor release we have to keep backwards compatibility. This file
 * contains helpers to "normalize" these arguments to their new form.
 * 
 * If you're doing a major release and a breaking change is expected, feel
 * free to stop supporting the old arguments form and remove this file.
 */

/**
 * @param {import('..').RequiresLoginCheck | import('./requiresAuth').RequiresAuthParams} [authCheckOrParams]
 * @returns {import('./requiresAuth').RequiresAuthParams}
 */
function normalizeRequiresAuthArgs(authCheckOrParams) {
  /** @type {import('./requiresAuth').RequiresAuthParams} */
  const output = {};

  if (!authCheckOrParams) {
    // nothing to do
  } else if (typeof authCheckOrParams === 'function') {
    output.requiresLoginCheck = authCheckOrParams;
  } else if (typeof authCheckOrParams === 'object') {
    if ('requiresLoginCheck' in authCheckOrParams) {
      output.requiresLoginCheck = authCheckOrParams.requiresLoginCheck;
    }

    if ('authorizationParams' in authCheckOrParams) {
      output.authorizationParams = authCheckOrParams.authorizationParams;
    }
  }

  return output;
}

/**
 * @param {string | import('./requiresAuth').ClaimEqualsParams} claimOrParams
 * @param {boolean | number | string | null} [value]
 * @returns {import('./requiresAuth').ClaimEqualsParams}
 */
function normalizeClaimEqualsArgs(claimOrParams, value) {
  /** @type {import('./requiresAuth').ClaimEqualsParams} */
  const output = {};

  if (!claimOrParams) { // not needed but expected by tests
    // nothing to do
  } else if (typeof claimOrParams === 'string') {
    output.claim = claimOrParams;

    if (value !== undefined) {
      output.value = value;
    }
  } else if (typeof claimOrParams === 'object') {
    output.claim = claimOrParams.claim;
    output.value = claimOrParams.value;

    if ('authorizationParams' in claimOrParams) {
      output.authorizationParams = claimOrParams.authorizationParams;
    }
  }

  return output;
}

/**
 * @param {string | import('./requiresAuth').ClaimIncludesParams} claimOrParams
 * @param {(boolean | number | string | null)[]} values
 * @returns {import('./requiresAuth').ClaimIncludesParamsMulti}
 */
function normalizeClaimIncludesArgs(claimOrParams, ...values) {
  const output = {};

  if (typeof claimOrParams === 'string') {
    output.claim = claimOrParams;
    output.values = values;
  } else if (typeof claimOrParams === 'object') {
    output.claim = claimOrParams.claim;
    output.values = 'value' in claimOrParams
      ? [claimOrParams.value]
      : claimOrParams.values;

    if ('authorizationParams' in claimOrParams) {
      output.authorizationParams = claimOrParams.authorizationParams;
    }
  }

  return output;
}

/**
 * @param {import('./requiresAuth').ClaimCheckFunction | import('./requiresAuth').ClaimCheckParams} predicateOrParams
 * @returns {import('./requiresAuth').ClaimCheckParams}
 */
function normalizeClaimCheckArgs(predicateOrParams) {
  const output = {};

  if (!predicateOrParams) { // not needed but expected by tests
    // nothing to do
  } else if (typeof predicateOrParams === 'function') {
    output.predicate = predicateOrParams;
  } else if (typeof predicateOrParams === 'object') {
    output.predicate = predicateOrParams.predicate;

    if ('authorizationParams' in predicateOrParams) {
      output.authorizationParams = predicateOrParams.authorizationParams;
    }
  }

  return output;
}

module.exports = {
  requiresAuth: { normalize: normalizeRequiresAuthArgs },
  claimEquals: { normalize: normalizeClaimEqualsArgs },
  claimIncludes: { normalize: normalizeClaimIncludesArgs },
  claimCheck: { normalize: normalizeClaimCheckArgs },
};

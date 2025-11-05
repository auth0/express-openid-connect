const { promisify } = require('util');

/**
 * Safely promisify store methods to avoid Node.js deprecation warnings.
 * Intelligently detects callback-based vs Promise-based methods.
 *
 * @param {Function} method - The method to potentially promisify
 * @param {Object} context - The context to bind the method to
 * @returns {Function} Promise-based function
 * @throws {TypeError} When method is not a function
 */
function safePromisify(method, context) {
  validateInput(method);

  // If declared async, treat as promise-based.
  if (isAsyncFunction(method)) {
    return method.bind(context);
  }

  // Detect inline Promise usage (Promise.resolve/reject/new Promise)
  if (isPromiseSource(method)) {
    return method.bind(context);
  }

  // Traditional callback-based methods - promisify normally
  if (isCallbackBasedMethod(method)) {
    return promisify(method).bind(context);
  }

  // Heuristic promise detection (zero-arity or single-arg non-callback methods)
  if (isPromiseReturningMethod(method, context)) {
    return method.bind(context);
  }

  // Default: assume callback-based and promisify (will wrap and expect a callback parameter)
  return promisify(method).bind(context);
}

/**
 * Validates that the input is a function
 * @param {*} method - The method to validate
 * @throws {TypeError} When method is not a function
 */
function validateInput(method) {
  if (typeof method !== 'function') {
    throw new TypeError('Expected method to be a function');
  }
}

/**
 * Checks if a method follows callback-based pattern
 * @param {Function} method - The method to check
 * @returns {boolean} True if method appears to be callback-based
 */
function isCallbackBasedMethod(method) {
  const paramCount = method.length;

  // Must have at least 2 parameters for callback pattern
  if (paramCount < 2) {
    return false;
  }

  const src = method.toString();
  return /\b(cb|callback)\b/.test(src);
}

/**
 * Checks if a method is declared as async
 * @param {Function} method - The method to check
 * @returns {boolean} True if method is async
 */
function isAsyncFunction(method) {
  return method.constructor.name === 'AsyncFunction';
}

/**
 * Safely tests if a method returns a Promise
 * @param {Function} method - The method to test
 * @param {Object} context - The context to bind to
 * @returns {boolean} True if method returns a Promise
 */
function isPromiseReturningMethod(method, context) {
  // Zero-arity safe probe (no arguments => no side effects)
  if (method.length === 0) {
    try {
      const testResult = method.call(context);
      if (isPromiseLike(testResult)) return true;
    } catch {
      /* ignore */
    }
  }
  // Single-argument non-callback methods: classify as promise-returning only if source shows promise usage.
  if (method.length === 1) {
    const src = method.toString();
    if (!/\b(cb|callback)\b/.test(src) && isPromiseSource(method)) {
      return true;
    }
  }
  return false;
}

/**
 * Checks if an object is Promise-like (has a then method)
 * @param {*} obj - The object to check
 * @returns {boolean} True if object is Promise-like
 */
function isPromiseLike(obj) {
  return obj != null && typeof obj.then === 'function';
}

/**
 * Detects inline Promise usage in method source code
 * @param {Function} method - The method to check
 * @returns {boolean} True if method uses Promise inline
 */
function isPromiseSource(method) {
  try {
    const src = method.toString();
    // Broaden detection: any Promise static, new Promise, or returning a thenable chain.
    if (/Promise\./.test(src)) return true; // Promise.resolve/reject/all/race/any/allSettled
    if (/new\s+Promise\s*\(/.test(src)) return true;
    if (/return\s+[^;]+\.then\s*\(/.test(src)) return true; // returning a thenable chain
    return false;
  } catch {
    return false;
  }
}

module.exports = safePromisify;

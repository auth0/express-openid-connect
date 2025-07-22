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

  // Handle async functions that still require callbacks
  if (isAsyncFunction(method) && isCallbackBasedMethod(method)) {
    return function (...args) {
      return new Promise((resolve, reject) => {
        // Add callback as last argument
        const callback = (err, result) => {
          if (err) reject(err);
          else resolve(result);
        };
        method.call(context, ...args, callback);
      });
    };
  }

  // Pure async functions - return directly
  if (isAsyncFunction(method)) {
    return method.bind(context);
  }

  // Traditional callback-based methods - promisify normally
  if (isCallbackBasedMethod(method)) {
    return promisify(method).bind(context);
  }

  if (isPromiseReturningMethod(method, context)) {
    return method.bind(context);
  }

  // Default: assume callback-based and promisify
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

  const methodSource = method.toString();
  const callbackPatterns = ['cb', 'callback'];

  return callbackPatterns.some((pattern) => methodSource.includes(pattern));
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
  try {
    const testResult = method.call(context, '__test_key__');
    return isPromiseLike(testResult);
  } catch {
    // If test fails, assume it's not Promise-based
    return false;
  }
}

/**
 * Checks if an object is Promise-like (has a then method)
 * @param {*} obj - The object to check
 * @returns {boolean} True if object is Promise-like
 */
function isPromiseLike(obj) {
  return obj != null && typeof obj.then === 'function';
}

module.exports = safePromisify;

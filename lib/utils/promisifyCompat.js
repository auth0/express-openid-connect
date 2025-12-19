const utilPromisify = require('util-promisify');

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
 * Safely promisify store methods to avoid Node.js deprecation warnings.
 * Uses util-promisify with additional safety checks to prevent hanging.
 *
 * @param {Function} method - The method to potentially promisify
 * @param {Object} context - The context to bind the method to
 * @returns {Function} Promise-based function
 * @throws {TypeError} When method is not a function
 */
function safePromisify(method, context) {
  if (typeof method !== 'function') {
    throw new TypeError('Expected method to be a function');
  }

  // 1. Async functions - require callbacks
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
  // 2. Async functions - these are already Promise-based
  if (isAsyncFunction(method)) {
    return method.bind(context);
  }

  // 3. Functions that clearly return Promises (without calling them)
  const methodSource = method.toString();
  const directPromisePatterns = [
    'return Promise.resolve',
    'return Promise.reject',
    'return new Promise',
  ];

  const returnsDirectPromise = directPromisePatterns.some((pattern) =>
    methodSource.includes(pattern),
  );

  if (returnsDirectPromise) {
    return method.bind(context);
  }

  // 3. For all other cases, use util-promisify safely
  // util-promisify should handle:
  // - Callback-based methods: promisifies them without deprecation warnings
  // - Promise-returning methods: returns them as-is
  try {
    return utilPromisify(method).bind(context);
  } catch {
    // Fallback to treating as already Promise-based if util-promisify fails
    return method.bind(context);
  }
}

module.exports = safePromisify;

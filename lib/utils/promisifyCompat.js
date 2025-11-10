const utilPromisify = require('util-promisify');

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

  // First, handle cases that might cause util-promisify to hang

  // 1. Async functions - these are already Promise-based
  if (method.constructor.name === 'AsyncFunction') {
    return method.bind(context);
  }

  // 2. Functions that clearly return Promises (without calling them)
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

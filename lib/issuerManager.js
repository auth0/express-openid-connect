const debug = require('./debug')('issuerManager');
const { createClientForIssuer } = require('./client');

/**
 * Manages multiple OIDC issuers and their metadata/clients.
 * Supports both static issuer (string) and dynamic issuer resolution (function).
 *
 * Implements LRU (Least Recently Used) cache eviction to prevent unbounded memory growth
 * when using dynamic issuer resolution with many different issuers.
 *
 * @class IssuerManager
 */
class IssuerManager {
  constructor() {
    /**
     * Cache structure: Map<issuerUrl, { client, issuer, timestamp }>
     * Uses Map's insertion-order guarantee for LRU eviction.
     * @type {Map<string, {client: Object, issuer: Object, timestamp: number}>}
     */
    this.cache = new Map();
  }

  /**
   * Resolve issuer URL from config.
   * Handles both static (string) and dynamic (function) issuer resolution.
   *
   * @param {Object} config - Application config
   * @param {string|function} config.issuerBaseURL - Issuer URL or resolver function
   * @param {Object} context - Request context for dynamic resolution
   * @param {Object} context.req - Express request object
   * @returns {Promise<string>} Resolved issuer URL
   * @throws {TypeError} If resolver returns invalid value
   * @throws {Error} If resolver throws or returns invalid URL
   */
  async resolveIssuer(config, context) {
    let issuerUrl;

    // Handle function (dynamic resolution)
    if (typeof config.issuerBaseURL === 'function') {
      try {
        issuerUrl = await config.issuerBaseURL(context);
      } catch (err) {
        debug('Error in issuerBaseURL resolver: %s', err.message);
        throw new Error(`Failed to resolve issuer: ${err.message}`);
      }

      // Validation 1: Null/undefined check
      if (issuerUrl === null || issuerUrl === undefined) {
        throw new TypeError(
          'issuerBaseURL resolver returned null or undefined',
        );
      }

      // Validation 2: Type check
      if (typeof issuerUrl !== 'string') {
        throw new TypeError(
          `issuerBaseURL resolver must return a single string URL, got ${typeof issuerUrl}`,
        );
      }

      // Validation 3: Empty string check
      if (issuerUrl.trim() === '') {
        throw new TypeError('issuerBaseURL resolver returned an empty string');
      }

      // Validation 4: Valid URL check
      try {
        new URL(issuerUrl);
      } catch {
        throw new TypeError(
          `issuerBaseURL resolver returned invalid URL: ${issuerUrl}`,
        );
      }
    } else {
      // Handle string (static resolution)
      issuerUrl = config.issuerBaseURL;
    }

    // Security: Only allow HTTPS (except localhost for dev)
    const urlObj = new URL(issuerUrl);
    if (urlObj.protocol !== 'https:' && urlObj.hostname !== 'localhost') {
      throw new Error(
        `issuerBaseURL must use HTTPS protocol, got ${urlObj.protocol}//${urlObj.hostname}`,
      );
    }

    return issuerUrl;
  }

  /**
   * Get or create OIDC client for an issuer.
   * Uses cached client if available and not expired.
   * Implements LRU eviction when cache exceeds maxCachedIssuers.
   * Delegates to createClientForIssuer from client.js to ensure single code path.
   *
   * @param {string} issuerUrl - The issuer URL
   * @param {Object} config - Application config
   * @param {number} [config.maxCachedIssuers=100] - Maximum issuers to cache (LRU eviction)
   * @returns {Promise<{client: Object, issuer: Object}>} Client and issuer metadata
   * @throws {Error} If discovery fails
   */
  async getClient(issuerUrl, config) {
    const { discoveryCacheMaxAge, maxCachedIssuers = 100 } = config;
    const now = Date.now();

    // Check cache
    const cached = this.cache.get(issuerUrl);
    if (cached && now < cached.timestamp + discoveryCacheMaxAge) {
      debug('Using cached client for issuer: %s', issuerUrl);
      // Move to end for LRU (most recently used)
      this.cache.delete(issuerUrl);
      this.cache.set(issuerUrl, cached);
      return { client: cached.client, issuer: cached.issuer };
    }

    debug('Creating client for issuer: %s', issuerUrl);

    // Use shared client creation logic from client.js
    const { client, issuer } = await createClientForIssuer(issuerUrl, config);

    // LRU eviction: remove oldest entries if at capacity
    while (this.cache.size >= maxCachedIssuers) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) {
        this.cache.delete(oldestKey);
        debug('LRU eviction: removed cached issuer: %s', oldestKey);
      } else {
        break;
      }
    }

    // Cache the result (at the end = most recently used)
    this.cache.set(issuerUrl, {
      client,
      issuer,
      timestamp: now,
    });

    debug(
      'Successfully cached client for issuer: %s (cache size: %d/%d)',
      issuerUrl,
      this.cache.size,
      maxCachedIssuers,
    );
    return { client, issuer };
  }

  /**
   * Clear cache for specific issuer or all issuers.
   * Useful for testing or forcing re-discovery.
   *
   * @param {string} [issuerUrl] - Optional specific issuer to clear
   */
  clearCache(issuerUrl) {
    if (issuerUrl) {
      this.cache.delete(issuerUrl);
      debug('Cleared cache for issuer: %s', issuerUrl);
    } else {
      this.cache.clear();
      debug('Cleared all issuer cache');
    }
  }

  /**
   * Check if an issuer is known (exists in cache).
   * Used for security validation to prevent SSRF attacks in backchannel logout.
   *
   * Normalizes the issuer URL before checking to handle trailing slash differences.
   *
   * @param {string} issuerUrl - The issuer URL to check
   * @returns {boolean} True if the issuer is in cache
   */
  isKnownIssuer(issuerUrl) {
    if (!issuerUrl) return false;

    // Normalize the URL for comparison (remove trailing slashes)
    const normalizedUrl = issuerUrl.replace(/\/+$/, '');

    // Check both with and without trailing slash
    for (const cachedUrl of this.cache.keys()) {
      const normalizedCachedUrl = cachedUrl.replace(/\/+$/, '');
      if (normalizedCachedUrl === normalizedUrl) {
        return true;
      }
    }
    return false;
  }
}

// Singleton instance
let instance;

/**
 * Get the singleton IssuerManager instance.
 * Creates a new instance if one doesn't exist.
 *
 * @returns {IssuerManager} The singleton instance
 */
module.exports.getIssuerManager = () => {
  if (!instance) {
    instance = new IssuerManager();
  }
  return instance;
};

/**
 * Reset the singleton instance.
 * Useful for testing to ensure clean state.
 */
module.exports.resetIssuerManager = () => {
  instance = null;
};

// Export class for testing
module.exports.IssuerManager = IssuerManager;

const { Issuer, custom } = require('openid-client');
const { JWK } = require('jose');
const url = require('url');
const urlJoin = require('url-join');
const debug = require('./debug')('issuerManager');
const pkg = require('../package.json');

/**
 * Manages multiple OIDC issuers and their metadata/clients.
 * Supports both static issuer (string) and dynamic issuer resolution (function).
 *
 * @class IssuerManager
 */
class IssuerManager {
  constructor() {
    /**
     * Cache structure: Map<issuerUrl, { client, issuer, timestamp }>
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
   *
   * @param {string} issuerUrl - The issuer URL
   * @param {Object} config - Application config
   * @returns {Promise<{client: Object, issuer: Object}>} Client and issuer metadata
   * @throws {Error} If discovery fails
   */
  async getClient(issuerUrl, config) {
    const { discoveryCacheMaxAge } = config;
    const now = Date.now();

    // Check cache
    const cached = this.cache.get(issuerUrl);
    if (cached && now < cached.timestamp + discoveryCacheMaxAge) {
      debug('Using cached client for issuer: %s', issuerUrl);
      return { client: cached.client, issuer: cached.issuer };
    }

    debug('Discovering issuer: %s', issuerUrl);

    try {
      // v4 API: Setup HTTP options
      const defaultHttpOptions = (options) => {
        options.headers = {
          ...options.headers,
          'User-Agent': config.httpUserAgent || `${pkg.name}/${pkg.version}`,
          ...(config.enableTelemetry
            ? {
                'Auth0-Client': Buffer.from(
                  JSON.stringify({
                    name: 'express-oidc',
                    version: pkg.version,
                    env: { node: process.version },
                  }),
                ).toString('base64'),
              }
            : undefined),
        };
        options.timeout = config.httpTimeout;
        options.agent = config.httpAgent;
        return options;
      };

      // v4 API: Discover issuer
      Issuer[custom.http_options] = defaultHttpOptions;
      const issuer = await Issuer.discover(issuerUrl);
      issuer[custom.http_options] = defaultHttpOptions;

      // v4 API: Validate algorithms
      const issuerTokenAlgs = Array.isArray(
        issuer.id_token_signing_alg_values_supported,
      )
        ? issuer.id_token_signing_alg_values_supported
        : [];
      if (!issuerTokenAlgs.includes(config.idTokenSigningAlg)) {
        debug(
          'ID token algorithm %o is not supported by issuer %s. Supported: %o.',
          config.idTokenSigningAlg,
          issuerUrl,
          issuerTokenAlgs,
        );
      }

      // v4 API: Build JWKS if clientAssertionSigningKey provided
      let jwks;
      if (config.clientAssertionSigningKey) {
        const key = JWK.asKey(config.clientAssertionSigningKey);
        jwks = { keys: [key.toJWK()] };
      }

      // v4 API: Create client
      const client = new issuer.Client(
        {
          client_id: config.clientID,
          client_secret: config.clientSecret,
          id_token_signed_response_alg: config.idTokenSigningAlg,
          token_endpoint_auth_method: config.clientAuthMethod,
          ...(config.clientAssertionSigningAlg && {
            token_endpoint_auth_signing_alg: config.clientAssertionSigningAlg,
          }),
        },
        jwks,
      );
      client[custom.http_options] = defaultHttpOptions;
      client[custom.clock_tolerance] = config.clockTolerance;

      // v4 API: Setup Auth0 logout if needed
      if (config.idpLogout) {
        if (
          config.auth0Logout ||
          (url.parse(issuer.issuer).hostname.match('\\.auth0\\.com$') &&
            config.auth0Logout !== false)
        ) {
          Object.defineProperty(client, 'endSessionUrl', {
            value(params) {
              const {
                id_token_hint,
                post_logout_redirect_uri,
                ...extraParams
              } = params;
              const parsedUrl = url.parse(urlJoin(issuer.issuer, '/v2/logout'));
              parsedUrl.query = {
                ...extraParams,
                returnTo: post_logout_redirect_uri,
                client_id: client.client_id,
              };

              Object.entries(parsedUrl.query).forEach(([key, value]) => {
                if (value === null || value === undefined) {
                  delete parsedUrl.query[key];
                }
              });

              return url.format(parsedUrl);
            },
          });
        } else if (!issuer.end_session_endpoint) {
          debug('issuer %s does not support RP-Initiated Logout', issuerUrl);
        }
      }

      // Cache the result
      this.cache.set(issuerUrl, {
        client,
        issuer,
        timestamp: now,
      });

      debug('Successfully created client for issuer: %s', issuerUrl);
      return { client, issuer };
    } catch (err) {
      debug('Discovery failed for issuer %s: %s', issuerUrl, err.message);
      throw new Error(
        `Failed to discover OIDC metadata for ${issuerUrl}: ${err.message}`,
      );
    }
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

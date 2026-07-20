class SessionExpiredError extends Error {
  constructor(message = 'The upstream IdP session has expired.') {
    super(message);
    this.name = 'SessionExpiredError';
    this.code = 'ERR_SESSION_EXPIRED';
    this.status = 401;
    this.statusCode = 401;
  }
}

/**
 * Error codes for mTLS (Mutual TLS, RFC 8705) configuration failures.
 */
const MtlsErrorCode = Object.freeze({
  MTLS_REQUIRES_CUSTOM_FETCH: 'mtls_requires_custom_fetch',
});

/**
 * Thrown during `auth()` initialization when the mTLS configuration is invalid.
 *
 * The only current case: `useMtls: true` was set but no `customFetch` was provided.
 * The standard `fetch` global has no API for attaching client certificates, so mTLS
 * is non-functional without a TLS-aware transport.
 *
 * Catch by `error.code` (a string) rather than `instanceof` to stay compatible with
 * bundlers that may produce multiple class instances across module copies.
 */
class MtlsError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'MtlsError';
    this.code = code;
  }
}

module.exports = { SessionExpiredError, MtlsError, MtlsErrorCode };

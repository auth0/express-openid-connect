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
  // `useMtls` was set but no `customFetch` was provided. The standard fetch
  // global has no API for attaching client certificates, so mTLS cannot work.
  MTLS_REQUIRES_CUSTOM_FETCH: 'mtls_requires_custom_fetch',
  // `useMtls` was set but the discovery document does not advertise
  // `mtls_endpoint_aliases.token_endpoint`. The SDK refuses to proceed rather
  // than silently sending token requests to an endpoint that will not forward
  // the client certificate (which would fail with invalid_client).
  MTLS_ENDPOINT_ALIASES_MISSING: 'mtls_endpoint_aliases_missing',
  // `useMtls` was combined with `clientSecret` or `clientAssertionSigningKey`.
  // mTLS replaces secret-based client authentication entirely.
  MTLS_INCOMPATIBLE_CLIENT_AUTH: 'mtls_incompatible_client_auth',
});

/**
 * Thrown when the mTLS (RFC 8705) configuration is invalid.
 *
 * Catch by `error.code` (a string from {@link MtlsErrorCode}) rather than
 * `instanceof` to stay compatible with bundlers that may produce multiple class
 * instances across module copies.
 */
class MtlsError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'MtlsError';
    this.code = code;
  }
}

module.exports = { SessionExpiredError, MtlsError, MtlsErrorCode };

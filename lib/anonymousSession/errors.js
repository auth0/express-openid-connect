/**
 * Error thrown when an anonymous session operation fails.
 *
 * The `code` field carries the Auth0 error code returned by the
 * `/anonymous/token` and `/anonymous/logout` endpoints, e.g. `metadata_too_large`,
 * `unauthorized_client`, `feature_not_enabled`, `invalid_client`, `invalid_target`,
 * `invalid_scope`, or `server_error`.
 *
 * The `session_expired` and `invalid_session_token` codes are handled internally
 * (a new session is created transparently) and are never surfaced as this error.
 */
class AnonymousSessionError extends Error {
  constructor(message, code, statusCode) {
    super(message);
    this.name = 'AnonymousSessionError';
    this.code = code;
    if (statusCode !== undefined) {
      this.status = statusCode;
      this.statusCode = statusCode;
    }
  }
}

module.exports = { AnonymousSessionError };

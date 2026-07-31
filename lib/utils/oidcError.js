'use strict';

/**
 * Extracts a meaningful message and OAuth error fields from openid-client v6 /
 * oauth4webapi errors.
 *
 * Error classes from those libraries fall into two categories:
 *  - ResponseBodyError / AuthorizationResponseError: populated from the AS
 *    response body — .error and .error_description are the authoritative fields.
 *  - ClientError (codes: INVALID_RESPONSE, RESPONSE_IS_NOT_CONFORM, etc.):
 *    .message is always a generic constant string; the useful detail is in
 *    .cause.message (e.g. 'unexpected JWT "alg" header parameter') with
 *    additional context in .cause.cause (e.g. { header, expected, reason }).
 *  - Anything else: fall back to .message.
 */
function extractOidcError(error) {
  if (error.error_description) {
    return {
      message: error.error_description,
      error: error.error,
      error_description: error.error_description,
    };
  }
  if (error.cause?.message && error.cause.message !== error.message) {
    const detail = error.cause.cause;
    const suffix =
      detail && typeof detail === 'object' && !Array.isArray(detail)
        ? ` (${Object.entries(detail)
            .filter(([, v]) => v !== undefined)
            .map(([k, v]) => `${k}: ${JSON.stringify(v)}`)
            .join(', ')})`
        : '';
    return {
      message: `${error.cause.message}${suffix}`,
      error: error.error || error.code,
      error_description: `${error.cause.message}${suffix}`,
    };
  }
  return {
    message: error.message,
    error: error.error || error.code,
    error_description: error.message,
  };
}

module.exports = { extractOidcError };

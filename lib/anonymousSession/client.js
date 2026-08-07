const { get: getClient, createCustomFetch } = require('../client');
const { AnonymousSessionError } = require('./errors');
const debug = require('../debug')('anonymousSession');

/**
 * Builds the client-authentication additions for an anonymous session request.
 *
 * Returns the headers to merge and the body fields to merge. Confidential
 * clients using `client_secret_basic` send an `Authorization: Basic` header;
 * other clients send `client_id` (and `client_secret` when present) in the body.
 *
 * `private_key_jwt` and mTLS are not supported yet.
 */
function getClientAuth(config) {
  const { clientID, clientSecret, clientAuthMethod } = config;

  if (clientAuthMethod === 'client_secret_basic' && clientSecret) {
    const credentials = Buffer.from(`${clientID}:${clientSecret}`).toString(
      'base64',
    );
    return { headers: { Authorization: `Basic ${credentials}` }, body: {} };
  }

  const body = { client_id: clientID };
  if (clientSecret) {
    body.client_secret = clientSecret;
  }
  return { headers: {}, body };
}

async function postJson(config, path, payload) {
  const { serverMetadata } = await getClient(config);
  const url = new URL(path, serverMetadata.issuer);

  const { headers: authHeaders, body: authBody } = getClientAuth(config);
  const doFetch = createCustomFetch(config);

  const response = await doFetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders,
    },
    body: JSON.stringify({ ...authBody, ...payload }),
    signal: AbortSignal.timeout(config.httpTimeout),
  });

  let data;
  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {
    const code = data.error || 'server_error';
    const message =
      data.error_description || data.message || `Anonymous session ${code}`;
    debug('%s failed: %d %s', path, response.status, code);
    throw new AnonymousSessionError(message, code, response.status);
  }

  return data;
}

/**
 * Calls `POST /anonymous/token` to create a new anonymous session or, when a
 * `session_token` is supplied, to re-mint an access token for the existing one.
 *
 * @param {Object} config
 * @param {Object} options
 * @param {string} [options.session_token] Existing session token to renew from.
 * @param {string} [options.audience] Resource Server identifier.
 * @param {string} [options.scope] Space-separated scopes.
 * @param {Object} [options.metadata] Session metadata (creation only).
 * @returns {Promise<Object>} The parsed token response.
 */
async function requestToken(
  config,
  { session_token, audience, scope, metadata } = {},
) {
  const payload = {};
  if (session_token !== undefined) payload.session_token = session_token;
  if (audience !== undefined) payload.audience = audience;
  if (scope !== undefined) payload.scope = scope;
  // Metadata is only accepted on creation, never on renewal.
  if (metadata !== undefined && session_token === undefined) {
    payload.metadata = metadata;
  }

  return postJson(config, '/anonymous/token', payload);
}

/**
 * Calls `POST /anonymous/logout` to end an anonymous session.
 *
 * @param {Object} config
 * @param {string} session_token The session token to end.
 * @returns {Promise<Object>}
 */
async function logout(config, session_token) {
  return postJson(config, '/anonymous/logout', { session_token });
}

module.exports = { requestToken, logout };

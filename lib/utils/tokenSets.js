const { epoch } = require('./epoch');

/**
 * Initialises the tokenSets array from an existing flat session.
 * Called once when an old session (pre-MRRT) is encountered so the new
 * cache structure is bootstrapped without requiring a fresh token exchange.
 *
 * @param {object} session - the raw session object
 * @param {string} audience - the synthetic audience key ('default' or real audience)
 * @returns {Array}
 */
function getOrInitTokenSets(session, audience) {
  if (session.tokenSets) return session.tokenSets;

  if (session.access_token) {
    return [
      {
        audience,
        access_token: session.access_token,
        scope: undefined,
        expires_at: session.expires_at,
      },
    ];
  }

  return [];
}

/**
 * Merges a newly-fetched token into the tokenSets array.
 * Replaces an existing entry for the same audience+scope, or appends a new one.
 *
 * @param {Array} tokenSets - existing tokenSets from session
 * @param {string} audience - audience key for the new token
 * @param {object} tokenResponse - raw token endpoint response from openid-client
 * @returns {Array} updated tokenSets (new array reference)
 */
function updateTokenSets(tokenSets, audience, tokenResponse) {
  const scope = tokenResponse.scope;
  const entry = {
    audience,
    access_token: tokenResponse.access_token,
    scope,
    expires_at: tokenResponse.expires_in
      ? epoch() + tokenResponse.expires_in
      : undefined,
  };

  const idx = tokenSets.findIndex(
    (ts) => ts.audience === audience && ts.scope === scope,
  );

  if (idx === -1) {
    return [...tokenSets, entry];
  }

  const updated = [...tokenSets];
  updated[idx] = entry;
  return updated;
}

module.exports = { getOrInitTokenSets, updateTokenSets };

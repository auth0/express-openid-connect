/**
 * Returns true if cachedScope contains every scope token in requestedScope.
 * Used to determine whether a cached token satisfies a narrower scope request.
 *
 * @param {string|undefined} cachedScope - space-separated scopes on the cached token
 * @param {string|undefined} requestedScope - space-separated scopes being requested
 * @returns {boolean}
 */
function compareScopes(cachedScope, requestedScope) {
  if (cachedScope === requestedScope) return true;
  if (!cachedScope || !requestedScope) return false;

  const cached = new Set(cachedScope.trim().split(/\s+/).filter(Boolean));
  const requested = requestedScope.trim().split(/\s+/).filter(Boolean);
  return requested.every((s) => cached.has(s));
}

module.exports = compareScopes;

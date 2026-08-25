const { buildTelemetryHeaders } = require('./client');

const WEBFINGER_REL = 'http://openid.net/specs/connect/1.0/issuer';
const WEBFINGER_TIMEOUT_MS = 5000;

/**
 * Small TTL cache with FIFO eviction, used to avoid a WebFinger round trip on
 * every call for the same domain. Only `true` (60s) and `false`-from-404 (15s)
 * results are cached; ambiguous/error responses are never cached so a
 * transient failure doesn't stick.
 */
const MAX_CACHE_SIZE = 1000; // prevents unbounded growth across many distinct domains

class TtlCache {
  constructor() {
    this._store = new Map();
  }

  get(key) {
    const entry = this._store.get(key);
    if (entry && Date.now() < entry.expiresAt) {
      return entry.result;
    }
    this._store.delete(key);
    return undefined;
  }

  set(key, result, ttlMs) {
    if (this._store.size >= MAX_CACHE_SIZE) {
      this._store.delete(this._store.keys().next().value); // FIFO eviction
    }
    this._store.set(key, { result, expiresAt: Date.now() + ttlMs });
  }
}

const cache = new TtlCache();

/**
 * Checks whether an email domain is managed for enterprise SSO on the given
 * Auth0 tenant, via the WebFinger domain-discovery endpoint.
 *
 * This is a routing hint, not a security control. Callers must still validate
 * the `org_id` claim on the returned ID token after the Auth0 callback,
 * regardless of what this function returned.
 *
 * @param {String} auth0Domain e.g. 'your-tenant.auth0.com'
 * @param {String} emailDomain e.g. 'acmecorp.com' (case-insensitive)
 * @returns {Promise<Boolean>}
 */
async function isFederatedDomain(auth0Domain, emailDomain) {
  const normalizedDomain = emailDomain.toLowerCase();
  const key = `${auth0Domain}:${normalizedDomain}`;

  const cached = cache.get(key);
  if (cached !== undefined) {
    return cached;
  }

  try {
    const url = new URL(`https://${auth0Domain}/.well-known/webfinger`);
    url.searchParams.set(
      'resource',
      `urn:auth0:discovery:domain:${normalizedDomain}`,
    );
    url.searchParams.set('rel', WEBFINGER_REL);

    const res = await fetch(url, {
      headers: buildTelemetryHeaders(),
      signal: AbortSignal.timeout(WEBFINGER_TIMEOUT_MS),
    });

    if (res.ok) {
      const body = await res.json();
      const managed =
        Array.isArray(body.links) &&
        body.links.some((link) => link.rel === WEBFINGER_REL);
      if (managed) {
        cache.set(key, true, 60000);
        return true;
      }
      // 200 with no matching rel is ambiguous — do not cache.
      return false;
    }

    if (res.status === 404) {
      cache.set(key, false, 15000);
      return false;
    }

    if (res.status === 429) {
      console.warn(
        'isFederatedDomain: rate limited (429) by the WebFinger endpoint',
      );
      return false;
    }

    // 403 (WebFinger disabled on the tenant) and any other status: false, uncached.
  } catch {
    // Network error / unexpected failure: false, uncached.
  }

  return false;
}

module.exports = isFederatedDomain;

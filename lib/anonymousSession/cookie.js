const { compactDecrypt } = require('jose');
const cookie = require('cookie');
const { getKeyStore, encryptSync } = require('../crypto');
const COOKIES = require('../cookies');
const debug = require('../debug')('anonymousSession');

const ALG = 'dir';
const ENC = 'A256GCM';

/**
 * Reads, writes, and clears the encrypted `auth0_anon` cookie that stores the
 * anonymous session state (`{ session_token, access_token, token_type,
 * expires_at, session_expires_at, audience, scope }`).
 *
 * The payload is encrypted with the app `secret` using the same JWE profile
 * (dir / A256GCM) as the main session cookie, so only the server can read it.
 * Only the `session_token` is ever forwarded to Auth0 (on `/authorize`); the
 * access token never leaves the server except when the developer sends it to
 * their own API.
 */
module.exports = (config) => {
  const { name, ...cookieOptions } = config.anonymousSession.cookie;
  const [current, keystore] = getKeyStore(config.secret, true);

  async function decrypt(jwe) {
    let lastError;
    for (const key of keystore) {
      try {
        const { plaintext } = await compactDecrypt(jwe, key, {
          contentEncryptionAlgorithms: [ENC],
          keyManagementAlgorithms: [ALG],
        });
        return JSON.parse(new TextDecoder().decode(plaintext));
      } catch (err) {
        lastError = err;
      }
    }
    throw lastError;
  }

  return {
    /**
     * Reads and decrypts the anonymous session state from the request, or
     * returns `null` when there is no cookie or it cannot be decrypted.
     */
    async read(req) {
      const cookies = req[COOKIES] || cookie.parse(req.get('cookie') || '');
      const raw = cookies[name];
      if (!raw) {
        return null;
      }
      try {
        return await decrypt(raw);
      } catch (err) {
        debug('could not decrypt %s cookie: %s', name, err);
        return null;
      }
    },

    /**
     * Encrypts and writes the anonymous session state to the response. The
     * cookie expiry is driven by `session_expires_at` so that renewals never
     * extend the lifetime of the anonymous session.
     */
    write(res, state) {
      const value = encryptSync(JSON.stringify(state), current);
      res.cookie(name, value, {
        ...cookieOptions,
        expires: state.session_expires_at
          ? new Date(state.session_expires_at * 1000)
          : undefined,
      });
    },

    /**
     * Clears the anonymous session cookie from the response.
     */
    clear(res) {
      const { domain, path, sameSite, secure } = cookieOptions;
      res.clearCookie(name, { domain, path, sameSite, secure });
    },
  };
};

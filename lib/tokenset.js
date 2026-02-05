const { decodeJwt } = require('jose');

/**
 * Internal TokenSet class that wraps token properties with helper methods.
 * This replaces the TokenSet class from openid-client v4 which isn't present in v6.
 */
class TokenSet {
  /**
   * @param {Object} tokenSet - Token set properties
   * @param {string} [tokenSet.id_token] - ID Token
   * @param {string} [tokenSet.access_token] - Access Token
   * @param {string} [tokenSet.refresh_token] - Refresh Token
   * @param {string} [tokenSet.token_type] - Token Type
   * @param {number} [tokenSet.expires_at] - Expiration time in seconds since epoch
   * @param {number} [tokenSet.expires_in] - Expiration time in seconds from now
   */
  constructor(tokenSet) {
    this.id_token = tokenSet.id_token;
    this.access_token = tokenSet.access_token;
    this.token_type = tokenSet.token_type;
    this.refresh_token = tokenSet.refresh_token;

    if (tokenSet.expires_at !== undefined) {
      this.expires_at = tokenSet.expires_at;
    } else if (tokenSet.expires_in !== undefined) {
      this.expires_at = Math.floor(Date.now() / 1000) + tokenSet.expires_in;
    }
  }

  /**
   * Returns the number of seconds until the access token expires.
   * @returns {number|undefined} Seconds until expiration, 0 if expired, undefined if no expires_at
   */
  get expires_in() {
    if (this.expires_at === undefined) {
      return undefined;
    }
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = this.expires_at - now;
    return expiresIn > 0 ? expiresIn : 0;
  }

  /**
   * Checks if the access token is expired.
   * @returns {boolean} True if expired
   */
  expired() {
    if (this.expires_at === undefined) {
      return false;
    }
    const now = Math.floor(Date.now() / 1000);
    return this.expires_at <= now;
  }

  /**
   * Returns the decoded claims from the ID Token.
   * @returns {Object|undefined} Decoded JWT claims or undefined if no id_token
   */
  claims() {
    if (!this.id_token) {
      return undefined;
    }
    return decodeJwt(this.id_token);
  }
}

module.exports = TokenSet;

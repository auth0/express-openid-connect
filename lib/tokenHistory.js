// @ts-check

const { TokenSetUtils } = require('./tokenSetUtils');

const SYMBOL = Symbol('tokenHistory');

/**
 * Time in seconds that history will keep refreshable tokensets after
 * their expiration. This does not apply to non-refreshable tokensets,
 * since those will be deleted as soon as they expire.
 */
const PRUNE_GRACE_PERIOD = 86400;

const TokenHistory = {
  /**
   * @param {import('express').Request} req
   * @param {import('..').TokenSetParameters[]} tokenSets
   * @returns {void}
   */
  attach(req, tokenSets) {
    req[SYMBOL] = tokenSets;
  },

  /**
   * @param {import('express').Request} req
   * @returns {import('..').TokenSetParameters[]}
   */
  getAll(req) {
    return req[SYMBOL] || [];
  },

  /**
   * @param {import('express').Request} req
   * @param {import('..').TokenSetParameters} newTokenSet
   * @returns {void}
   */
  append(req, newTokenSet) {
    req[SYMBOL].push(TokenSetUtils.cleanTokenSet(newTokenSet));
  },

  /**
   * @param {import('express').Request} req
   * @param {number} index
   * @param {Partial<import('..').TokenSetParameters>} newValues
   * @returns {void}
   */
  _patch(req, index, newValues) {
    Object.assign(req[SYMBOL][index], newValues);
  },

  /**
   * @param {import('express').Request} req
   * @param {(ts: import('..').TokenSetParameters) => boolean} predicate
   * @param {Partial<import('..').TokenSetParameters>} newValues
   * @returns {void}
   */
  _patchBy(req, predicate, newValues) {
    const tokenSets = this.getAll(req);

    tokenSets.forEach((ts, index) => {
      if (predicate(ts)) {
        this._patch(req, index, newValues);
      }
    });
  },

  /**
   * @param {import('express').Request} req
   * @param {(ts: import('..').TokenSetParameters) => boolean} predicate
   * @returns {void}
   */
  _deleteBy(req, predicate) {
    const tokenSets = this.getAll(req);

    // Deleting while traversing is finicky, let's just assign a clone
    // excluding unwanted items.
    req[SYMBOL] = tokenSets.filter((ts) => !predicate(ts));
  },

  /**
   * @param {import('express').Request} req
   * @returns {void}
   */
  prune(req) {
    this._deleteBy(req, (ts) => {
      // Expired tokens with no RT are never useful.
      if (!ts.refresh_token) {
        return TokenSetUtils.isExpired(ts);
      }

      // Expired tokens with RT are useful but don't keep them around forever.
      if (TokenSetUtils.hasBeenExpiredForAtLeast(ts, PRUNE_GRACE_PERIOD)) {
        return true;
      }

      return false;
    });
  },

  /**
   * @param {import('express').Request} req
   * @param {string} accessToken
   * @param {Partial<import('..').TokenSetParameters>} newValues
   * @returns {void}
   */
  patchByAccessToken(req, accessToken, newValues) {
    return this._patchBy(
      req,
      (ts) => ts.access_token === accessToken,
      newValues,
    );
  },

  /**
   * @param {import('express').Request} req
   * @param {string} refreshToken
   * @param {Partial<import('..').TokenSetParameters>} newValues
   * @returns {void}
   */
  patchByRefreshToken(req, refreshToken, newValues) {
    return this._patchBy(
      req,
      (ts) => ts.refresh_token === refreshToken,
      newValues,
    );
  },
};

module.exports = {
  TokenHistory,
  PRUNE_GRACE_PERIOD,
};

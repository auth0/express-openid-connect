// @ts-check

const { TokenHistory } = require('./tokenHistory');
const { TokenSetUtils } = require('./tokenSetUtils');
const weakCache = require('./weakCache');

/** @typedef {import('..').TokenSetParameters & { refresh_token: string }} RefreshableTokenSet */

const TokenSets = {
  /**
   * Find the first tokenset that is "compatible" (see `_areTokenSetsCompatible()`)
   * with the provided `authorizationParams` and is active (i.e. not expired).
   *
   * @param {import('..').TokenSetParameters[]} tokenSets
   * @param {import('..').AuthorizationParameters} authorizationParams
   * @returns {import('..').TokenSetParameters | undefined}
   */
  findCompatibleActive(tokenSets, authorizationParams) {
    return tokenSets.find(
      (ts) =>
        !TokenSetUtils.isExpired(ts) &&
        TokenSetUtils.areTokenSetsCompatible(authorizationParams, ts),
    );
  },

  /**
   * Find the first tokenset that is "compatible" (see `_areTokenSetsCompatible()`)
   * with the provided `authorizationParams` and is expired.
   *
   * @param {import('..').TokenSetParameters[]} tokenSets
   * @param {import('..').AuthorizationParameters} authorizationParams
   * @returns {import('..').TokenSetParameters | undefined}
   */
  findCompatibleExpired(tokenSets, authorizationParams) {
    return tokenSets.find(
      (ts) =>
        TokenSetUtils.isExpired(ts) &&
        TokenSetUtils.areTokenSetsCompatible(authorizationParams, ts),
    );
  },

  /**
   * Find the first tokenset that is "compatible" (see `_areTokenSetsCompatible()`)
   * with the provided `authorizationParams` and has a refresh token.
   *
   * @param {import('..').TokenSetParameters[]} tokenSets
   * @param {import('..').AuthorizationParameters} authorizationParams
   * @returns {(RefreshableTokenSet) | undefined}
   */
  findCompatibleRefreshable(tokenSets, authorizationParams) {
    return tokenSets.find(
      /**
       * @param {import('..').TokenSetParameters} ts
       * @returns {ts is RefreshableTokenSet}
       */
      (ts) =>
        !!ts.refresh_token &&
        TokenSetUtils.areTokenSetsCompatible(authorizationParams, ts),
    );
  },

  /**
   * Find the first tokenset that can be used with MRRT (i.e. it has a refresh
   * token and belongs to the same organization).
   *
   * @param {import('..').TokenSetParameters[]} tokenSets
   * @param {import('..').AuthorizationParameters} authorizationParams
   * @returns {(RefreshableTokenSet) | undefined}
   */
  findMrrtable(tokenSets, authorizationParams) {
    return tokenSets.find(
      /**
       * @param {import('..').TokenSetParameters} ts
       * @returns {ts is RefreshableTokenSet}
       */
      (ts) =>
        !!ts.refresh_token &&
        TokenSetUtils.areOrganizationsCompatible(authorizationParams, ts),
    );
  },

  /**
   * @param {import('express').Request} req
   * @returns {import('..').TokenSetParameters[]}
   */
  getAvailableTokenSets(req) {
    const { config } = weakCache.weakRef(req.oidc);

    // Candidate tokensets will be:
    // - The full history if enabled, which *includes the current one*.
    // - Just the current tokenset if history is disabled.
    return config.tokenHistory
      ? TokenHistory.getAll(req)
      : [req[config.session.name]];
  },

  /**
   * @param {import('express').Request} req
   * @param {import('..').AuthorizationParameters} [authorizationParams]
   * @returns {Promise<import('..').TokenSetParameters | undefined>}
   */
  async findCompatible(req, authorizationParams = {}) {
    const { config } = weakCache.weakRef(req.oidc);

    const tokenSets = this.getAvailableTokenSets(req);

    const mergedParams = {
      ...config.authorizationParams,
      ...authorizationParams,
    };

    /** @type {import('..').TokenSetParameters | undefined} */
    let found;

    // Try to find a compatible & active tokenset.
    found = this.findCompatibleActive(tokenSets, mergedParams);

    if (found) {
      return found;
    }

    // Try to find a compatible & refreshable tokenset. Note that at this
    // point if this returns something it will be expired but it will be
    // taken care of in the caller before making it available to the context
    // (unless `autoRefreshExpired` is disabled).
    found = this.findCompatibleRefreshable(tokenSets, mergedParams);

    if (found) {
      return found;
    }

    found = this.findCompatibleExpired(tokenSets, mergedParams);

    if (found) {
      return found;
    }

    if (config.useMrrt) {
      // Try to find a "MRRT-able" tokenset (i.e. not directly compatible
      // but with an RT that might refresh into a compatible tokenset).
      const mrrtable = this.findMrrtable(tokenSets, mergedParams);

      if (mrrtable) {
        found = await TokenSetUtils.doMrrtRefresh(
          config,
          mrrtable,
          mergedParams,
        );

        if (found) {
          // A normal refresh overwrites the previous tokenset since it's supposed
          // to be expired. However a MRRT refresh is a "lateral move" to get a
          // tokenset for a different audience than the first, so we keep both.
          TokenHistory.append(req, found);

          return found;
        }
      }
    }

    return undefined;
  },
};

module.exports = {
  TokenSets,
};

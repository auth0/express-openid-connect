// @ts-check

const weakCache = require('./weakCache');

const SYMBOL = Symbol('tokenSets');

const TokenSets = {
  /**
   * @param {import('express').Request} req
   * @param {import('openid-client').TokenSetParameters[]} tokenSets
   * @returns {void}
   */
  attach(req, tokenSets) {
    req[SYMBOL] = tokenSets;
  },

  /**
   * @param {import('express').Request} req
   * @returns {import('openid-client').TokenSetParameters[]}
   */
  getAll(req) {
    return req[SYMBOL] || [];
  },

  /**
   * @param {import('express').Request} req
   * @param {import('openid-client').TokenSetParameters} newTokenSet
   * @returns {void}
   */
  append(req, newTokenSet) {
    req[SYMBOL].push(newTokenSet);
  },

  /**
   * @param {import('express').Request} req
   * @param {number} index
   * @param {import('openid-client').TokenSetParameters} newTokenSet
   * @returns {void}
   */
  _replace(req, index, newTokenSet) {
    req[SYMBOL][index] = newTokenSet;
  },

  /**
   * @param {import('express').Request} req
   * @param {(ts: import('openid-client').TokenSetParameters) => boolean} predicate
   * @param {import('openid-client').TokenSetParameters} newTokenSet
   * @returns {void}
   */
  _patchBy(req, predicate, newTokenSet) {
    const tokenSets = this.getAll(req);

    tokenSets.forEach((ts, index) => {
      if (predicate(ts)) {
        this._replace(req, index, { ...tokenSets[index], ...newTokenSet });
      }
    });
  },

  /**
   * @param {import('express').Request} req
   * @param {string} accessToken
   * @param {import('openid-client').TokenSetParameters} newTokenSet
   * @returns {void}
   */
  patchByAccessToken(req, accessToken, newTokenSet) {
    return this._patchBy(req, (ts) => ts.access_token === accessToken, newTokenSet);
  },

  /**
   * @param {import('express').Request} req
   * @param {string} refreshToken
   * @param {import('openid-client').TokenSetParameters} newTokenSet
   * @returns {void}
   */
  patchByRefreshToken(req, refreshToken, newTokenSet) {
    return this._patchBy(req, (ts) => ts.refresh_token === refreshToken, newTokenSet);
  },

  /**
   * @param {string} requested
   * @param {string} available
   * @returns {boolean}
   */
  _areScopesCompatible(requested, available) {
    const requestedScopes = requested.split(' ');
    const availableScopes = available.split(' ');

    return requestedScopes.every((s) => availableScopes.includes(s));
  },

  /**
   * @param {Pick<import('..').Session, 'access_token' | 'refresh_token'>} session
   * @param {Pick<import('openid-client').TokenSetParameters, 'access_token' | 'refresh_token'>} newTokenSet
   * @returns {void}
   */
  _invalidateTokenSetIfNeeded(session, newTokenSet) {
    const {
      access_token: oldAccessToken,
      refresh_token: oldRefreshToken,
    } = session;

    const {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
    } = newTokenSet;

    // We don't check other properties since it doesn't make sense
    // that those would change but AT/RT didn't.
    if (oldAccessToken !== newAccessToken
      || oldRefreshToken !== newRefreshToken) {
      const cachedTokenSet = weakCache.weakRef(session);
      delete cachedTokenSet.value;
    }
  },

  /**
   * @param {import('express').Request} req
   * @param {import('openid-client').TokenSetParameters} newTokenSet
   * @returns {void}
   */
  setCurrent(req, newTokenSet) {
    const values = {
      id_token: newTokenSet.id_token,
      access_token: newTokenSet.access_token,
      refresh_token: newTokenSet.refresh_token,
      token_type: newTokenSet.token_type,
      expires_at: newTokenSet.expires_at,
    };

    if (newTokenSet.audience) {
      values.audience = newTokenSet.audience;
    }

    if (newTokenSet.scope) {
      values.scope = newTokenSet.scope;
    }

    if (newTokenSet.organization) {
      values.organization = newTokenSet.organization;
    }

    const { config } = weakCache.weakRef(req.oidc);
    const session = req[config.session.name];

    // If we're going to mutate the current tokenset in the session,
    // we have to invalidate the tokenset weakCache because it's bound
    // to the session reference.
    //
    // Note that we invalidate first! Otherwise we wouldn't be able
    // to compare with the old values in the session.
    this._invalidateTokenSetIfNeeded(session, newTokenSet);

    Object.assign(session, values);
  },

  /**
   * @param {import('..').AuthorizationParameters} [authorizationParams]
   * @returns {Promise<import('openid-client').TokenSetParameters | undefined>}
   */
  async findCompatible(req, authorizationParams = {}) {
    const context = weakCache.weakRef(req.oidc);

    const mergedParams = {
      ...context.config.authorizationParams,
      ...authorizationParams,
    };

    const tokenSets = this.getAll(req);

    const found = tokenSets.find((ts) => {
      // TODO: improve this logic to be more useful

      if (mergedParams.organization !== ts.organization) {
        return false;
      }

      if (mergedParams.audience !== ts.audience) {
        return false;
      }

      if (mergedParams.scope && ts.scope) {
        const scopesAreCompatible = this._areScopesCompatible(mergedParams.scope, ts.scope);

        if (!scopesAreCompatible) {
          return false;
        }
      }

      return true;
    });

    return found;
  },

  /**
   * @param {import('express').Request} req
   * @returns {Promise<void>}
   */
  async maybeRefreshCurrent(req) {
    const context = weakCache.weakRef(req.oidc);

    if (!context.config.autoRefreshIfExpired) {
      return;
    }

    const { accessToken } = req.oidc;

    if (accessToken && accessToken.isExpired()) {
      await accessToken.refresh();
    }
  },
};

module.exports = {
  TokenSets,
};

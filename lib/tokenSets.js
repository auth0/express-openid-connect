// @ts-check

const { get: getClient } = require('./client');
const weakCache = require('./weakCache');

const SYMBOL = Symbol('tokenSets');

const TokenSets = {
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
    req[SYMBOL].push(newTokenSet);
  },

  /**
   * @param {import('express').Request} req
   * @param {number} index
   * @param {import('..').TokenSetParameters} newTokenSet
   * @returns {void}
   */
  _replace(req, index, newTokenSet) {
    req[SYMBOL][index] = newTokenSet;
  },

  /**
   * @param {import('express').Request} req
   * @param {(ts: import('..').TokenSetParameters) => boolean} predicate
   * @param {import('..').TokenSetParameters} newTokenSet
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
   * @param {import('..').TokenSetParameters} newTokenSet
   * @returns {void}
   */
  patchByAccessToken(req, accessToken, newTokenSet) {
    return this._patchBy(req, (ts) => ts.access_token === accessToken, newTokenSet);
  },

  /**
   * @param {import('express').Request} req
   * @param {string} refreshToken
   * @param {import('..').TokenSetParameters} newTokenSet
   * @returns {void}
   */
  patchByRefreshToken(req, refreshToken, newTokenSet) {
    return this._patchBy(req, (ts) => ts.refresh_token === refreshToken, newTokenSet);
  },

  /**
   * @param {Pick<import('..').AuthorizationParameters, 'scope'>} requested
   * @param {Pick<import('..').TokenSetParameters, 'scope'>} available
   * @returns {boolean}
   */
  _areScopesCompatible(requested, available) {
    let { scope: requestedScope } = requested;
    const { scope: availableScope } = available;

    // no requested scope => fall back to SDK defaults
    if (!requestedScope) {
      requestedScope = 'openid profile email';
    }

    // requested scope + no available scope => never compatible
    if (!availableScope) {
      return false;
    }

    const requestedScopes = requestedScope.split(' ');
    const availableScopes = availableScope.split(' ');

    return requestedScopes.every((s) => availableScopes.includes(s));
  },

  /**
   * @param {Pick<import('..').AuthorizationParameters, 'audience'>} requested
   * @param {Pick<import('..').TokenSetParameters, 'audience'>} available
   * @returns {boolean}
   */
  _areAudiencesCompatible(requested, available) {
    const { audience: requestedAudience } = requested;
    const { audience: availableAudience } = available;

    return requestedAudience === availableAudience;
  },

  /**
   * @param {Pick<import('..').AuthorizationParameters, 'organization'>} requested
   * @param {Pick<import('..').TokenSetParameters, 'organization'>} available
   * @returns {boolean}
   */
  _areOrganizationsCompatible(requested, available) {
    const { organization: requestedOrganization } = requested;
    const { organization: availableOrganization } = available;

    return requestedOrganization === availableOrganization;
  },

  /**
   * @param {import('..').AuthorizationParameters} requested
   * @param {import('..').TokenSetParameters} available
   * @returns {boolean}
   */
  _areTokenSetsCompatible(requested, available) {
    return this._areAudiencesCompatible(requested, available) &&
      this._areOrganizationsCompatible(requested, available) &&
      this._areScopesCompatible(requested, available);
  },

  /**
   * @param {Pick<import('..').TokenSetParameters, 'expires_at'>} tokenSet
   * @returns {boolean}
   */
  _isExpired(tokenSet) {
    return tokenSet.expires_at
      ? tokenSet.expires_at < Math.round(Date.now() / 1000)
      : true;
  },

  /**
   * @param {Pick<import('..').Session, 'access_token' | 'refresh_token'>} session
   * @param {Pick<import('..').TokenSetParameters, 'access_token' | 'refresh_token'>} newTokenSet
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
   * @param {import('..').TokenSetParameters} newTokenSet
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
   * @param {import('express').Request} req 
   * @param {import('..').AuthorizationParameters} authorizationParams
   * @returns {import('..').TokenSetParameters | undefined}
   */
  _findCompatibleActive(req, authorizationParams) {
    const tokenSets = this.getAll(req);

    return tokenSets.find((ts) =>
      !this._isExpired(ts) &&
      this._areTokenSetsCompatible(authorizationParams, ts),
    );
  },

  /**
   * @param {import('express').Request} req 
   * @param {import('..').AuthorizationParameters} authorizationParams
   * @returns {import('..').TokenSetParameters | undefined}
   */
  _findCompatibleExpired(req, authorizationParams) {
    const tokenSets = this.getAll(req);

    return tokenSets.find((ts) =>
      this._isExpired(ts) &&
      this._areTokenSetsCompatible(authorizationParams, ts),
    );
  },

  /**
   * @param {import('express').Request} req 
   * @param {import('..').AuthorizationParameters} authorizationParams
   * @returns {(import('..').TokenSetParameters & { refresh_token: string }) | undefined}
   */
  _findCompatibleRefreshable(req, authorizationParams) {
    const tokenSets = this.getAll(req);

    return tokenSets.find(
      /**
       * @param {import('..').TokenSetParameters} ts
       * @returns {ts is import('..').TokenSetParameters & { refresh_token: string }}
       */
      (ts) =>
        ts.refresh_token !== undefined &&
        this._areTokenSetsCompatible(authorizationParams, ts),
    );
  },

  /**
   * @param {import('express').Request} req
   * @param {import('..').AuthorizationParameters} [authorizationParams]
   * @returns {Promise<import('..').TokenSetParameters | undefined>}
   */
  async findCompatible(req, authorizationParams = {}) {
    const { config } = weakCache.weakRef(req.oidc);

    const mergedParams = {
      ...config.authorizationParams,
      ...authorizationParams,
    };

    /** @type {import('..').TokenSetParameters | undefined} */
    let found;

    // Try to find a compatible & active tokenset.
    found = this._findCompatibleActive(req, mergedParams);

    if (found) {
      return found;
    }

    // Try to find a compatible & refreshable tokenset. Note that at this
    // point if this returns something it will be expired but it will be
    // taken care of in the caller before making it available to the context
    // (unless `autoRefreshIfExpired` is disabled).
    found = this._findCompatibleRefreshable(req, mergedParams);

    if (found) {
      return found;
    }

    found = this._findCompatibleExpired(req, mergedParams);

    if (found) {
      return found;
    }

    return undefined;
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

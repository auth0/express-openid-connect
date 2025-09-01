// @ts-check

const { get: getClient } = require('./client');
const weakCache = require('./weakCache');

const SYMBOL = Symbol('tokenSets');

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
   * This method apparently does nothing useful, but it's needed because
   * tokensets are saved in the session data intermingled with arbitrary
   * data, so we need a "clean" tokenset before saving it into the history.
   *
   * @param {import('..').TokenSetParameters} tokenSet
   * @returns {import('..').TokenSetParameters}
   */
  _cleanTokenSet(tokenSet) {
    /** @type {import('..').TokenSetParameters} */
    const output = {
      id_token: tokenSet.id_token,
      access_token: tokenSet.access_token,
      refresh_token: tokenSet.refresh_token,
      token_type: tokenSet.token_type,
      expires_at: tokenSet.expires_at,
    };

    if (tokenSet.audience) {
      output.audience = tokenSet.audience;
    }

    if (tokenSet.scope) {
      output.scope = tokenSet.scope;
    }

    if (tokenSet.organization) {
      output.organization = tokenSet.organization;
    }

    return output;
  },

  /**
   * @param {import('express').Request} req
   * @param {import('..').TokenSetParameters} newTokenSet
   * @returns {void}
   */
  append(req, newTokenSet) {
    req[SYMBOL].push(this._cleanTokenSet(newTokenSet));
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
        return this._isExpired(ts);
      }

      // Expired tokens with RT are useful but don't keep them around forever.
      if (this._hasBeenExpiredForAtLeast(ts, PRUNE_GRACE_PERIOD)) {
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
      newValues
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
      newValues
    );
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
    return (
      this._areAudiencesCompatible(requested, available) &&
      this._areOrganizationsCompatible(requested, available) &&
      this._areScopesCompatible(requested, available)
    );
  },

  /**
   * @param {Pick<import('..').TokenSetParameters, 'expires_at'>} tokenSet
   * @param {number} seconds
   * @returns {boolean}
   */
  _hasBeenExpiredForAtLeast(tokenSet, seconds) {
    return tokenSet.expires_at
      ? Math.round(Date.now() / 1000) > tokenSet.expires_at + seconds
      : true;
  },

  /**
   * @param {Pick<import('..').TokenSetParameters, 'expires_at'>} tokenSet
   * @returns {boolean}
   */
  _isExpired(tokenSet) {
    return this._hasBeenExpiredForAtLeast(tokenSet, 0);
  },

  /**
   * @param {Pick<import('..').Session, 'access_token' | 'refresh_token'>} session
   * @param {Pick<import('..').TokenSetParameters, 'access_token' | 'refresh_token'>} newTokenSet
   * @returns {void}
   */
  _invalidateTokenSetIfNeeded(session, newTokenSet) {
    const { access_token: oldAccessToken, refresh_token: oldRefreshToken } =
      session;

    const { access_token: newAccessToken, refresh_token: newRefreshToken } =
      newTokenSet;

    // We don't check other properties since it doesn't make sense
    // that those would change but AT/RT didn't.
    if (
      oldAccessToken !== newAccessToken ||
      oldRefreshToken !== newRefreshToken
    ) {
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
    const { config } = weakCache.weakRef(req.oidc);
    const session = req[config.session.name];

    // If we're going to mutate the current tokenset in the session,
    // we have to invalidate the tokenset weakCache because it's bound
    // to the session reference.
    //
    // Note that we invalidate first! Otherwise we wouldn't be able
    // to compare with the old values in the session.
    this._invalidateTokenSetIfNeeded(session, newTokenSet);

    Object.assign(session, this._cleanTokenSet(newTokenSet));
  },

  /**
   * @param {import('..').TokenSetParameters[]} tokenSets
   * @param {import('..').AuthorizationParameters} authorizationParams
   * @returns {import('..').TokenSetParameters | undefined}
   */
  _findCompatibleActive(tokenSets, authorizationParams) {
    return tokenSets.find(
      (ts) =>
        !this._isExpired(ts) &&
        this._areTokenSetsCompatible(authorizationParams, ts)
    );
  },

  /**
   * @param {import('..').TokenSetParameters[]} tokenSets
   * @param {import('..').AuthorizationParameters} authorizationParams
   * @returns {import('..').TokenSetParameters | undefined}
   */
  _findCompatibleExpired(tokenSets, authorizationParams) {
    return tokenSets.find(
      (ts) =>
        this._isExpired(ts) &&
        this._areTokenSetsCompatible(authorizationParams, ts)
    );
  },

  /**
   * @param {import('..').TokenSetParameters[]} tokenSets
   * @param {import('..').AuthorizationParameters} authorizationParams
   * @returns {(import('..').TokenSetParameters & { refresh_token: string }) | undefined}
   */
  _findCompatibleRefreshable(tokenSets, authorizationParams) {
    return tokenSets.find(
      /**
       * @param {import('..').TokenSetParameters} ts
       * @returns {ts is import('..').TokenSetParameters & { refresh_token: string }}
       */
      (ts) =>
        ts.refresh_token !== undefined &&
        this._areTokenSetsCompatible(authorizationParams, ts)
    );
  },

  /**
   * @param {import('..').TokenSetParameters[]} tokenSets
   * @param {import('..').AuthorizationParameters} authorizationParams
   * @returns {(import('..').TokenSetParameters & { refresh_token: string })[]}
   */
  _filterMrrtable(tokenSets, authorizationParams) {
    return tokenSets.filter(
      /**
       * @param {import('..').TokenSetParameters} ts
       * @returns {ts is import('..').TokenSetParameters & { refresh_token: string }}
       */
      (ts) =>
        ts.refresh_token !== undefined &&
        this._areOrganizationsCompatible(authorizationParams, ts)
    );
  },

  /**
   * @param {import('..').ConfigParams} config
   * @param {import('..').TokenSetParameters[]} tokenSets
   * @param {import('..').AuthorizationParameters} [authorizationParams]
   * @returns {Promise<import('..').TokenSetParameters | undefined>}
   */
  async _findMrrtable(config, tokenSets, authorizationParams = {}) {
    const mrrtable = this._filterMrrtable(tokenSets, authorizationParams);

    if (mrrtable.length === 0) {
      return undefined;
    }

    const { client, issuer } = await getClient(config);
    const { refresh_token: refreshToken } = mrrtable[0];

    try {
      const newTokenSet = await client.refresh(refreshToken, {
        clientAssertionPayload: { aud: issuer.issuer },

        // Since this refresh is done behind the scenes, be conservative
        // about what we use from `tokenEndpointParams` and use only the
        // ones we know might be useful in a refresh via MRRT.
        exchangeBody: {
          audience: authorizationParams.audience,
          scope: authorizationParams.scope,
        },
      });

      // A MRRT request ignores invalid parameters and succeeds anyway,
      // so we don't have a way to identify the case where the wrong
      // policies are configured. Let's try at least to indirectly
      // validate through the received scopes.
      if (!this._areScopesCompatible(authorizationParams, newTokenSet)) {
        throw new Error('MRRT refresh resulted in the wrong scopes');
      }

      return newTokenSet;
    } catch (err) {
      // A failure in a MRRT refresh is not something we want to throw outside,
      // just keep going so we can get to any subsequent fallbacks.
    }
  },

  /**
   * @param {import('express').Request} req
   * @param {import('..').AuthorizationParameters} [authorizationParams]
   * @returns {Promise<import('..').TokenSetParameters | undefined>}
   */
  async findCompatible(req, authorizationParams = {}) {
    const { config } = weakCache.weakRef(req.oidc);

    // Candidate tokensets will be:
    // - The full history if enabled, which *includes the current one*.
    // - Just the current tokenset if history is disabled.
    const tokenSets = config.tokenHistory
      ? this.getAll(req)
      : [req[config.session.name]];

    const mergedParams = {
      ...config.authorizationParams,
      ...authorizationParams,
    };

    /** @type {import('..').TokenSetParameters | undefined} */
    let found;

    // Try to find a compatible & active tokenset.
    found = this._findCompatibleActive(tokenSets, mergedParams);

    if (found) {
      return found;
    }

    // Try to find a compatible & refreshable tokenset. Note that at this
    // point if this returns something it will be expired but it will be
    // taken care of in the caller before making it available to the context
    // (unless `autoRefreshExpired` is disabled).
    found = this._findCompatibleRefreshable(tokenSets, mergedParams);

    if (found) {
      return found;
    }

    found = this._findCompatibleExpired(tokenSets, mergedParams);

    if (found) {
      return found;
    }

    if (config.useMrrt) {
      // Try to find a "MRRT-able" tokenset (i.e. not directly compatible
      // but with an RT that might issue a compatible tokenset).
      found = await this._findMrrtable(config, tokenSets, mergedParams);

      if (found) {
        // A normal refresh overwrites the previous tokenset since it's supposed
        // to be expired. However a MRRT refresh is a "lateral move" to get a
        // tokenset for a different audience than the first, so we keep both.
        TokenHistory.append(req, found);

        return found;
      }
    }

    return undefined;
  },

  /**
   * @param {import('express').Request} req
   * @returns {Promise<void>}
   */
  async maybeRefreshCurrent(req) {
    const context = weakCache.weakRef(req.oidc);

    if (!context.config.autoRefreshExpired) {
      return;
    }

    const { accessToken } = req.oidc;

    if (accessToken && accessToken.isExpired()) {
      await accessToken.refresh();
    }
  },
};

module.exports = {
  TokenHistory,
};

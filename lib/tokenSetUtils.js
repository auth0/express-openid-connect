// @ts-check

const client = require('./client');
const weakCache = require('./weakCache');

const TokenSetUtils = {
  /**
   * This method apparently does nothing useful, but it's needed because
   * tokensets are saved in the session data intermingled with arbitrary
   * data, so we need a "clean" tokenset before saving it into the history.
   *
   * @param {import('..').TokenSetParameters} tokenSet
   * @returns {import('..').TokenSetParameters}
   */
  cleanTokenSet(tokenSet) {
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
   * @param {Pick<import('..').AuthorizationParameters, 'scope'>} requested
   * @param {Pick<import('..').TokenSetParameters, 'scope'>} available
   * @returns {boolean}
   */
  areScopesCompatible(requested, available) {
    let { scope: requestedScope } = requested;
    const { scope: availableScope } = available;

    if (!requestedScope || !availableScope) {
      return true;
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
  areAudiencesCompatible(requested, available) {
    if (!requested.audience || !available.audience) {
      return true;
    }

    return requested.audience === available.audience;
  },

  /**
   * @param {Pick<import('..').AuthorizationParameters, 'organization'>} requested
   * @param {Pick<import('..').TokenSetParameters, 'organization'>} available
   * @returns {boolean}
   */
  areOrganizationsCompatible(requested, available) {
    if (!requested.organization || !available.organization) {
      return true;
    }

    return requested.organization === available.organization;
  },

  /**
   * @param {Pick<import('..').AuthorizationParameters, 'audience' | 'organization' | 'scope'>} requested
   * @param {Pick<import('..').TokenSetParameters, 'audience' | 'organization' | 'scope'>} available
   * @returns {boolean}
   */
  areTokenSetsCompatible(requested, available) {
    return (
      this.areAudiencesCompatible(requested, available) &&
      this.areOrganizationsCompatible(requested, available) &&
      this.areScopesCompatible(requested, available)
    );
  },

  /**
   * @param {Pick<import('..').TokenSetParameters, 'expires_at'>} tokenSet
   * @param {number} seconds
   * @returns {boolean}
   */
  hasBeenExpiredForAtLeast(tokenSet, seconds) {
    return tokenSet.expires_at
      ? Math.round(Date.now() / 1000) > tokenSet.expires_at + seconds
      : true;
  },

  /**
   * @param {Pick<import('..').TokenSetParameters, 'expires_at'>} tokenSet
   * @returns {boolean}
   */
  isExpired(tokenSet) {
    return this.hasBeenExpiredForAtLeast(tokenSet, 0);
  },

  /**
   * @param {Pick<import('..').Session, 'access_token' | 'refresh_token'>} session
   * @param {Pick<import('..').TokenSetParameters, 'access_token' | 'refresh_token'>} newTokenSet
   * @returns {void}
   */
  invalidateCachedTokenSetIfNeeded(session, newTokenSet) {
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
    this.invalidateCachedTokenSetIfNeeded(session, newTokenSet);

    Object.assign(session, TokenSetUtils.cleanTokenSet(newTokenSet));
  },

  /**
   * @param {import('..').ConfigParams} config
   * @param {import('./tokenSets').RefreshableTokenSet} tokenSet
   * @param {import('..').AuthorizationParameters} [authorizationParams]
   * @returns {Promise<import('..').TokenSetParameters | undefined>}
   */
  async doMrrtRefresh(config, tokenSet, authorizationParams = {}) {
    const { client: openIdClient, issuer } = await client.get(config);

    try {
      const newTokenSet = await openIdClient.refresh(tokenSet.refresh_token, {
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
      if (!this.areScopesCompatible(authorizationParams, newTokenSet)) {
        throw new Error('MRRT refresh resulted in the wrong scopes');
      }

      return newTokenSet;
    } catch {
      // A failure in a MRRT refresh is not something we want to throw outside,
      // just keep going so we can get to any subsequent fallbacks.
    }
  },

  /**
   * @param {import('express').Request} req
   * @returns {Promise<void>}
   */
  async maybeRefreshCurrentIfNeeded(req) {
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
  TokenSetUtils,
};

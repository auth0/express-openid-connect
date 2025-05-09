// @ts-check

const weakCache = require('./weakCache');

const TokenSets = {
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

    const session = req[context.config.session.name];

    // TODO: improve this logic to be more useful

    if (mergedParams.organization !== session.organization) {
      return undefined;
    }

    if (mergedParams.audience !== session.audience) {
      return undefined;
    }

    if (mergedParams.scope && session.scope) {
      const scopesAreCompatible = this._areScopesCompatible(mergedParams.scope, session.scope);

      if (!scopesAreCompatible) {
        return undefined;
      }
    }

    return session;
  },
};

module.exports = {
  TokenSets,
};

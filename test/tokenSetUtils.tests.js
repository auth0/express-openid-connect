// @ts-check

const { assert } = require('chai');
const sinon = require('sinon');
const weakCache = require('../lib/weakCache');
const { TokenSetUtils } = require('../lib/tokenSetUtils');
const client = require('../lib/client');

/**
 * @param {Record<string, unknown>} [props]
 * @returns {import('express').Request}
 * */
function newReq(props = {}) {
  // @ts-expect-error just for passing around, not worth mocking
  return props;
}

describe('TokenSetUtils', () => {
  describe('areScopesCompatible()', () => {
    it('returns true when scopes are enough plus some extra', () => {
      assert.isTrue(
        TokenSetUtils.areScopesCompatible({ scope: 'a b' }, { scope: 'b c a' }),
      );
    });

    it('returns false when scopes are not enough', () => {
      assert.isFalse(
        TokenSetUtils.areScopesCompatible({ scope: 'a b' }, { scope: 'b' }),
      );
    });

    it('falls back to default SDK scope when no scope is requested', () => {
      assert.isTrue(
        TokenSetUtils.areScopesCompatible(
          {},
          { scope: 'openid profile email' },
        ),
      );
    });

    it('returns false when no scope is available', () => {
      assert.isFalse(TokenSetUtils.areScopesCompatible({ scope: 'a b' }, {}));
    });
  });

  describe('areAudiencesCompatible()', () => {
    /** @type {[string | undefined, string | undefined, boolean][]} */
    const testCases = [
      ['foo', 'foo', true],
      ['foo', 'bar', false],
      ['foo', undefined, true],
      [undefined, undefined, true],
    ];

    testCases.forEach((testCase) => {
      const [requested, available, expected] = testCase;

      it(`returns ${expected} for (${requested}, ${available})`, () => {
        assert.strictEqual(
          expected,
          TokenSetUtils.areAudiencesCompatible(
            { audience: requested },
            { audience: available },
          ),
        );
      });
    });
  });

  describe('areOrganizationsCompatible()', () => {
    /** @type {[string | undefined, string | undefined, boolean][]} */
    const testCases = [
      ['foo', 'foo', true],
      ['foo', 'bar', false],
      ['foo', undefined, true],
      [undefined, undefined, true],
    ];

    testCases.forEach((testCase) => {
      const [requested, available, expected] = testCase;

      it(`returns ${expected} for (${requested}, ${available})`, () => {
        assert.strictEqual(
          expected,
          TokenSetUtils.areOrganizationsCompatible(
            { organization: requested },
            { organization: available },
          ),
        );
      });
    });
  });

  describe('hasBeenExpiredForAtLeast()', () => {
    const gracePeriod = 86400;
    const now = Math.floor(Date.now() / 1000);

    it('returns true when token is very expired', () => {
      const token = {
        expires_at: now - gracePeriod - 100,
      };

      assert.isTrue(TokenSetUtils.hasBeenExpiredForAtLeast(token, gracePeriod));
    });

    it('returns false when token has just expired', () => {
      const token = {
        expires_at: now - gracePeriod + 100,
      };

      assert.isFalse(
        TokenSetUtils.hasBeenExpiredForAtLeast(token, gracePeriod),
      );
    });

    it('returns false when token is not expired', () => {
      const token = { expires_at: now + 100 };

      assert.isFalse(
        TokenSetUtils.hasBeenExpiredForAtLeast(token, gracePeriod),
      );
    });
  });

  describe('isExpired()', () => {
    const now = Math.floor(Date.now() / 1000);

    it('returns true when token is expired', () => {
      const expiredToken = { expires_at: now - 100 };
      assert.isTrue(TokenSetUtils.isExpired(expiredToken));
    });

    it('returns false when token is not expired', () => {
      const validToken = { expires_at: now + 100 };
      assert.isFalse(TokenSetUtils.isExpired(validToken));
    });

    it('returns true when expires_at is not present', () => {
      assert.isTrue(TokenSetUtils.isExpired({}));
    });
  });

  describe('invalidateCachedTokenSetIfNeeded()', () => {
    const session = { access_token: 'AT1', refresh_token: 'RT1' };

    describe('access token changed', () => {
      it('deletes the cache', () => {
        const cachedTokenSet = { value: {} };
        sinon.stub(weakCache, 'weakRef').returns(cachedTokenSet);

        TokenSetUtils.invalidateCachedTokenSetIfNeeded(session, {
          access_token: 'AT2',
        });

        assert.isUndefined(cachedTokenSet.value);

        sinon.restore();
      });
    });

    describe('refresh token changed', () => {
      it('deletes the cache', () => {
        const cachedTokenSet = { value: {} };
        sinon.stub(weakCache, 'weakRef').returns(cachedTokenSet);

        TokenSetUtils.invalidateCachedTokenSetIfNeeded(session, {
          refresh_token: 'RT2',
        });

        assert.isUndefined(cachedTokenSet.value);

        sinon.restore();
      });
    });

    describe('nothing changed', () => {
      it('does not touch the cache', () => {
        const weakRefSpy = sinon.spy(weakCache, 'weakRef');

        TokenSetUtils.invalidateCachedTokenSetIfNeeded(session, {
          access_token: session.access_token,
          refresh_token: session.refresh_token,
        });

        assert.isFalse(weakRefSpy.called);

        sinon.restore();
      });
    });
  });

  describe('setCurrent()', () => {
    it('merges the new tokenset into the session', () => {
      const sessName = 'mySession';

      const req = newReq();
      req[sessName] = {
        access_token: 'foo1',
        something_else: 'bar',
      };

      sinon.stub(weakCache, 'weakRef').returns({
        config: { session: { name: sessName } },
      });

      const invalidateSpy = sinon.spy(
        TokenSetUtils,
        'invalidateCachedTokenSetIfNeeded',
      );

      const newTokenSet = { access_token: 'foo2', refresh_token: 'qux' };

      TokenSetUtils.setCurrent(req, newTokenSet);

      assert.isTrue(invalidateSpy.called);
      assert.equal(req[sessName].access_token, 'foo2'); // overwritten
      assert.equal(req[sessName].refresh_token, 'qux'); // new prop
      assert.equal(req[sessName].something_else, 'bar'); // untouched

      sinon.restore();
    });
  });

  describe('doMrrtRefresh()', () => {
    const tokenSet = { access_token: 'test_at', refresh_token: 'test_rt' };
    const refreshedTokenSet = { access_token: 'refreshed_at' };

    describe('refresh succeeds', () => {
      it('refresh is done with the expected parameters', async () => {
        const authorizationParams = {
          audience: 'test_aud',
          scope: 'test_scope',
          extra: 'foo',
        };

        const refreshSpy = sinon.spy();
        const issuer = 'test_issuer';

        sinon.stub(client, 'get').resolves({
          client: { refresh: refreshSpy },
          issuer: { issuer },
        });

        sinon.stub(TokenSetUtils, 'areScopesCompatible').returns(true);

        await TokenSetUtils.doMrrtRefresh({}, tokenSet, authorizationParams);

        assert.isTrue(
          refreshSpy.calledWith(tokenSet.refresh_token, {
            clientAssertionPayload: { aud: issuer },
            exchangeBody: {
              audience: authorizationParams.audience,
              scope: authorizationParams.scope,
            },
          }),
        );

        sinon.restore();
      });

      describe('scopes are compatible', () => {
        it('returns refreshed tokenset', async () => {
          sinon.stub(client, 'get').resolves({
            client: { refresh: () => Promise.resolve(refreshedTokenSet) },
            issuer: {},
          });

          sinon.stub(TokenSetUtils, 'areScopesCompatible').returns(true);

          assert.strictEqual(
            await TokenSetUtils.doMrrtRefresh({}, tokenSet),
            refreshedTokenSet,
          );

          sinon.restore();
        });
      });

      describe('otherwise', () => {
        it('returns undefined', async () => {
          sinon.stub(client, 'get').resolves({
            client: { refresh: () => Promise.resolve(refreshedTokenSet) },
            issuer: {},
          });

          sinon.stub(TokenSetUtils, 'areScopesCompatible').returns(false);

          assert.isUndefined(await TokenSetUtils.doMrrtRefresh({}, tokenSet));

          sinon.restore();
        });
      });
    });

    describe('refresh fails', () => {
      it('returns undefined', async () => {
        sinon.stub(client, 'get').resolves({
          client: {
            refresh: () => Promise.reject(new Error('refresh error!')),
          },
          issuer: {},
        });

        assert.isUndefined(await TokenSetUtils.doMrrtRefresh({}, tokenSet));

        sinon.restore();
      });
    });
  });

  describe('maybeRefreshCurrentIfNeeded()', async () => {
    describe('autoRefreshExpired disabled', async () => {
      it('does not refresh the token', async () => {
        const context = {
          config: { autoRefreshExpired: false },
        };

        sinon.stub(weakCache, 'weakRef').returns(context);

        const reqProps = {
          oidc: { accessToken: { refresh: sinon.spy() } },
        };

        await TokenSetUtils.maybeRefreshCurrentIfNeeded(newReq(reqProps));

        assert.isFalse(reqProps.oidc.accessToken.refresh.called);

        sinon.restore();
      });
    });

    describe('autoRefreshExpired enabled + token expired', async () => {
      it('refreshes the token', async () => {
        const context = {
          config: { autoRefreshExpired: true },
        };

        sinon.stub(weakCache, 'weakRef').returns(context);

        const reqProps = {
          oidc: {
            accessToken: {
              isExpired: () => true,
              refresh: sinon.stub().resolves(),
            },
          },
        };

        await TokenSetUtils.maybeRefreshCurrentIfNeeded(newReq(reqProps));

        assert.isTrue(reqProps.oidc.accessToken.refresh.called);

        sinon.restore();
      });
    });

    describe('autoRefreshExpired enabled + token active', async () => {
      it('does not refresh the token', async () => {
        const context = {
          config: { autoRefreshExpired: true },
        };

        sinon.stub(weakCache, 'weakRef').returns(context);

        const reqProps = {
          oidc: {
            accessToken: {
              isExpired: () => false,
              refresh: sinon.stub().resolves(),
            },
          },
        };

        await TokenSetUtils.maybeRefreshCurrentIfNeeded(newReq(reqProps));

        assert.isFalse(reqProps.oidc.accessToken.refresh.called);

        sinon.restore();
      });
    });
  });
});

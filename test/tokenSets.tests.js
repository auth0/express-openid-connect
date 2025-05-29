// @ts-check

const { assert } = require('chai');
const sinon = require('sinon');
const weakCache = require('../lib/weakCache');
const { TokenSets } = require('../lib/tokenSets');

/**
 * @param {Record<string, unknown>} [props]
 * @returns {import('express').Request}
 * */
function newReq(props = {}) {
  // @ts-expect-error just for passing around, not worth mocking
  return props;
}

const authorizationParams = {
  audience: 'aud',
  scope: 'read:foo',
  organization: 'org',
};

const YESTERDAY = Math.round(Date.now() / 1000) - 86400;
const TOMORROW = Math.round(Date.now() / 1000) + 86400;

/** @type {import('..').TokenSetParameters[]} */
const tokenSets = [
  // active + compatible
  { ...authorizationParams, expires_at: TOMORROW },
  // active + compatible + refreshable + mrrt-able
  { ...authorizationParams, expires_at: TOMORROW, refresh_token: 'rt123' },
  // active + incompatible
  { ...authorizationParams, expires_at: TOMORROW, audience: 'bad' },
  // active + incompatible
  { ...authorizationParams, expires_at: TOMORROW, scope: 'bad' },
  // active + incompatible
  {
    ...authorizationParams,
    expires_at: TOMORROW,
    refresh_token: 'rt123',
    organization: 'bad',
  },
  // active + incompatible + mrrt-able
  {
    ...authorizationParams,
    expires_at: TOMORROW,
    refresh_token: 'rt123',
    audience: 'bad',
  },
  // active + incompatible + mrrt-able
  {
    ...authorizationParams,
    expires_at: TOMORROW,
    refresh_token: 'rt123',
    scope: 'bad',
  },
  // active + incompatible
  { ...authorizationParams, expires_at: TOMORROW, organization: 'bad' },
  // expired + compatible
  { ...authorizationParams, expires_at: YESTERDAY },
  // expired + compatible + refreshable + mrrt-able
  { ...authorizationParams, expires_at: YESTERDAY, refresh_token: 'rt123' },
];

describe('tokenSets', () => {
  describe('attach()', () => {
    it('attaches the tokensets to the request', () => {
      const req = newReq();
      const tokenSets = [];

      TokenSets.attach(req, tokenSets);

      assert.strictEqual(TokenSets.getAll(req), tokenSets);
    });
  });

  describe('getAll()', () => {
    it('returns an empty array if not attached', () => {
      const req = newReq();

      assert.deepEqual(TokenSets.getAll(req), []);
    });
  });

  describe('append()', () => {
    it('appends a tokenset to the list', () => {
      const req = newReq();

      const tokenSet1 = { access_token: 'one' };
      const tokenSet2 = { access_token: 'two' };

      const tokenSets = [tokenSet1];
      TokenSets.attach(req, tokenSets);

      TokenSets.append(req, tokenSet2);

      assert.deepEqual(TokenSets.getAll(req), [tokenSet1, tokenSet2]);
    });
  });

  describe('_areScopesCompatible', () => {
    it('returns true when scopes are enough plus some extra', () => {
      assert.isTrue(
        TokenSets._areScopesCompatible({ scope: 'a b' }, { scope: 'b c a' })
      );
    });

    it('returns false when scopes are not enough', () => {
      assert.isFalse(
        TokenSets._areScopesCompatible({ scope: 'a b' }, { scope: 'b' })
      );
    });

    it('falls back to default SDK scope when no scope is requested', () => {
      assert.isTrue(
        TokenSets._areScopesCompatible({}, { scope: 'openid profile email' })
      );
    });

    it('returns false when no scope is available', () => {
      assert.isFalse(TokenSets._areScopesCompatible({ scope: 'a b' }, {}));
    });
  });

  describe('_areAudiencesCompatible', () => {
    /** @type {[string | undefined, string | undefined, boolean][]} */
    const testCases = [
      ['foo', 'foo', true],
      ['foo', 'bar', false],
      ['foo', undefined, false],
      [undefined, undefined, true],
    ];

    testCases.forEach((testCase) => {
      const [requested, available, expected] = testCase;

      it(`returns ${expected} for (${requested}, ${available})`, () => {
        assert.strictEqual(
          expected,
          TokenSets._areAudiencesCompatible(
            { audience: requested },
            { audience: available }
          )
        );
      });
    });
  });

  describe('_areOrganizationsCompatible', () => {
    /** @type {[string | undefined, string | undefined, boolean][]} */
    const testCases = [
      ['foo', 'foo', true],
      ['foo', 'bar', false],
      ['foo', undefined, false],
      [undefined, undefined, true],
    ];

    testCases.forEach((testCase) => {
      const [requested, available, expected] = testCase;

      it(`returns ${expected} for (${requested}, ${available})`, () => {
        assert.strictEqual(
          expected,
          TokenSets._areOrganizationsCompatible(
            { organization: requested },
            { organization: available }
          )
        );
      });
    });
  });

  describe('_isExpired', () => {
    it('returns true when token is expired', () => {
      const expiredToken = { expires_at: Math.floor(Date.now() / 1000) - 100 };
      assert.isTrue(TokenSets._isExpired(expiredToken));
    });

    it('returns false when token is not expired', () => {
      const validToken = { expires_at: Math.floor(Date.now() / 1000) + 100 };
      assert.isFalse(TokenSets._isExpired(validToken));
    });

    it('returns true when expires_at is not present', () => {
      assert.isTrue(TokenSets._isExpired({}));
    });
  });

  describe('_invalidateTokenSetIfNeeded()', () => {
    const session = { access_token: 'AT1', refresh_token: 'RT1' };

    describe('access token changed', () => {
      it('deletes the cache', () => {
        const cachedTokenSet = { value: {} };
        sinon.stub(weakCache, 'weakRef').returns(cachedTokenSet);

        TokenSets._invalidateTokenSetIfNeeded(session, { access_token: 'AT2' });

        assert.isUndefined(cachedTokenSet.value);

        sinon.restore();
      });
    });

    describe('refresh token changed', () => {
      it('deletes the cache', () => {
        const cachedTokenSet = { value: {} };
        sinon.stub(weakCache, 'weakRef').returns(cachedTokenSet);

        TokenSets._invalidateTokenSetIfNeeded(session, {
          refresh_token: 'RT2',
        });

        assert.isUndefined(cachedTokenSet.value);

        sinon.restore();
      });
    });

    describe('nothing changed', () => {
      it('does not touch the cache', () => {
        const weakRefSpy = sinon.spy(weakCache, 'weakRef');

        TokenSets._invalidateTokenSetIfNeeded(session, {
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

      const newTokenSet = { access_token: 'foo2', refresh_token: 'qux' };

      TokenSets.setCurrent(req, newTokenSet);

      assert.equal(req[sessName].access_token, 'foo2'); // overwritten
      assert.equal(req[sessName].refresh_token, 'qux'); // new prop
      assert.equal(req[sessName].something_else, 'bar'); // untouched

      sinon.restore();
    });
  });

  describe('_findCompatibleActive()', () => {
    it('returns first compatible active tokenset', () => {
      sinon.stub(TokenSets, 'getAll').returns(tokenSets);

      const output = TokenSets._findCompatibleActive(
        newReq(),
        authorizationParams
      );

      assert.strictEqual(output, tokenSets[0]);

      sinon.restore();
    });
  });

  describe('_findCompatibleRefreshable()', () => {
    it('returns first compatible refreshable tokenset', () => {
      sinon.stub(TokenSets, 'getAll').returns(tokenSets);

      const output = TokenSets._findCompatibleRefreshable(
        newReq(),
        authorizationParams
      );

      assert.strictEqual(output, tokenSets[1]);

      sinon.restore();
    });
  });

  describe('_findCompatibleExpired()', () => {
    it('returns first compatible expired tokenset', () => {
      sinon.stub(TokenSets, 'getAll').returns(tokenSets);

      const output = TokenSets._findCompatibleExpired(
        newReq(),
        authorizationParams
      );

      assert.strictEqual(output, tokenSets[8]);

      sinon.restore();
    });
  });

  describe('findCompatible()', () => {
    const req = newReq();
    const config = { authorizationParams: { foo: 1 } };
    const routeAuthorizationParams = { bar: 2 };

    describe('compatible active tokenset found', () => {
      it('merges params and returns the result from _findCompatibleActive()', async () => {
        /** @type {import('..').TokenParameters | undefined} */
        const foundTokenSet = {};

        const findSpy = sinon
          .stub(TokenSets, '_findCompatibleActive')
          .returns(foundTokenSet);

        sinon.stub(TokenSets, '_findCompatibleRefreshable').throws();
        sinon.stub(TokenSets, '_findCompatibleExpired').throws();
        sinon.stub(TokenSets, '_findMrrtable').throws();

        sinon.stub(weakCache, 'weakRef').returns({ config });

        const result = await TokenSets.findCompatible(
          req,
          routeAuthorizationParams
        );

        assert.isTrue(findSpy.calledWith(req, { foo: 1, bar: 2 }));
        assert.strictEqual(result, foundTokenSet);

        sinon.restore();
      });
    });

    describe('compatible refreshable tokenset found', () => {
      it('merges params and returns the result from _findCompatibleRefreshable()', async () => {
        /** @type {(import('..').TokenParameters & { refresh_token: string }) | undefined} */
        const foundTokenSet = { refresh_token: 'rt_123xyz' };

        const findSpy = sinon
          .stub(TokenSets, '_findCompatibleRefreshable')
          .returns(foundTokenSet);

        sinon.stub(TokenSets, '_findCompatibleActive').returns(undefined);
        sinon.stub(TokenSets, '_findCompatibleExpired').throws();
        sinon.stub(TokenSets, '_findMrrtable').throws();

        sinon
          .stub(weakCache, 'weakRef')
          .returns({ config: { ...config, autoRefreshIfExpired: true } });

        const result = await TokenSets.findCompatible(
          req,
          routeAuthorizationParams
        );

        assert.isTrue(findSpy.calledWith(req, { foo: 1, bar: 2 }));
        assert.strictEqual(result, foundTokenSet);

        sinon.restore();
      });
    });

    describe('compatible expired tokenset found', () => {
      it('merges params and returns the result from _findCompatibleExpired()', async () => {
        /** @type {import('..').TokenParameters | undefined} */
        const foundTokenSet = {};

        const findSpy = sinon
          .stub(TokenSets, '_findCompatibleExpired')
          .returns(foundTokenSet);

        sinon.stub(TokenSets, '_findCompatibleActive').returns(undefined);
        sinon.stub(TokenSets, '_findCompatibleRefreshable').returns(undefined);
        sinon.stub(TokenSets, '_findMrrtable').throws();

        sinon
          .stub(weakCache, 'weakRef')
          .returns({ config: { ...config, autoRefreshIfExpired: true } });

        const result = await TokenSets.findCompatible(
          req,
          routeAuthorizationParams
        );

        assert.isTrue(findSpy.calledWith(req, { foo: 1, bar: 2 }));
        assert.strictEqual(result, foundTokenSet);

        sinon.restore();
      });
    });

    describe('compatible mrrt-able tokenset found', () => {
      it('merges params and returns the result from _findMrrtable()', async () => {
        /** @type {import('..').TokenParameters | undefined} */
        const foundTokenSet = {};

        const findSpy = sinon
          .stub(TokenSets, '_findMrrtable')
          .resolves(foundTokenSet);

        sinon.stub(TokenSets, '_findCompatibleActive').returns(undefined);
        sinon.stub(TokenSets, '_findCompatibleRefreshable').returns(undefined);
        sinon.stub(TokenSets, '_findCompatibleExpired').returns(undefined);

        const appendSpy = sinon.stub(TokenSets, 'append');

        sinon.stub(weakCache, 'weakRef').returns({ config });

        const result = await TokenSets.findCompatible(
          req,
          routeAuthorizationParams
        );

        assert.isTrue(findSpy.calledWith(req, { foo: 1, bar: 2 }));
        assert.isTrue(appendSpy.calledWith(foundTokenSet));
        assert.strictEqual(result, foundTokenSet);

        sinon.restore();
      });
    });
  });

  describe('maybeRefreshCurrent()', async () => {
    describe('autoRefreshIfExpired disabled', async () => {
      it('does not refresh the token', async () => {
        const context = {
          config: { autoRefreshIfExpired: false },
        };

        sinon.stub(weakCache, 'weakRef').returns(context);

        const reqProps = {
          oidc: { accessToken: { refresh: sinon.spy() } },
        };

        await TokenSets.maybeRefreshCurrent(newReq(reqProps));

        assert.isFalse(reqProps.oidc.accessToken.refresh.called);

        sinon.restore();
      });
    });

    describe('autoRefreshIfExpired enabled + token expired', async () => {
      it('refreshes the token', async () => {
        const context = {
          config: { autoRefreshIfExpired: true },
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

        await TokenSets.maybeRefreshCurrent(newReq(reqProps));

        assert.isTrue(reqProps.oidc.accessToken.refresh.called);

        sinon.restore();
      });
    });

    describe('autoRefreshIfExpired enabled + token active', async () => {
      it('does not refresh the token', async () => {
        const context = {
          config: { autoRefreshIfExpired: true },
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

        await TokenSets.maybeRefreshCurrent(newReq(reqProps));

        assert.isFalse(reqProps.oidc.accessToken.refresh.called);

        sinon.restore();
      });
    });
  });
});

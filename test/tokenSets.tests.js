// @ts-check

const { assert } = require('chai');
const sinon = require('sinon');
const weakCache = require('../lib/weakCache');
const { TokenHistory } = require('../lib/tokenHistory');
const { TokenSets } = require('../lib/tokenSets');
const { TokenSetUtils } = require('../lib/tokenSetUtils');

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
const TOKENSETS = [
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

describe('TokenSets', () => {
  describe('findCompatibleActive()', () => {
    it('returns first compatible active tokenset', () => {
      const output = TokenSets.findCompatibleActive(
        TOKENSETS,
        authorizationParams,
      );

      assert.strictEqual(output, TOKENSETS[0]);

      sinon.restore();
    });
  });

  describe('findCompatibleExpired()', () => {
    it('returns first compatible expired tokenset', () => {
      const output = TokenSets.findCompatibleExpired(
        TOKENSETS,
        authorizationParams,
      );

      assert.strictEqual(output, TOKENSETS[8]);
    });
  });

  describe('findCompatibleRefreshable()', () => {
    it('returns first compatible refreshable tokenset', () => {
      const output = TokenSets.findCompatibleRefreshable(
        TOKENSETS,
        authorizationParams,
      );

      assert.strictEqual(output, TOKENSETS[1]);
    });
  });

  describe('findMrrtable()', () => {
    it('returns first compatible "MRRT-able" tokenset', () => {
      const output = TokenSets.findMrrtable(TOKENSETS, authorizationParams);

      assert.strictEqual(output, TOKENSETS[1]);
    });
  });

  describe('getAvailableTokenSets()', () => {
    const sessionName = 'testSess';
    const tokenSet = { access_token: 'some_test_token' };
    const req = newReq({ [sessionName]: tokenSet });

    describe('history is enabled', () => {
      it('returns the token history', () => {
        const tokenHistory = [];

        sinon.stub(TokenHistory, 'getAll').returns(tokenHistory);

        sinon
          .stub(weakCache, 'weakRef')
          .returns({ config: { tokenHistory: true } });

        assert.strictEqual(TokenSets.getAvailableTokenSets(req), tokenHistory);

        sinon.restore();
      });
    });

    describe('otherwise', () => {
      it('returns the current tokenset', () => {
        sinon.stub(weakCache, 'weakRef').returns({
          config: {
            tokenHistory: false,
            session: { name: sessionName },
          },
        });

        assert.deepEqual(TokenSets.getAvailableTokenSets(req), [tokenSet]);

        sinon.restore();
      });
    });
  });

  describe('findCompatible()', () => {
    const req = newReq();
    const config = { authorizationParams: { foo: 1 }, useMrrt: true };
    const routeAuthorizationParams = { bar: 2 };

    describe('compatible active tokenset found', () => {
      it('merges params and returns the result from findCompatibleActive()', async () => {
        /** @type {import('..').TokenParameters | undefined} */
        const foundTokenSet = {};

        const findSpy = sinon
          .stub(TokenSets, 'findCompatibleActive')
          .returns(foundTokenSet);

        sinon.stub(TokenSets, 'getAvailableTokenSets').returns(TOKENSETS);
        sinon.stub(TokenSets, 'findCompatibleRefreshable').throws();
        sinon.stub(TokenSets, 'findCompatibleExpired').throws();
        sinon.stub(TokenSets, 'findMrrtable').throws();

        sinon.stub(weakCache, 'weakRef').returns({ config });

        const result = await TokenSets.findCompatible(
          req,
          routeAuthorizationParams,
        );

        assert.isTrue(findSpy.calledWith(TOKENSETS, { foo: 1, bar: 2 }));
        assert.strictEqual(result, foundTokenSet);

        sinon.restore();
      });
    });

    describe('compatible refreshable tokenset found', () => {
      it('merges params and returns the result from findCompatibleRefreshable()', async () => {
        /** @type {(import('..').TokenParameters & { refresh_token: string }) | undefined} */
        const foundTokenSet = { refresh_token: 'rt_123xyz' };

        const findSpy = sinon
          .stub(TokenSets, 'findCompatibleRefreshable')
          .returns(foundTokenSet);

        sinon.stub(TokenSets, 'getAvailableTokenSets').returns(TOKENSETS);
        sinon.stub(TokenSets, 'findCompatibleActive').returns(undefined);
        sinon.stub(TokenSets, 'findCompatibleExpired').throws();
        sinon.stub(TokenSets, 'findMrrtable').throws();

        sinon.stub(weakCache, 'weakRef').returns({ config });

        const result = await TokenSets.findCompatible(
          req,
          routeAuthorizationParams,
        );

        assert.isTrue(findSpy.calledWith(TOKENSETS, { foo: 1, bar: 2 }));
        assert.strictEqual(result, foundTokenSet);

        sinon.restore();
      });
    });

    describe('compatible expired tokenset found', () => {
      it('merges params and returns the result from findCompatibleExpired()', async () => {
        /** @type {import('..').TokenParameters | undefined} */
        const foundTokenSet = {};

        const findSpy = sinon
          .stub(TokenSets, 'findCompatibleExpired')
          .returns(foundTokenSet);

        sinon.stub(TokenSets, 'getAvailableTokenSets').returns(TOKENSETS);
        sinon.stub(TokenSets, 'findCompatibleActive').returns(undefined);
        sinon.stub(TokenSets, 'findCompatibleRefreshable').returns(undefined);
        sinon.stub(TokenSets, 'findMrrtable').throws();

        sinon.stub(weakCache, 'weakRef').returns({ config });

        const result = await TokenSets.findCompatible(
          req,
          routeAuthorizationParams,
        );

        assert.isTrue(findSpy.calledWith(TOKENSETS, { foo: 1, bar: 2 }));
        assert.strictEqual(result, foundTokenSet);

        sinon.restore();
      });
    });

    describe('compatible mrrt-able tokenset found', () => {
      it('merges params and returns the result from findMrrtable()', async () => {
        /** @type {import('..').TokenParameters | undefined} */
        const foundTokenSet = { access_token: 'test_token' };

        /** @type {import('..').TokenParameters | undefined} */
        const refreshedTokenSet = { access_token: 'refreshed_token' };

        const findSpy = sinon
          .stub(TokenSets, 'findMrrtable')
          .resolves(foundTokenSet);

        sinon.stub(TokenSets, 'getAvailableTokenSets').returns(TOKENSETS);
        sinon.stub(TokenSets, 'findCompatibleActive').returns(undefined);
        sinon.stub(TokenSets, 'findCompatibleRefreshable').returns(undefined);
        sinon.stub(TokenSets, 'findCompatibleExpired').returns(undefined);
        sinon.stub(TokenSetUtils, 'doMrrtRefresh').resolves(refreshedTokenSet);

        const appendSpy = sinon.stub(TokenHistory, 'append');

        sinon.stub(weakCache, 'weakRef').returns({ config });

        const result = await TokenSets.findCompatible(
          req,
          routeAuthorizationParams,
        );

        assert.isTrue(findSpy.calledWith(TOKENSETS, { foo: 1, bar: 2 }));
        assert.isTrue(appendSpy.calledWith(req, refreshedTokenSet));
        assert.strictEqual(result, refreshedTokenSet);

        sinon.restore();
      });
    });
  });
});

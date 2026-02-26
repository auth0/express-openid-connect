const { assert } = require('chai');
const sinon = require('sinon');
const nock = require('nock');
const {
  getIssuerManager,
  resetIssuerManager,
} = require('../lib/issuerManager');

describe('MCD Requirement 2: IssuerManager', () => {
  let manager;

  beforeEach(() => {
    resetIssuerManager();
    manager = getIssuerManager();
  });

  afterEach(() => {
    nock.cleanAll();
    resetIssuerManager();
  });

  describe('Singleton pattern', () => {
    it('should return the same instance', () => {
      const manager1 = getIssuerManager();
      const manager2 = getIssuerManager();
      assert.strictEqual(manager1, manager2);
    });

    it('should create new instance after reset', () => {
      const manager1 = getIssuerManager();
      resetIssuerManager();
      const manager2 = getIssuerManager();
      assert.notStrictEqual(manager1, manager2);
    });
  });

  describe('resolveIssuer() - static issuer (string)', () => {
    it('should return static issuer URL', async () => {
      const config = { issuerBaseURL: 'https://tenant.auth0.com' };
      const context = {
        req: {},
      };

      const issuerUrl = await manager.resolveIssuer(config, context);
      assert.equal(issuerUrl, 'https://tenant.auth0.com');
    });

    it('should validate HTTPS protocol', async () => {
      const config = { issuerBaseURL: 'http://tenant.auth0.com' };
      const context = {
        req: {},
      };

      try {
        await manager.resolveIssuer(config, context);
        assert.fail('Should have thrown error');
      } catch (err) {
        assert.include(err.message, 'must use HTTPS protocol');
      }
    });

    it('should allow localhost with HTTP', async () => {
      const config = { issuerBaseURL: 'http://localhost:3000' };
      const context = {
        req: {},
      };

      const issuerUrl = await manager.resolveIssuer(config, context);
      assert.equal(issuerUrl, 'http://localhost:3000');
    });
  });

  describe('resolveIssuer() - dynamic issuer (function)', () => {
    it('should call resolver function and return result', async () => {
      const resolverFn = sinon.stub().resolves('https://tenant-a.auth0.com');
      const config = { issuerBaseURL: resolverFn };
      const context = {
        req: { headers: { host: 'tenant-a.example.com' } },
      };

      const issuerUrl = await manager.resolveIssuer(config, context);

      assert.equal(issuerUrl, 'https://tenant-a.auth0.com');
      assert.ok(resolverFn.calledOnce);
      assert.ok(resolverFn.calledWith(context));
    });

    it('should handle sync resolver functions', async () => {
      const config = {
        issuerBaseURL: () => 'https://tenant.auth0.com',
      };
      const context = {
        req: {},
      };

      const issuerUrl = await manager.resolveIssuer(config, context);
      assert.equal(issuerUrl, 'https://tenant.auth0.com');
    });

    it('should reject null return value', async () => {
      const config = { issuerBaseURL: async () => null };
      const context = {
        req: {},
      };

      try {
        await manager.resolveIssuer(config, context);
        assert.fail('Should have thrown error');
      } catch (err) {
        assert.include(err.message, 'returned null or undefined');
      }
    });

    it('should reject undefined return value', async () => {
      const config = { issuerBaseURL: async () => undefined };
      const context = {
        req: {},
      };

      try {
        await manager.resolveIssuer(config, context);
        assert.fail('Should have thrown error');
      } catch (err) {
        assert.include(err.message, 'returned null or undefined');
      }
    });

    it('should reject non-string return value', async () => {
      const config = { issuerBaseURL: async () => 12345 };
      const context = {
        req: {},
      };

      try {
        await manager.resolveIssuer(config, context);
        assert.fail('Should have thrown error');
      } catch (err) {
        assert.include(err.message, 'must return a single string URL');
        assert.include(err.message, 'got number');
      }
    });

    it('should reject empty string return value', async () => {
      const config = { issuerBaseURL: async () => '   ' };
      const context = {
        req: {},
      };

      try {
        await manager.resolveIssuer(config, context);
        assert.fail('Should have thrown error');
      } catch (err) {
        assert.include(err.message, 'returned an empty string');
      }
    });

    it('should reject invalid URL return value', async () => {
      const config = { issuerBaseURL: async () => 'not-a-valid-url' };
      const context = {
        req: {},
      };

      try {
        await manager.resolveIssuer(config, context);
        assert.fail('Should have thrown error');
      } catch (err) {
        assert.include(err.message, 'returned invalid URL');
      }
    });

    it('should handle resolver errors', async () => {
      const config = {
        issuerBaseURL: async () => {
          throw new Error('Database connection failed');
        },
      };
      const context = {
        req: {},
      };

      try {
        await manager.resolveIssuer(config, context);
        assert.fail('Should have thrown error');
      } catch (err) {
        assert.include(err.message, 'Failed to resolve issuer');
        assert.include(err.message, 'Database connection failed');
      }
    });

    it('should reject HTTP URLs from resolver', async () => {
      const config = {
        issuerBaseURL: async () => 'http://tenant.auth0.com',
      };
      const context = {
        req: {},
      };

      try {
        await manager.resolveIssuer(config, context);
        assert.fail('Should have thrown error');
      } catch (err) {
        assert.include(err.message, 'must use HTTPS protocol');
      }
    });
  });

  describe('clearCache()', () => {
    it('should clear specific issuer from cache', () => {
      manager.cache.set('https://tenant-a.auth0.com', { mock: 'data-a' });
      manager.cache.set('https://tenant-b.auth0.com', { mock: 'data-b' });

      manager.clearCache('https://tenant-a.auth0.com');

      assert.isFalse(manager.cache.has('https://tenant-a.auth0.com'));
      assert.isTrue(manager.cache.has('https://tenant-b.auth0.com'));
    });

    it('should clear all issuers when no parameter provided', () => {
      manager.cache.set('https://tenant-a.auth0.com', { mock: 'data-a' });
      manager.cache.set('https://tenant-b.auth0.com', { mock: 'data-b' });

      manager.clearCache();

      assert.equal(manager.cache.size, 0);
    });
  });

  describe('Cache behavior', () => {
    it('should cache client and issuer', () => {
      const mockData = {
        client: { mock: 'client' },
        issuer: { mock: 'issuer' },
        timestamp: Date.now(),
      };

      manager.cache.set('https://tenant.auth0.com', mockData);

      assert.isTrue(manager.cache.has('https://tenant.auth0.com'));
      assert.deepEqual(manager.cache.get('https://tenant.auth0.com'), mockData);
    });

    it('should maintain separate cache entries per issuer', () => {
      const dataA = {
        client: { tenant: 'a' },
        issuer: { issuer: 'https://tenant-a.auth0.com' },
        timestamp: Date.now(),
      };
      const dataB = {
        client: { tenant: 'b' },
        issuer: { issuer: 'https://tenant-b.auth0.com' },
        timestamp: Date.now(),
      };

      manager.cache.set('https://tenant-a.auth0.com', dataA);
      manager.cache.set('https://tenant-b.auth0.com', dataB);

      assert.equal(manager.cache.size, 2);
      assert.deepEqual(manager.cache.get('https://tenant-a.auth0.com'), dataA);
      assert.deepEqual(manager.cache.get('https://tenant-b.auth0.com'), dataB);
    });
  });

  describe('getClient() - Multi-Issuer Metadata Caching', () => {
    const wellKnown = require('./fixture/well-known.json');
    const certs = require('./fixture/cert');

    const defaultConfig = {
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      idTokenSigningAlg: 'RS256',
      clientAuthMethod: 'client_secret_basic',
      clockTolerance: 60,
      httpTimeout: 5000,
      enableTelemetry: false,
      discoveryCacheMaxAge: 300000, // 5 minutes
      idpLogout: false,
      authorizationParams: {
        response_type: 'id_token',
        scope: 'openid profile email',
      },
    };

    beforeEach(() => {
      // Setup nock mocks for issuer discovery
      ['tenant-a', 'tenant-b', 'tenant-c'].forEach((tenant) => {
        nock(`https://${tenant}.auth0.com`)
          .persist()
          .get('/.well-known/openid-configuration')
          .reply(200, {
            ...wellKnown,
            issuer: `https://${tenant}.auth0.com`,
            authorization_endpoint: `https://${tenant}.auth0.com/authorize`,
            token_endpoint: `https://${tenant}.auth0.com/oauth/token`,
            userinfo_endpoint: `https://${tenant}.auth0.com/userinfo`,
          });

        nock(`https://${tenant}.auth0.com`)
          .persist()
          .get('/.well-known/jwks.json')
          .reply(200, certs.jwks);
      });
    });

    it('should discover and cache issuer metadata', async () => {
      const result = await manager.getClient(
        'https://tenant-a.auth0.com',
        defaultConfig,
      );

      assert.ok(result.client);
      assert.ok(result.issuer);
      assert.equal(result.issuer.issuer, 'https://tenant-a.auth0.com');

      // Verify it's cached
      assert.isTrue(manager.cache.has('https://tenant-a.auth0.com'));
    });

    it('should return cached client on subsequent calls', async () => {
      // First call - should discover
      const result1 = await manager.getClient(
        'https://tenant-a.auth0.com',
        defaultConfig,
      );

      // Second call - should use cache
      const result2 = await manager.getClient(
        'https://tenant-a.auth0.com',
        defaultConfig,
      );

      // Should be the same cached objects
      assert.strictEqual(result1.client, result2.client);
      assert.strictEqual(result1.issuer, result2.issuer);
    });

    it('should cache different issuers separately', async () => {
      const resultA = await manager.getClient(
        'https://tenant-a.auth0.com',
        defaultConfig,
      );
      const resultB = await manager.getClient(
        'https://tenant-b.auth0.com',
        defaultConfig,
      );

      // Should be different issuers
      assert.notEqual(resultA.issuer.issuer, resultB.issuer.issuer);
      assert.equal(resultA.issuer.issuer, 'https://tenant-a.auth0.com');
      assert.equal(resultB.issuer.issuer, 'https://tenant-b.auth0.com');

      // Both should be cached
      assert.equal(manager.cache.size, 2);
    });

    it('should not cross-contaminate cache between issuers', async () => {
      // Get client for tenant-a
      await manager.getClient('https://tenant-a.auth0.com', defaultConfig);

      // Get client for tenant-b
      await manager.getClient('https://tenant-b.auth0.com', defaultConfig);

      // Get client for tenant-a again - should get correct cached version
      const resultA = await manager.getClient(
        'https://tenant-a.auth0.com',
        defaultConfig,
      );

      assert.equal(resultA.issuer.issuer, 'https://tenant-a.auth0.com');
    });

    it('should respect discoveryCacheMaxAge', async () => {
      // Use a very short cache age for testing
      const shortCacheConfig = {
        ...defaultConfig,
        discoveryCacheMaxAge: 100, // 100ms
      };

      // First call
      await manager.getClient('https://tenant-a.auth0.com', shortCacheConfig);
      assert.isTrue(manager.cache.has('https://tenant-a.auth0.com'));

      // Wait for cache to expire
      await new Promise((resolve) => setTimeout(resolve, 150));

      // The cache entry should still exist but be expired
      // getClient should re-discover (we can't easily verify re-discovery without
      // more complex nock setup, but we can verify the call doesn't fail)
      const result = await manager.getClient(
        'https://tenant-a.auth0.com',
        shortCacheConfig,
      );
      assert.ok(result.client);
      assert.ok(result.issuer);
    });

    it('should handle discovery errors gracefully', async () => {
      nock('https://failing.auth0.com')
        .get('/.well-known/openid-configuration')
        .reply(500, 'Internal Server Error');

      try {
        await manager.getClient('https://failing.auth0.com', defaultConfig);
        assert.fail('Should have thrown error');
      } catch (err) {
        // Error from openid-client discovery
        assert.ok(err.message);
      }
    });

    it('should clear cache and re-discover after clearCache()', async () => {
      // First call - discover and cache
      await manager.getClient('https://tenant-a.auth0.com', defaultConfig);
      assert.isTrue(manager.cache.has('https://tenant-a.auth0.com'));

      // Clear cache
      manager.clearCache('https://tenant-a.auth0.com');
      assert.isFalse(manager.cache.has('https://tenant-a.auth0.com'));

      // Next call should re-discover
      const result = await manager.getClient(
        'https://tenant-a.auth0.com',
        defaultConfig,
      );
      assert.ok(result.client);
      assert.isTrue(manager.cache.has('https://tenant-a.auth0.com'));
    });
  });

  describe('LRU cache eviction', () => {
    const wellKnown = require('./fixture/well-known.json');
    const certs = require('./fixture/cert');

    const makeIssuerUrl = (n) => `https://lru-tenant-${n}.auth0.com`;

    const setupNock = (n) => {
      const issuerUrl = makeIssuerUrl(n);
      nock(issuerUrl)
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, {
          ...wellKnown,
          issuer: issuerUrl,
          authorization_endpoint: `${issuerUrl}/authorize`,
          token_endpoint: `${issuerUrl}/oauth/token`,
          userinfo_endpoint: `${issuerUrl}/userinfo`,
        });

      nock(issuerUrl)
        .persist()
        .get('/.well-known/jwks.json')
        .reply(200, certs.jwks);
    };

    const smallCacheConfig = {
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      idTokenSigningAlg: 'RS256',
      clientAuthMethod: 'client_secret_basic',
      clockTolerance: 60,
      httpTimeout: 5000,
      enableTelemetry: false,
      discoveryCacheMaxAge: 300000,
      idpLogout: false,
      authorizationParams: {
        response_type: 'id_token',
        scope: 'openid profile email',
      },
      maxCachedIssuers: 3, // Small cache for testing
    };

    it('should evict oldest issuer when cache exceeds maxCachedIssuers', async () => {
      // Setup nocks for 4 issuers
      for (let i = 1; i <= 4; i++) {
        setupNock(i);
      }

      // Add 3 issuers (at capacity)
      await manager.getClient(makeIssuerUrl(1), smallCacheConfig);
      await manager.getClient(makeIssuerUrl(2), smallCacheConfig);
      await manager.getClient(makeIssuerUrl(3), smallCacheConfig);

      assert.equal(manager.cache.size, 3);
      assert.isTrue(manager.cache.has(makeIssuerUrl(1)));
      assert.isTrue(manager.cache.has(makeIssuerUrl(2)));
      assert.isTrue(manager.cache.has(makeIssuerUrl(3)));

      // Add 4th issuer - should evict issuer 1 (oldest)
      await manager.getClient(makeIssuerUrl(4), smallCacheConfig);

      assert.equal(manager.cache.size, 3);
      assert.isFalse(manager.cache.has(makeIssuerUrl(1))); // Evicted
      assert.isTrue(manager.cache.has(makeIssuerUrl(2)));
      assert.isTrue(manager.cache.has(makeIssuerUrl(3)));
      assert.isTrue(manager.cache.has(makeIssuerUrl(4)));
    });

    it('should update LRU order when accessing cached issuer', async () => {
      // Setup nocks for 4 issuers
      for (let i = 1; i <= 4; i++) {
        setupNock(i);
      }

      // Add 3 issuers
      await manager.getClient(makeIssuerUrl(1), smallCacheConfig);
      await manager.getClient(makeIssuerUrl(2), smallCacheConfig);
      await manager.getClient(makeIssuerUrl(3), smallCacheConfig);

      // Access issuer 1 - moves it to the end (most recently used)
      await manager.getClient(makeIssuerUrl(1), smallCacheConfig);

      // Add 4th issuer - should evict issuer 2 (now the oldest)
      await manager.getClient(makeIssuerUrl(4), smallCacheConfig);

      assert.equal(manager.cache.size, 3);
      assert.isTrue(manager.cache.has(makeIssuerUrl(1))); // Still present (was accessed)
      assert.isFalse(manager.cache.has(makeIssuerUrl(2))); // Evicted (was oldest)
      assert.isTrue(manager.cache.has(makeIssuerUrl(3)));
      assert.isTrue(manager.cache.has(makeIssuerUrl(4)));
    });

    it('should use default maxCachedIssuers of 100 if not specified', async () => {
      setupNock(1);

      const configWithoutMax = {
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        idTokenSigningAlg: 'RS256',
        clientAuthMethod: 'client_secret_basic',
        clockTolerance: 60,
        httpTimeout: 5000,
        enableTelemetry: false,
        discoveryCacheMaxAge: 300000,
        idpLogout: false,
        authorizationParams: {
          response_type: 'id_token',
          scope: 'openid profile email',
        },
        // No maxCachedIssuers specified - should default to 100
      };

      await manager.getClient(makeIssuerUrl(1), configWithoutMax);
      assert.equal(manager.cache.size, 1);
      // Default is 100, so no eviction with just 1 issuer
    });
  });
});

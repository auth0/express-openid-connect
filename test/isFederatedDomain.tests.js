const nock = require('nock');
const sinon = require('sinon');
const { assert } = require('chai');
const { isFederatedDomain } = require('..');

const WEBFINGER_REL = 'http://openid.net/specs/connect/1.0/issuer';

const managedBody = (domain) => ({
  subject: `urn:auth0:discovery:domain:${domain}`,
  links: [{ rel: WEBFINGER_REL, href: 'https://example-tenant.auth0.com/' }],
});

describe('isFederatedDomain', () => {
  it('should return true and request the urn:auth0:discovery:domain resource', async () => {
    const scope = nock('https://example-tenant.auth0.com')
      .get('/.well-known/webfinger')
      .query({
        resource: 'urn:auth0:discovery:domain:acmecorp.com',
        rel: WEBFINGER_REL,
      })
      .reply(200, managedBody('acmecorp.com'));

    const result = await isFederatedDomain(
      'example-tenant.auth0.com',
      'acmecorp.com',
    );
    assert.isTrue(result);
    assert.ok(scope.isDone());
  });

  it('should return false for a 404 (domain not managed)', async () => {
    nock('https://example-tenant.auth0.com')
      .get('/.well-known/webfinger')
      .query(true)
      .reply(404);

    const result = await isFederatedDomain(
      'example-tenant.auth0.com',
      'notexist.com',
    );
    assert.isFalse(result);
  });

  it('should return false for a 200 with no matching rel (ambiguous)', async () => {
    nock('https://example-tenant.auth0.com')
      .get('/.well-known/webfinger')
      .query(true)
      .reply(200, {
        subject: 'urn:auth0:discovery:domain:ambiguous.com',
        links: [],
      });

    const result = await isFederatedDomain(
      'example-tenant.auth0.com',
      'ambiguous.com',
    );
    assert.isFalse(result);
  });

  it('should return false for a 403 (WebFinger disabled on the tenant)', async () => {
    nock('https://example-tenant.auth0.com')
      .get('/.well-known/webfinger')
      .query(true)
      .reply(403);

    const result = await isFederatedDomain(
      'example-tenant.auth0.com',
      'forbidden.com',
    );
    assert.isFalse(result);
  });

  it('should return false and warn on a 429 (rate limited)', async () => {
    nock('https://example-tenant.auth0.com')
      .get('/.well-known/webfinger')
      .query(true)
      .reply(429);

    const result = await isFederatedDomain(
      'example-tenant.auth0.com',
      'ratelimited.com',
    );
    assert.isFalse(result);
    assert.ok(
      console.warn
        .getCalls()
        .some((call) => /429|rate limit/i.test(call.args[0])),
    );
  });

  it('should return false for a 5xx', async () => {
    nock('https://example-tenant.auth0.com')
      .get('/.well-known/webfinger')
      .query(true)
      .reply(500);

    const result = await isFederatedDomain(
      'example-tenant.auth0.com',
      'servererror.com',
    );
    assert.isFalse(result);
  });

  it('should return false on a network error', async () => {
    nock('https://example-tenant.auth0.com')
      .get('/.well-known/webfinger')
      .query(true)
      .replyWithError('connection reset');

    const result = await isFederatedDomain(
      'example-tenant.auth0.com',
      'networkerror.com',
    );
    assert.isFalse(result);
  });

  it('should normalize the email domain to lowercase (case-insensitive)', async () => {
    const scope = nock('https://example-tenant.auth0.com')
      .get('/.well-known/webfinger')
      .query({
        resource: 'urn:auth0:discovery:domain:zillo.com',
        rel: WEBFINGER_REL,
      })
      .reply(200, managedBody('zillo.com'));

    const result = await isFederatedDomain(
      'example-tenant.auth0.com',
      'ZILLO.COM',
    );
    assert.isTrue(result);
    assert.ok(scope.isDone());
  });

  it('should send the standard telemetry headers', async () => {
    let sentHeaders;
    nock('https://example-tenant.auth0.com')
      .get('/.well-known/webfinger')
      .query(true)
      .reply(200, function () {
        sentHeaders = this.req.headers;
        return [200, managedBody('telemetry.com')];
      });

    await isFederatedDomain('example-tenant.auth0.com', 'telemetry.com');
    assert.ok(sentHeaders['user-agent']);
    assert.ok(sentHeaders['auth0-client']);
  });

  describe('caching', () => {
    let clock;

    afterEach(() => {
      if (clock) {
        clock.restore();
        clock = undefined;
      }
    });

    it('should cache a true result for 60s and not re-request within that window', async () => {
      const scope = nock('https://example-tenant.auth0.com')
        .get('/.well-known/webfinger')
        .query(true)
        .once()
        .reply(200, managedBody('cached-true.com'));

      const first = await isFederatedDomain(
        'example-tenant.auth0.com',
        'cached-true.com',
      );
      const second = await isFederatedDomain(
        'example-tenant.auth0.com',
        'cached-true.com',
      );
      assert.isTrue(first);
      assert.isTrue(second);
      assert.ok(scope.isDone());
    });

    it('should re-request after the 60s TTL on a true result expires', async () => {
      clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] });
      const scope = nock('https://example-tenant.auth0.com')
        .get('/.well-known/webfinger')
        .query(true)
        .twice()
        .reply(200, managedBody('expiring-true.com'));

      await isFederatedDomain('example-tenant.auth0.com', 'expiring-true.com');
      clock.tick(60001);
      await isFederatedDomain('example-tenant.auth0.com', 'expiring-true.com');
      assert.ok(scope.isDone());
    });

    it('should cache a 404-false result for 15s and not re-request within that window', async () => {
      const scope = nock('https://example-tenant.auth0.com')
        .get('/.well-known/webfinger')
        .query(true)
        .once()
        .reply(404);

      const first = await isFederatedDomain(
        'example-tenant.auth0.com',
        'cached-false.com',
      );
      const second = await isFederatedDomain(
        'example-tenant.auth0.com',
        'cached-false.com',
      );
      assert.isFalse(first);
      assert.isFalse(second);
      assert.ok(scope.isDone());
    });

    it('should re-request after the 15s TTL on a 404-false result expires', async () => {
      clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] });
      const scope = nock('https://example-tenant.auth0.com')
        .get('/.well-known/webfinger')
        .query(true)
        .twice()
        .reply(404);

      await isFederatedDomain('example-tenant.auth0.com', 'expiring-false.com');
      clock.tick(15001);
      await isFederatedDomain('example-tenant.auth0.com', 'expiring-false.com');
      assert.ok(scope.isDone());
    });

    it('should never cache an ambiguous 200 (no matching rel)', async () => {
      const scope = nock('https://example-tenant.auth0.com')
        .get('/.well-known/webfinger')
        .query(true)
        .twice()
        .reply(200, { links: [] });

      await isFederatedDomain('example-tenant.auth0.com', 'never-cached.com');
      await isFederatedDomain('example-tenant.auth0.com', 'never-cached.com');
      assert.ok(scope.isDone());
    });

    it('should never cache a 429', async () => {
      const scope = nock('https://example-tenant.auth0.com')
        .get('/.well-known/webfinger')
        .query(true)
        .twice()
        .reply(429);

      await isFederatedDomain(
        'example-tenant.auth0.com',
        'never-cached-429.com',
      );
      await isFederatedDomain(
        'example-tenant.auth0.com',
        'never-cached-429.com',
      );
      assert.ok(scope.isDone());
    });

    it('should evict the oldest entry (FIFO) once the cache exceeds 1000 entries', async function () {
      this.timeout(20000);

      let requestCount = 0;
      nock('https://eviction-test.auth0.com')
        .persist()
        .get('/.well-known/webfinger')
        .query(true)
        .reply(200, () => {
          requestCount += 1;
          return [200, managedBody('eviction-fill.com')];
        });

      const firstDomain = 'eviction-domain-0.com';
      await isFederatedDomain('eviction-test.auth0.com', firstDomain);
      assert.equal(requestCount, 1);

      // Fill the cache with 1000 more distinct entries, pushing the FIFO
      // cap (1000) past the first-inserted entry.
      for (let i = 1; i <= 1000; i++) {
        await isFederatedDomain(
          'eviction-test.auth0.com',
          `eviction-domain-${i}.com`,
        );
      }

      // The first entry should have been evicted; querying it again must
      // hit the network rather than serve from cache.
      const requestCountBeforeRecheck = requestCount;
      await isFederatedDomain('eviction-test.auth0.com', firstDomain);
      assert.equal(requestCount, requestCountBeforeRecheck + 1);
    });
  });
});

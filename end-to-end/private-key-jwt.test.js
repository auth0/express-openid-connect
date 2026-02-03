import { assert } from 'chai';
import { once } from 'events';
import puppeteer from 'puppeteer';
import provider from './fixture/oidc-provider.js';
import {
  baseUrl,
  start,
  runExample,
  stubEnv,
  goto,
  login,
  shouldSkipPuppeteerTest,
  waitForPort,
} from './fixture/helpers.js';

describe('private key jwt', async () => {
  let authServer;
  let appServer;

  beforeEach(async () => {
    stubEnv();
    const resolvedProvider = await provider;
    authServer = await start(resolvedProvider, 3001);
    appServer = await runExample('private-key-jwt');
    // Wait for both servers to be ready before running tests
    await Promise.all([waitForPort(3000), waitForPort(3001)]);
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
  });

  it('should login with private key jwt client auth method', async () => {
    if (shouldSkipPuppeteerTest()) {
      return;
    }

    const browser = await puppeteer.launch({
      args: puppeteer
        .defaultArgs()
        .concat(['--no-sandbox', '--disable-setuid-sandbox']),
    });
    const page = await browser.newPage();
    await goto(baseUrl, page);
    assert.match(page.url(), /http:\/\/(localhost|127\.0\.0\.1):3000/);
    await page.click('a[href="/login"]');
    assert.match(
      page.url(),
      /http:\/\/(localhost|127\.0\.0\.1):3001\/interaction/,
      'User should have been redirected to the auth server to login',
    );
    const resolvedProvider = await provider;
    const promise = once(resolvedProvider, 'grant.success');

    await login('username', 'password', page);
    const [ctx] = await promise;
    assert(
      ctx.oidc.body.client_assertion,
      'Client should have authenticated with a client assertion payload',
    );
    assert.equal(
      ctx.oidc.body.client_assertion_type,
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
    assert.equal(
      page.url(),
      `${baseUrl}/`,
      'User is returned to the original page',
    );
    assert.include(await page.content(), 'hello username');
  });
});

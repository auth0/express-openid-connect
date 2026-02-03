import { assert } from 'chai';
import provider from './fixture/oidc-provider.js';
import {
  baseUrl,
  start,
  runExample,
  stubEnv,
  goto,
  login,
  shouldSkipPuppeteerTest,
  launchBrowser,
} from './fixture/helpers.js';

describe('fetch userinfo', async () => {
  let authServer;
  let appServer;

  beforeEach(async () => {
    stubEnv();
    const resolvedProvider = await provider;
    authServer = await start(resolvedProvider, 3001);
    appServer = await runExample('userinfo');
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
  });

  it('should login with hybrid flow and fetch userinfo', async () => {
    if (shouldSkipPuppeteerTest()) {
      return;
    }

    const browser = await launchBrowser();
    const page = await browser.newPage();
    await goto(baseUrl, page);
    assert.match(
      page.url(),
      /http:\/\/localhost:3001\/interaction/,
      'User should have been redirected to the auth server to login',
    );
    await login('username', 'password', page);
    assert.equal(
      page.url(),
      `${baseUrl}/`,
      'User is returned to the original page',
    );

    assert.include(await page.content(), 'hello username');
  });
});

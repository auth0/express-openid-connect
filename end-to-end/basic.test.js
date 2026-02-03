import { assert } from 'chai';
import provider from './fixture/oidc-provider.js';
import {
  baseUrl,
  start,
  runExample,
  stubEnv,
  checkContext,
  goto,
  login,
  logout,
  shouldSkipPuppeteerTest,
  launchBrowser,
} from './fixture/helpers.js';

describe('basic login and logout', async () => {
  let authServer;
  let appServer;

  beforeEach(async () => {
    stubEnv();
    const resolvedProvider = await provider;
    authServer = await start(resolvedProvider, 3001);
    appServer = await runExample('basic');
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
  });

  it('should login and logout with default configuration', async () => {
    // Check if we should skip this test due to known environment issues
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
    const loggedInCookies = await page.cookies(baseUrl);
    assert.ok(loggedInCookies.find(({ name }) => name === 'appSession'));

    const response = await checkContext(await page.cookies());
    assert.isOk(response.isAuthenticated);
    assert.equal(response.user.sub, 'username');
    assert.empty(
      response.accessToken,
      "default response_type doesn't include code",
    );
    await logout(page);

    const loggedOutCookies = await page.cookies(baseUrl);
    assert.notOk(loggedOutCookies.find(({ name }) => name === 'appSession'));
  });
});

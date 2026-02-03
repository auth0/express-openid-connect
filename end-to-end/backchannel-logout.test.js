import { assert } from 'chai';
import request from 'request-promise-native';
import provider from './fixture/oidc-provider.js';
import {
  baseUrl,
  start,
  runExample,
  stubEnv,
  checkContext,
  goto,
  login,
  shouldSkipPuppeteerTest,
  launchBrowser,
} from './fixture/helpers.js';

describe('back-channel logout', async () => {
  let authServer;
  let appServer;
  let browser;

  beforeEach(async () => {
    stubEnv();
    const resolvedProvider = await provider;
    authServer = await start(resolvedProvider, 3001);
  });

  afterEach(async () => {
    authServer.close();
    if (appServer) {
      appServer.close();
    }
    if (browser) {
      await browser.close();
    }
  });

  const runTest = async (example) => {
    if (shouldSkipPuppeteerTest()) {
      return;
    }

    appServer = await runExample(example);
    browser = await launchBrowser();
    const page = await browser.newPage();
    await goto(baseUrl, page);
    assert.match(page.url(), /http:\/\/localhost:300/);
    await Promise.all([page.click('a'), page.waitForNavigation()]);
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

    await goto(`${baseUrl}/logout-token`, page);

    await page.waitForSelector('pre');
    const element = await page.$('pre');
    const curl = await page.evaluate((el) => el.textContent, element);
    const [, logoutToken] = curl.match(/logout_token=([^"]+)/);
    const res = await request.post(`${baseUrl}/backchannel-logout`, {
      form: {
        logout_token: logoutToken,
      },
      resolveWithFullResponse: true,
    });
    assert.equal(res.statusCode, 204);

    await goto(baseUrl, page);
    const loggedOutCookies = await page.cookies(baseUrl);
    assert.notOk(loggedOutCookies.find(({ name }) => name === 'appSession'));
  };

  it('should logout via back-channel logout', () =>
    runTest('backchannel-logout'));

  it('should not logout sub via back-channel logout if user logs in after', async () => {
    if (shouldSkipPuppeteerTest()) {
      return;
    }

    await runTest('backchannel-logout');

    await browser.close();
    browser = await launchBrowser();
    const page = await browser.newPage();
    await goto(baseUrl, page);
    assert.match(page.url(), /http:\/\/localhost:300/);
    await Promise.all([page.click('a'), page.waitForNavigation()]);
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
  });

  it('should logout via back-channel logout with custom implementation genid', () =>
    runTest('backchannel-logout-custom-genid'));

  it('should logout via back-channel logout with custom implementation query store', () =>
    runTest('backchannel-logout-custom-query-store'));
});

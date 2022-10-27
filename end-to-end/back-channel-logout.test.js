const { assert } = require('chai');
const puppeteer = require('puppeteer');
const provider = require('./fixture/oidc-provider');
const {
  baseUrl,
  start,
  runExample,
  stubEnv,
  checkContext,
  goto,
  login,
} = require('./fixture/helpers');

describe('back-channel logout', async () => {
  let authServer;
  let appServer;

  beforeEach(async () => {
    stubEnv();
    authServer = await start(provider, 3001);
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
  });

  const runTest = async (example) => {
    appServer = await runExample(example);
    const browser = await puppeteer.launch({
      args: ['no-sandbox', 'disable-setuid-sandbox'],
    });
    const page = await browser.newPage();
    await goto(baseUrl, page);
    assert.match(page.url(), /http:\/\/localhost:300/);
    await Promise.all([page.click('a'), page.waitForNavigation()]);
    await login('username', 'password', page);
    assert.equal(
      page.url(),
      `${baseUrl}/`,
      'User is returned to the original page'
    );
    const loggedInCookies = await page.cookies('http://localhost:3000');
    assert.ok(loggedInCookies.find(({ name }) => name === 'appSession'));

    const response = await checkContext(await page.cookies());
    assert.isOk(response.isAuthenticated);

    await goto(`${baseUrl}/logout-token`, page);

    await page.click('button');
    await page.waitForNetworkIdle();

    await goto(baseUrl, page);
    const loggedOutCookies = await page.cookies('http://localhost:3000');
    assert.notOk(loggedOutCookies.find(({ name }) => name === 'appSession'));
  };

  it('should logout via back-channel logout', () =>
    runTest('back-channel-logout'));

  it('should logout via back-channel logout with custom implementation', () =>
    runTest('back-channel-logout-custom'));
});

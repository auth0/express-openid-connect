const { assert } = require('chai');
const puppeteer = require('puppeteer');
const request = require('request-promise-native');
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
  let browser;

  beforeEach(async () => {
    stubEnv();
    authServer = await start(provider, 3001);
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
    await browser.close();
  });

  const runTest = async (example) => {
    appServer = await runExample(example);
    browser = await puppeteer.launch({
      args: puppeteer
        .defaultArgs()
        .concat(['--no-sandbox', '--disable-setuid-sandbox']),
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

    await page.waitForSelector('pre');
    const element = await page.$('pre');
    const curl = await page.evaluate((el) => el.textContent, element);
    const [, logoutToken] = curl.match(/logout_token=([^"]+)/);
    const res = await request.post('http://localhost:3000/backchannel-logout', {
      form: {
        logout_token: logoutToken,
      },
      resolveWithFullResponse: true,
    });
    assert.equal(res.statusCode, 204);

    await goto(baseUrl, page);
    const loggedOutCookies = await page.cookies('http://localhost:3000');
    assert.notOk(loggedOutCookies.find(({ name }) => name === 'appSession'));
  };

  it('should logout via back-channel logout', () =>
    runTest('backchannel-logout'));

  it('should not logout sub via back-channel logout if user logs in after', async () => {
    await runTest('backchannel-logout');

    await browser.close();
    browser = await puppeteer.launch({
      args: puppeteer
        .defaultArgs()
        .concat(['--no-sandbox', '--disable-setuid-sandbox']),
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
  });

  it('should logout via back-channel logout with custom implementation genid', () =>
    runTest('backchannel-logout-custom-genid'));

  it('should logout via back-channel logout with custom implementation query store', () =>
    runTest('backchannel-logout-custom-query-store'));
});

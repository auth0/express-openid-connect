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
  logout,
  password,
} = require('./fixture/helpers');

describe('basic login and logout', async () => {
  let authServer;
  let appServer;

  beforeEach(async () => {
    stubEnv();
    authServer = await start(provider, 3001);
    appServer = await runExample('basic');
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
  });

  it('should login and logout with default configuration', async () => {
    const browser = await puppeteer.launch({
      args: puppeteer
        .defaultArgs()
        .concat(['--no-sandbox', '--disable-setuid-sandbox']),
    });
    const page = await browser.newPage();
    await goto(baseUrl, page);
    assert.match(
      page.url(),
      /http:\/\/localhost:3001\/interaction/,
      'User should have been redirected to the auth server to login'
    );
    await login('username', password, page);
    assert.equal(
      page.url(),
      `${baseUrl}/`,
      'User is returned to the original page'
    );
    const loggedInCookies = await page.cookies('http://localhost:3000');
    assert.ok(loggedInCookies.find(({ name }) => name === 'appSession'));

    const response = await checkContext(await page.cookies());
    assert.isOk(response.isAuthenticated);
    assert.equal(response.user.sub, 'username');
    assert.empty(
      response.accessToken,
      "default response_type doesn't include code"
    );
    await logout(page);

    const loggedOutCookies = await page.cookies('http://localhost:3000');
    assert.notOk(loggedOutCookies.find(({ name }) => name === 'appSession'));
  });
});

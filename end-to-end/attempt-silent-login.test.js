const { assert } = require('chai');
const puppeteer = require('puppeteer');
const provider = require('./fixture/oidc-provider');
const {
  baseUrl,
  start,
  login,
  runExample,
  stubEnv,
  goto,
} = require('./fixture/helpers');

describe('attempt silent login', async () => {
  let authServer;
  let appServer;

  beforeEach(async () => {
    stubEnv();
    authServer = await start(provider, 3001);
    appServer = await runExample('attempt-silent-login');
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
  });

  it('should attempt silent login and swallow failures', async () => {
    const args = puppeteer.defaultArgs();
    args.set('--no-sandbox');
    args.set('--disable-setuid-sandbox');

    const browser = await puppeteer.launch(args);
    const page = await browser.newPage();
    await goto(baseUrl, page);
    await page.waitForNavigation();
    assert.equal(page.url(), `${baseUrl}/`);
    const cookies = await page.cookies('http://localhost:3000');
    assert.ok(
      cookies.find(
        ({ name, value }) => name === 'skipSilentLogin' && value === 'true'
      )
    );
    assert.isNotOk(cookies.find(({ name }) => name === 'appSession'));
  });

  it('should login silently if there is an active session on the IDP', async () => {
    const args = puppeteer.defaultArgs();
    args.set('--no-sandbox');
    args.set('--disable-setuid-sandbox');

    const browser = await puppeteer.launch(args);
    const page = await browser.newPage();
    await goto(`${baseUrl}/login`, page);
    assert.match(
      page.url(),
      /http:\/\/localhost:3001\/interaction/,
      'User should have been redirected to the auth server to login'
    );
    await login('username', 'password', page);
    assert.equal(
      page.url(),
      `${baseUrl}/`,
      'User is returned to the original page'
    );
    const loggedInCookies = await page.cookies(baseUrl);
    assert.ok(loggedInCookies.find(({ name }) => name === 'appSession'));

    await page.deleteCookie(
      { name: 'appSession' },
      { name: 'skipSilentLogin' }
    );
    const loggedOutCookies = await page.cookies(baseUrl);
    assert.isNotOk(loggedOutCookies.find(({ name }) => name === 'appSession'));

    await goto(baseUrl, page);
    await page.waitForNavigation();
    assert.equal(page.url(), `${baseUrl}/`);
    const cookies = await page.cookies('http://localhost:3000');
    assert.ok(cookies.find(({ name }) => name === 'appSession'));
  });
});

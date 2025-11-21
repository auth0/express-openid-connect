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
  password,
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
    const browser = await puppeteer.launch({
      args: puppeteer
        .defaultArgs()
        .concat(['--no-sandbox', '--disable-setuid-sandbox']),
    });
    const page = await browser.newPage();
    const context = page.browserContext();

    await goto(baseUrl, page);
    await page.waitForNavigation();
    assert.equal(page.url(), `${baseUrl}/`);
    const cookies = await context.cookies('http://localhost:3000');
    assert.ok(
      cookies.find(
        ({ name, value }) => name === 'skipSilentLogin' && value === 'true',
      ),
    );
    assert.isNotOk(cookies.find(({ name }) => name === 'appSession'));

    await browser.close();
  });

  it('should login silently if there is an active session on the IDP', async () => {
    const browser = await puppeteer.launch({
      args: puppeteer
        .defaultArgs()
        .concat(['--no-sandbox', '--disable-setuid-sandbox']),
    });
    const page = await browser.newPage();
    const context = page.browserContext();

    await goto(`${baseUrl}/login`, page);
    assert.match(
      page.url(),
      /http:\/\/localhost:3001\/interaction/,
      'User should have been redirected to the auth server to login',
    );
    await login('username', password, page);
    assert.equal(
      page.url(),
      `${baseUrl}/`,
      'User is returned to the original page',
    );
    const loggedInCookies = await context.cookies(baseUrl);
    assert.ok(loggedInCookies.find(({ name }) => name === 'appSession'));

    // Delete cookies using BrowserContext API
    const cookiesToDelete = await context.cookies(baseUrl);
    const appSessionCookie = cookiesToDelete.find(
      ({ name }) => name === 'appSession',
    );
    const skipSilentLoginCookie = cookiesToDelete.find(
      ({ name }) => name === 'skipSilentLogin',
    );

    if (appSessionCookie) {
      await page.deleteCookie({
        name: appSessionCookie.name,
        domain: appSessionCookie.domain,
        path: appSessionCookie.path,
      });
    }
    if (skipSilentLoginCookie) {
      await page.deleteCookie({
        name: skipSilentLoginCookie.name,
        domain: skipSilentLoginCookie.domain,
        path: skipSilentLoginCookie.path,
      });
    }

    const loggedOutCookies = await context.cookies(baseUrl);
    assert.isNotOk(loggedOutCookies.find(({ name }) => name === 'appSession'));

    await goto(baseUrl, page);
    await page.waitForNavigation();
    assert.equal(page.url(), `${baseUrl}/`);
    const cookies = await context.cookies('http://localhost:3000');
    assert.ok(cookies.find(({ name }) => name === 'appSession'));

    await browser.close();
  });
});

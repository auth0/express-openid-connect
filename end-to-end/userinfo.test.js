const { assert } = require('chai');
const puppeteer = require('puppeteer');
const provider = require('./fixture/oidc-provider');
const {
  baseUrl,
  start,
  runExample,
  stubEnv,
  goto,
  login,
} = require('./fixture/helpers');

describe('fetch userinfo', async () => {
  let authServer;
  let appServer;

  beforeEach(async () => {
    stubEnv();
    authServer = await start(provider, 3001);
    appServer = await runExample('userinfo');
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
  });

  it('should login with hybrid flow and fetch userinfo', async () => {
    const browser = await puppeteer.launch({
      args: ['no-sandbox', 'disable-setuid-sandbox'],
      executablePath: process.env.PUPPETEER_EXEC_PATH,
      headless: true,
    });
    const page = await browser.newPage();
    await goto(baseUrl, page);
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

    assert.include(await page.content(), 'hello username');
  });
});

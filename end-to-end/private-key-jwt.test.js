const { assert } = require('chai');
const { once } = require('events');
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

describe('private key jwt', async () => {
  let authServer;
  let appServer;

  beforeEach(async () => {
    stubEnv();
    authServer = await start(provider, 3001);
    appServer = await runExample('private-key-jwt');
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
  });

  it('should login with private key jwt client auth method', async () => {
    const browser = await puppeteer.launch({
      args: ['no-sandbox', 'disable-setuid-sandbox'],
      executablePath: process.env.PUPPETEER_EXEC_PATH,
      headless: true,
    });
    const page = await browser.newPage();
    await goto(baseUrl, page);
    assert.match(page.url(), /http:\/\/localhost:3000/);
    await page.click('a[href="/login"]');
    assert.match(
      page.url(),
      /http:\/\/localhost:3001\/interaction/,
      'User should have been redirected to the auth server to login'
    );
    const promise = once(provider, 'grant.success');

    await login('username', 'password', page);
    const [ctx] = await promise;
    assert(
      ctx.oidc.body.client_assertion,
      'Client should have authenticated with a client assertion payload'
    );
    assert.equal(
      ctx.oidc.body.client_assertion_type,
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    );
    assert.equal(
      page.url(),
      `${baseUrl}/`,
      'User is returned to the original page'
    );
    assert.include(await page.content(), 'hello username');
  });
});

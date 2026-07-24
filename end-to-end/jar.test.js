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

describe('JAR + PAR', async () => {
  let authServer;
  let appServer;

  beforeEach(async () => {
    stubEnv({
      ISSUER_BASE_URL: 'http://localhost:3001',
      CLIENT_ID: 'hri-client',
      BASE_URL: 'http://localhost:3000',
      SECRET: 'LONG_RANDOM_VALUE',
      CLIENT_SECRET: 'test-express-openid-connect-client-secret',
    });
    authServer = await start(provider, 3001);
    appServer = await runExample('jar');
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
  });

  it('should login with JAR and PAR', async () => {
    const browser = await puppeteer.launch({
      args: puppeteer
        .defaultArgs()
        .concat(['--no-sandbox', '--disable-setuid-sandbox']),
    });

    // pushed_authorization_request.success fires when the PAR endpoint accepts the request.
    // It receives the ctx at that moment, before the PushedAuthorizationRequest entity is
    // consumed during the subsequent authorization code flow.
    const parPromise = once(provider, 'pushed_authorization_request.success');
    const grantPromise = once(provider, 'grant.success');

    const page = await browser.newPage();
    await goto(baseUrl, page);
    assert.match(page.url(), /http:\/\/localhost:3000/);
    await page.click('a[href="/login"]');
    assert.match(
      page.url(),
      /http:\/\/localhost:3001\/interaction/,
      'User should have been redirected to the auth server to login',
    );

    await login('username', 'password', page);

    // PAR must have completed before the authorization redirect was issued
    const [parCtx] = await parPromise;
    assert.ok(
      parCtx.oidc.body.request,
      'PAR request should contain a signed request object (JAR)',
    );

    // The final token exchange must also succeed
    await grantPromise;

    // Verify we're back on the app
    assert.equal(
      page.url(),
      `${baseUrl}/`,
      'User is returned to the original page',
    );

    const content = await page.content();
    assert.include(content, 'Logged in as');
    assert.include(content, 'username');

    await browser.close();
  });
});

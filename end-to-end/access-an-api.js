const { assert } = require('chai');
const sinon = require('sinon');
const puppeteer = require('puppeteer');
const provider = require('./fixture/oidc-provider');
const {
  baseUrl,
  start,
  runExample,
  runApi,
  stubEnv,
  checkContext,
  goto,
  login,
  password,
} = require('./fixture/helpers');

describe('access an api', async () => {
  let authServer;
  let appServer;
  let apiServer;

  beforeEach(async () => {
    stubEnv();
    authServer = await start(provider, 3001);
    appServer = await runExample('access-an-api');
    apiServer = await runApi();
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
    apiServer.close();
  });

  it('should get an access token and access an api', async () => {
    const browser = await puppeteer.launch({
      args: puppeteer
        .defaultArgs()
        .concat(['--no-sandbox', '--disable-setuid-sandbox']),
    });
    const page = await browser.newPage();

    const clock = sinon.useFakeTimers({
      now: Date.now(),
      toFake: ['Date'],
    });

    await goto(baseUrl, page);

    await login('username', password, page);

    assert.equal(
      page.url(),
      `${baseUrl}/`,
      'User is returned to the original page'
    );
    const {
      accessToken: { access_token, expires_in },
    } = await checkContext(await page.cookies());
    assert.isOk(access_token);
    const content = await page.content();
    assert.include(
      content,
      'Products: Football boots, Running shoes, Flip flops',
      'Page should access products api and show a list of items'
    );
    clock.tick(expires_in * 10000);
    const {
      accessToken: { isExpired },
    } = await checkContext(await page.cookies());
    assert.ok(isExpired);

    await page.reload();

    const reloadedContent = await page.content();
    assert.include(
      reloadedContent,
      'Products: Football boots, Running shoes, Flip flops',
      'Page should access products api with refreshed token and show a list of items'
    );
    const {
      accessToken: { access_token: new_access_token, isExpired: newIsExpired },
    } = await checkContext(await page.cookies());

    assert.isOk(new_access_token);
    assert.notOk(newIsExpired);
    assert.notEqual(new_access_token, access_token);
    clock.restore();
  });
});

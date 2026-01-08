import { assert } from 'chai';
import puppeteer from 'puppeteer';
import provider from './fixture/oidc-provider.js';
import {
  baseUrl,
  start,
  runExample,
  stubEnv,
  goto,
  login,
} from './fixture/helpers.js';

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
      args: puppeteer
        .defaultArgs()
        .concat(['--no-sandbox', '--disable-setuid-sandbox']),
    });
    const page = await browser.newPage();
    await goto(baseUrl, page);
    assert.match(
      page.url(),
      /http:\/\/localhost:3001\/interaction/,
      'User should have been redirected to the auth server to login',
    );
    await login('username', 'password', page);
    assert.equal(
      page.url(),
      `${baseUrl}/`,
      'User is returned to the original page',
    );

    assert.include(await page.content(), 'hello username');
  });
});

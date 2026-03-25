const { assert } = require('chai');
const nock = require('nock');
const { JWT } = require('jose');
const puppeteer = require('puppeteer');
const provider = require('./fixture/oidc-provider');
const { privateJWK } = require('./fixture/jwk');
const {
  baseUrl,
  start,
  runExample,
  runApi,
  stubEnv,
  goto,
  login,
} = require('./fixture/helpers');

describe('custom token exchange', async () => {
  let authServer;
  let appServer;
  let apiServer;

  beforeEach(async () => {
    stubEnv();
    authServer = await start(provider, 3001);
    appServer = await runExample('custom-token-exchange');
    apiServer = await runApi();
  });

  afterEach(async () => {
    nock.cleanAll();
    authServer.close();
    appServer.close();
    apiServer.close();
  });

  it('should exchange the session token and call the downstream API', async () => {
    const browser = await puppeteer.launch({
      args: puppeteer
        .defaultArgs()
        .concat(['--no-sandbox', '--disable-setuid-sandbox']),
    });

    try {
      const page = await browser.newPage();

      // Real OIDC login via Puppeteer
      await goto(baseUrl, page);
      await login('username', 'password', page);
      assert.equal(
        page.url(),
        `${baseUrl}/`,
        'User is returned to the base URL after login',
      );

      /*
       * Set up nock AFTER login to avoid intercepting the auth-code callback.
       * The authorization-code callback POSTs to /token during login, registering the
       * interceptor only after login completes ensures nock fires only for the
       * customTokenExchange call triggered by GET /products.
       *
       * NOTE: The local oidc-provider does not support the token-exchange
       * grant type (urn:ietf:params:oauth:grant-type:token-exchange), so the token
       * exchange request cannot be sent to this provider. nock intercepts the
       * POST /token call and returns a hand-crafted RS256 JWT instead. The JWT is
       * signed with privateJWK (kid: key-1), the same key the provider uses, so
       * express-oauth2-jwt-bearer in api.js can validate it against the provider's
       * live JWKS endpoint. { allowUnmocked: true } is required so that nock still
       * passes through the provider's discovery and JWKS GET requests.
       */
      const downstreamToken = JWT.sign(
        {
          aud: 'https://api.example.com/products',
          scope: 'read:products',
        },
        privateJWK,
        {
          issuer: 'http://localhost:3001',
          algorithm: 'RS256',
          expiresIn: '1h',
          header: { kid: 'key-1' },
        },
      );

      nock('http://localhost:3001', { allowUnmocked: true })
        .post('/token')
        .reply(200, {
          access_token: downstreamToken,
          token_type: 'Bearer',
          expires_in: 3600,
        });

      // Navigate to the protected route that calls customTokenExchange
      await page.goto(`${baseUrl}/products`);

      // Assert the downstream API response is rendered
      assert.include(
        await page.content(),
        'Products: Football boots, Running shoes, Flip flops',
      );
    } finally {
      await browser.close();
    }
  });
});

const Provider = require('oidc-provider');

const client = {
  client_id: 'test-express-openid-connect-client-id',
  client_secret: 'test-express-openid-connect-client-secret',
  token_endpoint_auth_method: 'client_secret_post',
  response_types: ['id_token', 'code', 'code id_token'],
  grant_types: ['implicit', 'authorization_code', 'refresh_token'],
  redirect_uris: [`http://localhost:3000/callback`],
  post_logout_redirect_uris: [
    'http://localhost:3000',
    'http://localhost:3000/custom-logout',
  ],
};

const config = {
  clients: [
    client,
    Object.assign({}, client, {
      client_id: 'private-key-jwt-client',
      token_endpoint_auth_method: 'private_key_jwt',
      jwks: {
        keys: [
          {
            kty: 'RSA',
            e: 'AQAB',
            use: 'sig',
            kid: 'cZNBq0YuRtJ2W9K2xSKZunnLayHcARrjcKtvbkELbdY',
            alg: 'RS256',
            n: 'wJ0FAxJvhTqQGORKMdYInzfjduWHmjikWPv4t-gze-NPgCawwsmOC5N5pgb2qPK_3hdvLAucm36kJyq1C9XDdmA6va51qDHWsAwOd0ob5Tm1xosiULr83KiFhGPCBsgWEPvO3vkdqEwTOq0_p55TfJFfnP5IrwrrUPPwCfDXlGc5xiV-ah4JcqlTdZTk_CfIO7zdhAJUBORam5dDoPzZ035f8GOw6k1ktcX2QxquO3zVcQ4ZOeSwve9ox2ZwNTXOassurfR8jC_E8LcytY083UJ0DdRUJ-8NKjnH_RczfKYmd8nyvjAsD4HBMu97xBat1vP975oHsVA5a9rE-j0lQw',
          },
        ],
      },
    }),
    Object.assign({}, client, {
      client_id: 'client-secret-jwt-client',
      token_endpoint_auth_method: 'client_secret_jwt',
    }),
  ],
  formats: {
    AccessToken: 'jwt',
  },
  audiences() {
    return 'https://api.example.com/products';
  },
  scopes: ['openid', 'offline_access', 'read:products'],
  findAccount(ctx, id) {
    return {
      accountId: id,
      claims: () => ({ sub: id }),
    };
  },
};

const PORT = process.env.PROVIDER_PORT || 3001;

const provider = new Provider(`http://localhost:${PORT}`, config);

// Monkey patch the provider to allow localhost and http redirect uris
const { invalidate: orig } = provider.Client.Schema.prototype;
provider.Client.Schema.prototype.invalidate = function invalidate(
  message,
  code
) {
  if (code === 'implicit-force-https' || code === 'implicit-forbid-localhost') {
    return;
  }
  orig.call(this, message);
};

module.exports = provider;

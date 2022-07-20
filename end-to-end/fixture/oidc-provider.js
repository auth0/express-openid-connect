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
            n: '20yjkC7WmelNZN33GAjFaMvKaInjTz3G49eUwizpuAW6Me9_1FMSAK6nM1XI7VBpy_o5-ffNleRIgcvFudZuSvZiAYBBS2HS5F5PjluVExPwHTD7X7CIwqJxq67N5sTeFkh_ZL4fWK-Na4VlFEsKhcjDrLGxhPCuOgr9FmL0u0Vx_TM3Mk3DEhaf-tMlFx-K3R2GRJRe1wnYhOt1sXm8SNUM2uMZI05W6eRFn1gUAdTLNdCTvDY67ZAl6wyOewYo-WGpzwFYXLXDvc-f8vYucRM3Hq_GSzvFQ4l0nRLLj_33vlCg8mB1CEw_LudadzticAir3Ux3bnpno9yndUZR6w',
            e: 'AQAB',
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

const Provider = require('oidc-provider');

const config = {
  clients: [
    {
      client_id: 'test-express-openid-connect-client-id',
      client_secret: 'test-express-openid-connect-client-secret',
      token_endpoint_auth_method: 'client_secret_basic',
      response_types: ['id_token', 'code', 'code id_token'],
      grant_types: ['implicit', 'authorization_code', 'refresh_token'],
      redirect_uris: [`http://localhost:3000/callback`],
      post_logout_redirect_uris: [
        'http://localhost:3000',
        'http://localhost:3000/custom-logout',
      ],
    },
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

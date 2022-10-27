const Provider = require('oidc-provider');
const { privateJWK, publicJWK } = require('./jwk');

const client = {
  client_id: 'test-express-openid-connect-client-id',
  client_secret: 'test-express-openid-connect-client-secret',
  token_endpoint_auth_method: 'client_secret_post',
  response_types: ['id_token', 'code', 'code id_token'],
  grant_types: ['implicit', 'authorization_code', 'refresh_token'],
  redirect_uris: ['http://localhost:3000/callback'],
  post_logout_redirect_uris: ['http://localhost:3000'],
};

const config = {
  clients: [
    client,
    Object.assign({}, client, {
      client_id: 'private-key-jwt-client',
      token_endpoint_auth_method: 'private_key_jwt',
      jwks: { keys: [publicJWK] },
    }),
    Object.assign({}, client, {
      client_id: 'back-channel-logout-client',
      backchannel_logout_uri: 'http://localhost:3000/back-channel-logout',
      backchannel_logout_session_required: true,
    }),
    Object.assign({}, client, {
      client_id: 'back-channel-logout-client-no-sid',
      backchannel_logout_uri: 'http://localhost:3000/back-channel-logout',
      backchannel_logout_session_required: false,
    }),
    Object.assign({}, client, {
      client_id: 'client-secret-jwt-client',
      token_endpoint_auth_method: 'client_secret_jwt',
    }),
  ],
  jwks: {
    keys: [privateJWK],
  },
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
  features: {
    backchannelLogout: {
      enabled: true,
    },
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

const express = require('express');
const request = require('request-promise-native');
const { auth, requiresAuth } = require('../');

const app = express();

const { API_PORT = 3002 } = process.env;

app.use(
  auth({
    authorizationParams: {
      response_type: 'code',
      // This is the "upstream" audience — the API the user grants access to at login time.
      // In production this is typically different from the downstream service's audience.
      audience: 'https://api.example.com/products',
      scope: 'openid profile offline_access',
    },
  }),
);

app.get('/products', requiresAuth(), async (req, res, next) => {
  try {
    // Exchange the session access token for a downstream API token.
    // subject_token and subject_token_type are resolved from the session automatically.
    const tokenSet = await req.oidc.customTokenExchange({
      audience: 'https://api.example.com/products',
      scope: 'openid read:products',
      // For Auth0 Token Vault add: extra: { connection: 'YOUR_TOKEN_VAULT_CONNECTION' }
    });

    const products = await request.get(
      `http://localhost:${API_PORT}/products`,
      {
        headers: {
          Authorization: `Bearer ${tokenSet.access_token}`,
        },
        json: true,
      },
    );

    res.send(`Products: ${products.map(({ name }) => name).join(', ')}`);
  } catch (err) {
    // AS errors expose err.error and err.error_description
    next(err);
  }
});

module.exports = app;

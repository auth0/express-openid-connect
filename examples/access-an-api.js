const express = require('express');
const request = require('request-promise-native');
const { auth } = require('../');

const app = express();

const { API_PORT = 3002 } = process.env;

app.use(
  auth({
    authorizationParams: {
      response_type: 'code',
      audience: 'https://api.example.com/products',
      scope: 'openid profile email offline_access read:products',
      prompt: 'consent',
    },
  })
);

app.get('/', async (req, res) => {
  let { token_type, access_token, isExpired, refresh } = req.oidc.accessToken;
  if (isExpired()) {
    ({ access_token } = await refresh());
  }
  const products = await request.get(`http://localhost:${API_PORT}/products`, {
    headers: {
      Authorization: `${token_type} ${access_token}`,
    },
    json: true,
  });
  res.send(`Products: ${products.map(({ name }) => name).join(', ')}`);
});

module.exports = app;

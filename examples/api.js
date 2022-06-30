process.env.AUDIENCE = 'https://api.example.com/products';
process.env.TOKEN_SIGNING_ALG = 'RS256';

const express = require('express');
const { auth, requiredScopes } = require('express-oauth2-jwt-bearer');

const app = express();
app.use(auth({ secret: false }));

app.get('/products', requiredScopes('read:products'), (req, res) => {
  res.json([
    { id: 1, name: 'Football boots' },
    { id: 2, name: 'Running shoes' },
    { id: 3, name: 'Flip flops' },
  ]);
});

module.exports = app;

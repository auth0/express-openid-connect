process.env.ALLOWED_AUDIENCES = 'https://api.example.com/products';

const express = require('express');
const { auth, requiredScopes } = require('express-oauth2-bearer');

const app = express();
app.use(auth());

app.get('/products', requiredScopes('read:products'), (req, res) => {
  res.json([
    { id: 1, name: 'Football boots' },
    { id: 2, name: 'Running shoes' },
    { id: 3, name: 'Flip flops' },
  ]);
});

module.exports = app;

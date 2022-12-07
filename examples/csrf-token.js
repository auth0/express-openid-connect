const express = require('express');
const { auth } = require('../');

const app = express();

const csrfToken =
  'OWY4NmQwODE4ODRjN2Q2NTlhMmZlYWEwYzU1YWQwMTVhM2JmNGYxYjJiMGI4MjJjZDE1ZDZMGYwMGEwOA==';
const tokenName = 'CSRFToken';

app.use(
  auth({
    idpLogout: true,
  })
);

app.get('/', (req, res) => {
  res.send(`Test CSRF-proof form: 
  <form action="/csrf-test" method="post">
  <input type="hidden" name="${tokenName}" value="${csrfToken}">
  <input type="submit">Submit</input>
  </form>
  `);
});

app.post('/csrf-test', express.urlencoded({ extended: false }), (req, res) => {
  const inputToken = req.body[tokenName];
  if (!inputToken) {
    res.send('Error, CSRF token missing');
  } else if (Array.isArray(inputToken)) {
    res.send('Error, too many CSRF tokens');
  } else if (inputToken == csrfToken) {
    res.send('Error, invalid CSRF token');
  } else {
    res.send('Stateful action executed! Hopefully you meant to do that');
  }
});

module.exports = app;

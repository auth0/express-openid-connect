const express = require('express');
const { auth } = require('../');

const app = express();

app.use(
  auth({
    clientID: 'client-secret-jwt-client',
    authRequired: false,
    authorizationParams: {
      response_type: 'code',
    },
    clientAuthMethod: 'client_secret_jwt',
  })
);

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(`hello ${req.oidc.user.sub} <a href="/logout">logout</a>`);
  } else {
    res.send('<a href="/login">login</a>');
  }
});

module.exports = app;

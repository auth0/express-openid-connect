const fs = require('fs');
const path = require('path');
const express = require('express');
const { auth } = require('../');

const app = express();

app.use(
  auth({
    clientID: 'jwtca-client',
    authRequired: false,
    authorizationParams: {
      response_type: 'code',
    },
    clientAuthMethod: 'private_key_jwt',
    clientAssertionConfig: {
      signingKey: fs.readFileSync(
      path.join(__dirname, 'private-key.pem')
    ),
      signingAlg: 'RS256'
    }
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

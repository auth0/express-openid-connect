// This example needs to be run on https, see https://auth0.com/docs/libraries/secure-local-development
const express = require('express');
const { auth } = require('../');

const app = express();

app.use(
  auth({
    authRequired: false,
    idpLogout: true,
    session: {
      cookie: {
        sameSite: 'None',
      },
    },
  })
);

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(`hello ${req.oidc.user.sub}, <a href="/logout">logout</a>`);
  } else {
    res.send(`<a href="/login">login</a>`);
  }
});

app.get('/iframe', (req, res) => {
  res.send(`
  <iframe src="https://localhost" style="width: 100%; height: 100%;"/>
  `);
});

module.exports = app;

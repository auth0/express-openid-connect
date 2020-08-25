const express = require('express');
const { auth, requiresAuth } = require('../');

const app = express();

app.use(
  auth({
    idpLogout: true,
    authRequired: false,
    routes: {
      // Pass custom options to the login method by overriding the default login route
      login: false,
      // Pass a custom path to the postLogoutRedirect to redirect users to a different
      // path after login, this should be registered on your authorization server.
      postLogoutRedirect: '/custom-logout',
    },
  })
);

app.get('/', (req, res) => res.send('Welcome!'));

app.get('/profile', requiresAuth(), (req, res) =>
  res.send(`hello ${req.oidc.user.sub}`)
);

app.get('/login', (req, res) => res.oidc.login({ returnTo: '/profile' }));

app.get('/custom-logout', (req, res) => res.send('Bye!'));

module.exports = app;

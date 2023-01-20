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
      callback: false,
    },
  })
);

app.get('/', (req, res) => res.send('Welcome!'));

app.get('/profile', requiresAuth(), (req, res) =>
  res.send(`hello ${req.oidc.user.sub}`)
);

app.get('/login', (req, res) =>
  res.oidc.login({
    returnTo: '/profile',
    authorizationParams: {
      redirect_uri: 'http://localhost:3000/callback',
    },
  })
);

app.get('/custom-logout', (req, res) => res.send('Bye!'));

app.get('/callback', (req, res) =>
  res.oidc.callback({
    redirect_uri: 'http://localhost:3000/callback',
  })
);

app.post('/callback', express.urlencoded({ extended: false }), (req, res) =>
  res.oidc.callback({
    redirect_uri: 'http://localhost:3000/callback',
  })
);

module.exports = app;

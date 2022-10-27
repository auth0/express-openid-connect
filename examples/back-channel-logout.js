const express = require('express');
const { auth, requiresAuth } = require('../');
const { logoutTokenTester } = require('../end-to-end/fixture/helpers');

const MemoryStore = require('memorystore')(auth);

const app = express();

app.use(
  auth({
    clientID: 'back-channel-logout-client',
    authRequired: false,
    idpLogout: true,
    session: {
      store: new MemoryStore(),
    },
    backChannelLogout: true,
  })
);

app.get('/', async (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(`hello ${req.oidc.user.sub} <a href="/logout">logout</a>`);
  } else {
    res.send('<a href="/login">login</a>');
  }
});

// For testing purposes only
app.get(
  '/logout-token',
  requiresAuth(),
  logoutTokenTester('back-channel-logout-client', true)
);

module.exports = app;

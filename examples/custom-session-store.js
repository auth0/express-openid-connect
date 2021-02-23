const express = require('express');
const { auth } = require('../');
const MemoryStore = require('memorystore')(auth);

const app = express();

app.use(
  auth({
    idpLogout: true,
    sessionStore: new MemoryStore({
      checkPeriod: 24 * 60 * 1000,
    }),
  })
);

app.get('/', (req, res) => {
  res.send(`hello ${req.oidc.user.sub}`);
});

module.exports = app;

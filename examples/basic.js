const express = require('express');
const { auth } = require('../');

const app = express();

app.use(
  auth({
    idpLogout: true,
  })
);

app.get('/', (req, res) => {
  res.send(`hello ${req.oidc.user.sub}`);
});

module.exports = app;

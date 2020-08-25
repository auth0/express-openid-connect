const express = require('express');
const { auth, requiresAuth } = require('../');

const app = express();

app.use(
  auth({
    authRequired: false
  })
);

// Anyone can access the homepage
app.get('/', (req, res) => {
  res.send('<a href="/admin">Admin Section</a>');
});

// requiresAuth checks authentication.
app.get('/admin', requiresAuth(), (req, res) =>
  res.send(`Hello ${req.oidc.user.sub}, this is the admin section.`)
);

module.exports = app;

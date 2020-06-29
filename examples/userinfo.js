const express = require('express');
const { auth } = require('../');

const app = express();

app.use(
  auth({
    idpLogout: true,
    authorizationParams: {
      response_type: 'code id_token',
    },
  })
);

app.get('/', async (req, res) => {
  const userInfo = await req.oidc.fetchUserInfo();
  res.send(`hello ${userInfo.sub}`);
});

module.exports = app;

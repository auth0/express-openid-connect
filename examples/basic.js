const express = require('express');
const { auth } = require('../');

const app = express();

app.use(
  auth({
    idpLogout: true,
    authorizationParams: {
      response_type: 'code',
      scope: 'openid',
    },
    afterCallback: async (req, res, session, decodedState) => {
      console.log('session: ', session); //here I can see the token in session
      return {
        ...session,
      };
    },
  })
);

app.get('/', (req, res) => {
  console.log('at', req.oidc.accessToken);
  res.send(`hello ${req.oidc.user.sub}`);
});

module.exports = app;

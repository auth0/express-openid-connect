const express = require('express');
const jose = require('jose');
const { auth } = require('../');

const app = express();

app.use(
  auth({
    authorizationParams: {
      response_type: 'code id_token',
    },
    afterCallback: (req, res, session) => {
      const claims = jose.JWT.decode(session.id_token); 

      if (claims.org_id !== 'Required Organization') {
        throw new Error('User is not a part of the Required Organization');
      }
      return session;
    }
  })
);

app.get('/', async (req, res) => {
  const userInfo = await req.oidc.fetchUserInfo();
  res.send(`hello ${userInfo.sub}`);
});

module.exports = app;

import express from 'express';
import * as jose from 'jose';
import { auth } from '../index.js';

const app = express();

app.use(
  auth({
    authorizationParams: {
      response_type: 'code id_token',
    },
    afterCallback: (req, res, session) => {
      const claims = jose.decodeJwt(session.id_token);

      if (claims.org_id !== 'Required Organization') {
        throw new Error('User is not a part of the Required Organization');
      }
      return session;
    },
    allowInsecureRequests: true,
  }),
);

app.get('/', async (req, res) => {
  const userInfo = await req.oidc.fetchUserInfo();
  res.send(`hello ${userInfo.sub}`);
});

export default app;

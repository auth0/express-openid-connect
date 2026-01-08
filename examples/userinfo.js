import express from 'express';
import { auth } from '../index.js';

const app = express();

app.use(
  auth({
    idpLogout: true,
    authorizationParams: {
      response_type: 'code id_token',
    },
  }),
);

app.get('/', async (req, res) => {
  const userInfo = await req.oidc.fetchUserInfo();
  res.send(`hello ${userInfo.sub}`);
});

export default app;

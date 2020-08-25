const path = require('path');

require('dotenv').config();

const { PORT = 3000, PROVIDER_PORT = 3001, API_PORT = 3002 } = process.env;

const example = process.argv.pop();

// Configure and start a mock authorization server if no .env config is found
if (!process.env.CLIENT_ID) {
  const provider = require('../end-to-end/fixture/oidc-provider');
  console.log(
    'Starting a mock authorization server. You can login with any credentials.'
  );
  process.env = {
    ...process.env,
    ISSUER_BASE_URL: `http://localhost:${PROVIDER_PORT}`,
    CLIENT_ID: 'test-express-openid-connect-client-id',
    BASE_URL: `http://localhost:${PORT}`,
    SECRET: 'LONG_RANDOM_VALUE',
    CLIENT_SECRET: 'test-express-openid-connect-client-secret',
  };
  provider.listen(PROVIDER_PORT, () =>
    console.log(
      `Authorization server started at http://localhost:${PROVIDER_PORT}`
    )
  );
}

const api = require(path.join(__dirname, 'api'));
api.listen(API_PORT, () =>
  console.log(`API started at http://localhost:${API_PORT}`)
);

const app = require(path.join(__dirname, example));

app.listen(PORT, () =>
  console.log(`Example app started at http://localhost:${PORT}`)
);

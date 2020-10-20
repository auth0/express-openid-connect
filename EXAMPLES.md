# Examples

## 1. Basic setup

The simplest use case for this middleware. By default all routes are protected. The middleware uses the [Implicit Flow with Form Post](https://auth0.com/docs/flows/concepts/implicit) to acquire an ID Token from the authorization server and an encrypted cookie session to persist it.

```text
# .env
ISSUER_BASE_URL=https://YOUR_DOMAIN
CLIENT_ID=YOUR_CLIENT_ID
BASE_URL=https://YOUR_APPLICATION_ROOT_URL
SECRET=LONG_RANDOM_STRING
```

```js
// basic.js
const express = require('express');
const { auth } = require('express-openid-connect');

const app = express();

app.use(auth());

app.get('/', (req, res) => {
  res.send(`hello ${req.oidc.user.sub}`);
});
```

**What you get:**

- Every route after the `auth()` middleware requires authentication.
- If a user tries to access a resource without being authenticated, the application will redirect the user to log in. After completion the user is redirected back to the resource.
- The application creates `/login` and `/logout` `GET` routes.

Full example at [basic.js](./examples/basic.js), to run it: `npm run start:example -- basic`

## 2. Require authentication for specific routes

If your application has routes accessible to anonymous users, you can enable authorization per route:

```js
const { auth, requiresAuth } = require('express-openid-connect');

app.use(
  auth({
    authRequired: false,
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
```

Full example at [routes.js](./examples/routes.js), to run it: `npm run start:example -- routes`

## 3. Route customization

If you need to customize the provided login and logout routes, you can disable the default routes and write your own route handler and pass custom paths to mount the handler at that path:

```js
app.use(
  auth({
    routes: {
      // Override the default login route to use your own login route as shown below
      login: false,
      // Pass a custom path to redirect users to a different
      // path after logout.
      postLogoutRedirect: '/custom-logout',
    },
  })
);

app.get('/login', (req, res) => res.oidc.login({ returnTo: '/profile' }));

app.get('/custom-logout', (req, res) => res.send('Bye!'));

module.exports = app;
```

Please note that the login and logout routes are not required. Trying to access any protected resource triggers a redirect directly to Auth0 to login. These are helpful if you need to provide user-facing links to login or logout.

Full example at [custom-routes.js](./examples/custom-routes.js), to run it: `npm run start:example -- custom-routes`

## 4. Obtaining access tokens to call external APIs

If your application needs an [access token](https://auth0.com/docs/tokens/access-tokens) for external APIs you can request one by adding `code` to your `response_type`. The Access Token will be available on the request context:

```js
app.use(
  auth({
    authorizationParams: {
      response_type: 'code',
      audience: 'https://api.example.com/products',
      scope: 'openid profile email read:products',
    },
  })
);

app.get('/', async (req, res) => {
  let { token_type, access_token } = req.oidc.accessToken;
  const products = await request.get('https://api.example.com/products', {
    headers: {
      Authorization: `${token_type} ${access_token}`,
    },
  });
  res.send(`Products: ${products}`);
});
```

Full example at [access-an-api.js](./examples/access-an-api.js), to run it: `npm run start:example -- access-an-api`

## 5. Obtaining and using refresh tokens

[Refresh tokens](https://auth0.com/docs/tokens/concepts/refresh-tokens) can be requested along with access tokens using the `offline_access` scope during login. On a route that calls an API, check for an expired token and attempt a refresh:

```js
app.use(
  auth({
    authorizationParams: {
      response_type: 'code',
      audience: 'https://api.example.com/products',
      scope: 'openid profile email offline_access read:products',
    },
  })
);

app.get('/', async (req, res) => {
  let { token_type, access_token, isExpired, refresh } = req.oidc.accessToken;
  if (isExpired()) {
    ({ access_token } = await refresh());
  }
  const products = await request.get('https://api.example.com/products', {
    headers: {
      Authorization: `${token_type} ${access_token}`,
    },
  });
  res.send(`Products: ${products}`);
});
```

Full example at [access-an-api.js](./examples/access-an-api.js), to run it: `npm run start:example -- access-an-api`

## 6. Calling userinfo

If your application needs to call the `/userinfo` endpoint you can use the `fetchUserInfo` method on the request context:

```js
app.use(auth());

app.get('/', async (req, res) => {
  const userInfo = await req.oidc.fetchUserInfo();
  // ...
});
```

Full example at [userinfo.js](./examples/userinfo.js), to run it: `npm run start:example -- userinfo`

## 6. Protect a route based on specific claims

You can check a user's specific claims to determine if they can access a route:

```js
const {
  auth,
  claimEquals,
  claimIncludes,
  claimCheck,
} = require('express-openid-connect');

app.use(
  auth({
    authRequired: false,
  })
);

// claimEquals checks if a claim equals the given value
app.get('/admin', claimEquals('isAdmin', true), (req, res) =>
  res.send(`Hello ${req.oidc.user.sub}, this is the admin section.`)
);

// claimIncludes checks if a claim includes all the given values
app.get(
  '/sales-managers',
  claimIncludes('roles', 'sales', 'manager'),
  (req, res) =>
    res.send(`Hello ${req.oidc.user.sub}, this is the sales managers section.`)
);

// claimCheck takes a function that checks the claims and returns true to allow access
app.get(
  '/payroll',
  claimCheck(({ isAdmin, roles }) => isAdmin || roles.includes('payroll')),
  (req, res) =>
    res.send(`Hello ${req.oidc.user.sub}, this is the payroll section.`)
);
```

# Examples

1. [Basic setup](#1-basic-setup)
2. [Require authentication for specific routes](#2-require-authentication-for-specific-routes)
3. [Route customization](#3-route-customization)
4. [Obtaining access tokens to call external APIs](#4-obtaining-access-tokens-to-call-external-apis)
5. [Obtaining and using refresh tokens](#5-obtaining-and-using-refresh-tokens)
6. [Calling userinfo](#6-calling-userinfo)
7. [Protect a route based on specific claims](#6-protect-a-route-based-on-specific-claims)
8. [Logout from Identity Provider](#7-logout-from-identity-provider)
9. [Validate Claims from an ID token before logging a user in](#8-validate-claims-from-an-id-token-before-logging-a-user-in)
10. [Use a custom session store](#9-use-a-custom-session-store)

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

## 7. Logout from Identity Provider

When using an IDP, such as Auth0, the default configuration will only log the user out of your application session. When the user logs in again, they will be automatically logged back in to the IDP session. To have the user additionally logged out of the IDP session you will need to add `idpLogout: true` to the middleware configuration.

```js
const { auth } = require('express-openid-connect');

app.use(
  auth({
    idpLogout: true,
    // auth0Logout: true // if using custom domain with Auth0
  })
);
```

## 8. Validate Claims from an ID token before logging a user in

The `afterCallback` hook can be used to do validation checks on claims after the ID token has been received in the callback phase.

```js
app.use(
  auth({
    afterCallback: (req, res, session) => {
      const claims = jose.JWT.decode(session.id_token); // using jose library to decode JWT
      if (claims.org_id !== 'Required Organization') {
        throw new Error('User is not a part of the Required Organization');
      }
      return session;
    },
  })
);
```

In this example, the application is validating the `org_id` to verify that the ID Token was issued to the correct Organization. [Organizations](https://auth0.com/docs/organizations) is a set of features of Auth0 that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.

If you don't know the Organization upfront, then your application should validate the claim to ensure that the value received is expected or known and that it corresponds to an entity your application trusts, such as a paying customer. If the claim cannot be validated, then the application should deem the token invalid. See https://auth0.com/docs/organizations/using-tokens for more info.

## 9. Use a custom session store

By default the session is stored in an encrypted cookie. But when the session gets too large it can bump up against the limits of cookie storage. In these instances you can use a custom session store. The store should have `get`, `set` and `destroy` methods, making it compatible with [express-session stores](https://github.com/expressjs/session#session-store-implementation).

```js
const { auth } = require('express-openid-connect');
const redis = require('redis');
const RedisStore = require('connect-redis')(auth);

const redisClient = redis.createClient();

app.use(
  auth({
    session: {
      store: new RedisStore({ client: redisClient }),
    },
  })
);
```

Full example at [custom-session-store.js](./examples/custom-session-store.js), to run it: `npm run start:example -- custom-session-store`

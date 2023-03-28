# Examples

1. [Basic setup](#1-basic-setup)
2. [Require authentication for specific routes](#2-require-authentication-for-specific-routes)
3. [Route customization](#3-route-customization)
4. [Obtaining access tokens to call external APIs](#4-obtaining-access-tokens-to-call-external-apis)
5. [Obtaining and using refresh tokens](#5-obtaining-and-using-refresh-tokens)
6. [Calling userinfo](#6-calling-userinfo)
7. [Protect a route based on specific claims](#7-protect-a-route-based-on-specific-claims)
8. [Logout from Identity Provider](#8-logout-from-identity-provider)
9. [Validate Claims from an ID token before logging a user in](#9-validate-claims-from-an-id-token-before-logging-a-user-in)
10. [Use a custom session store](#10-use-a-custom-session-store)
11. [Use appSession for CSRF](#11-use-sdk-session-for-csrf-protection)

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

If you need to customize the provided login, logout, and callback routes, you can disable the default routes and write your own route handler and pass custom paths to mount the handler at that path.

When overriding the callback route you should pass a `authorizationParams.redirect_uri` value on `res.oidc.login` and a `redirectUri` value on your `res.oidc.callback` call.

```js
app.use(
  auth({
    routes: {
      // Override the default login route to use your own login route as shown below
      login: false,
      // Pass a custom path to redirect users to a different
      // path after logout.
      postLogoutRedirect: '/custom-logout',
      // Override the default callback route to use your own callback route as shown below
    },
  })
);

app.get('/login', (req, res) =>
  res.oidc.login({
    returnTo: '/profile',
    authorizationParams: {
      redirect_uri: 'http://localhost:3000/callback',
    },
  })
);

app.get('/custom-logout', (req, res) => res.send('Bye!'));

app.get('/callback', (req, res) =>
  res.oidc.callback({
    redirectUri: 'http://localhost:3000/callback',
  })
);

app.post('/callback', express.urlencoded({ extended: false }), (req, res) =>
  res.oidc.callback({
    redirectUri: 'http://localhost:3000/callback',
  })
);

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
      response_type: 'code', // This requires you to provide a client secret
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
      response_type: 'code', // This requires you to provide a client secret
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

## 7. Protect a route based on specific claims

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

## 8. Logout from Identity Provider

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

## 9. Validate Claims from an ID token before logging a user in

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

## 10. Use a custom session store

By default the session is stored in an encrypted cookie. But when the session gets too large it can bump up against the limits of the platform's max header size (16KB for Node >= 14, 8KB for Node <14). In these instances you can use a custom session store. The store should have `get`, `set` and `destroy` methods, making it compatible with [express-session stores](https://github.com/expressjs/session#session-store-implementation).

```js
const { auth } = require('express-openid-connect');
const { createClient } = require('redis');
const RedisStore = require('connect-redis')(auth);

// redis@v4
let redisClient = createClient({ legacyMode: true });
redisClient.connect().catch(console.error);

// redis@v3
let redisClient = createClient();

app.use(
  auth({
    session: {
      store: new RedisStore({ client: redisClient }),
    },
  })
);
```

Full example at [custom-session-store.js](./examples/custom-session-store.js), to run it: `npm run start:example -- custom-session-store`

## 11. Use SDK session for CSRF protection
This SDK's main Cross-Site Request Forgery protection comes from the use of `SameSite=Lax` cookies.

You can add additional CSRF protection manually, using this SDK's session and a [Synchronizer Token](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern).

If your application uses `SameSite=None` cookies, or if for some reason you are using a [safe HTTP method](https://www.rfc-editor.org/rfc/rfc7231#section-4.2.1) like GET for state changes (please don't), you should add a CSRF token to your state changing requests.

Notably, at the time of this writing you cannot use additional cookies with this SDK (keeping your own CSRF token there), nor can you read the raw appSession cookie (using a hash of this cookie as the token, for stateless-ish CSRF). Using the appSession to store a Synchronizer Token seems to be the only valid option.

There are 3 key pieces to this Synchronizer Token example:

1. An `afterCallback` hook that adds a csrfToken to this SDK's `req.appSession`

```js
afterCallback: (req, res, session) => {
    ...
    const genToken = () => crypto.randomBytes(32).toString('hex');
    ...
    const csrfToken = genToken() // Token re-use logic omitted
    return {
        ...session,
        csrfToken
    }
}
```

2. The ability to render the session CSRF token in your HTML forms

```js
const expectedToken = req.appSession.csrfToken;
res.send(`Test CSRF-proof form: 
  <form action="/csrf-test" method="post">
  <input type="hidden" name="CSRFToken" value="${expectedToken}">
  <button type="submit">Submit</button>
  </form>
  `);
```

3. The ability to check submitted tokens against expect the session

```js
const inputToken = req.body['CSRFToken'];
const expectedToken = req.appSession.csrfToken;
if (inputToken != expectedToken) {
  // Block the request!
}
```

First run the example at [csrf-token.js](./examples/csrf-token.js), to run it: `npm run start:example -- csrf-token`

Then on a separate website (like the [W3C Schools](https://www.w3schools.com/html/tryit.asp?filename=tryhtml_form_submit)) host this HTML:

```html
<!DOCTYPE html>
<html>
  <body>
    <h2>CSRF Example</h2>

    <p>
      Log into the sample app at
      <a target="_blank" href="http://localhost:3000/login"
        >http://localhost:3000/login</a
      >
      (opens in another tab)
    </p>
    <p>Test out the test form hosted there, confirm the action executes</p>

    <p>Then come back here and submit the attack form below. It should fail</p>

    <form
      action="http://localhost:3000/csrf-test"
      method="post"
      target="_blank"
    >
      <button type="submit">Submit CSRF attack</button>
    </form>
  </body>
</html>
```

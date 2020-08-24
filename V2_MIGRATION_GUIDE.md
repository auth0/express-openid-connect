# V2 Migration Guide

## Configuration

### Required Keys

- `appSession.secret` is now just `secret` (because it is now used to sign the transient cookies as well as the `appSession` cookie). The environmental variable has changed from `APP_SESSION_SECRET` to `SECRET`.

```dotenv
# Before
SESSION_SECRET=LONG_RANDOM_STRING

# After
SECRET=LONG_RANDOM_STRING
```

```js
const { auth } = require('express-openid-connect');

// Before
app.use(
  auth({
    session: {
      secret: 'LONG_RANDOM_STRING',
    },
  })
);

// After
app.use(
  auth({
    secret: 'LONG_RANDOM_STRING',
  })
);
```

### Route customization

You can now enable individual routes rather than all or nothing and the path to routes can be customized using the `routes` config.

```js
// Before
app.use(
  auth({
    routes: true,
    loginPath: '/custom/login',
    logoutPath: '/custom/logout',
    redirectUriPath: '/custom/callback',
    postLogoutRedirectUri: '/custom/post-logout',
  })
);

// After
app.use(
  auth({
    routes: {
      login: '/custom/login',
      logout: '/custom/logout',
      callback: '/custom/callback',
      postLogoutRedirect: '/custom/post-logout',
    },
  })
);
```

### Session Lifecycle configuration

Session duration was rolling only and configured using `appSession.duration` (default 24hrs). Now it can be configured to rolling or absolute (default rolling 24hrs and absolute 7 days).

```js
// Before
app.use(
  auth({
    appSession: {
      duration: 86400, // default 1 day in secs
    },
  })
);

// After
app.use(
  auth({
    appSession: {
      rolling: true,
      rollingDuration: 86400, // default 1 day rolling duration in secs
      absoluteDuration: 86400 * 7, // default 7 days absolute duration in secs
    },
  })
);
```

### `required` is now `authRequired`

To enable or disable all routes to require authentication, use the `authRequired` configuration (default `true`)

```js
// Before
app.use(
  auth({
    required: true,
  })
);

// After
app.use(
  auth({
    authRequired: true,
  })
);
```

### Configuration items renamed/removed

- **`required` is now `authRequired`** - to enable or disable all routes to require authentication, use the `authRequired` configuration (default `true`)
- **`idTokenAlg` is now `idTokenSigningAlg`** - to specify an id token signing algorithm, use `idTokenSigningAlg`
- **`httpOptions`** - it is no longer possible to pass custom http options to the underlying library
- **`handleCallback`** and **`getUser`** - The hooks have been removed and will be replaced by a collection of hooks in a later release.

```js
// Before
app.use(
  auth({
    required: true,
    idTokenAlg: 'RS256',
    httpOptions: {},
    handleCallback: () => {},
    getUser: () => {},
  })
);

// After
app.use(
  auth({
    authRequired: true,
    idTokenSigningAlg: 'RS256',
  })
);
```

## Session and Context

This library adds an auth context to the request and response objects used within route handling called `oidc` (was `openid`).

```js
// Before
app.get('/', (req, res) => {
  const user = req.openid.user;
  const client = req.openid.client; // It is no longer possible to access the underlying client
  const isAuthenticated = req.isAuthenticated();
  const tokenSet = req.makeTokenSet({ tokens });

  // Login
  res.openid.login({});
  // Logout
  res.openid.logout({});
});

// After
app.get('/', async (req, res) => {
  const user = req.oidc.user;
  const claims = req.oidc.idTokenClaims;
  const isAuthenticated = req.oidc.isAuthenticated();
  const idToken = req.oidc.idToken;
  const {
    access_token,
    token_type,
    expires_in,
    isExpired,
    refresh,
  } = req.oidc.accessToken; // If `code` in response_type
  const refreshToken = req.oidc.refreshToken; // if `offline_access` in scope
  const userInfo = await req.oidc.fetchUserInfo();

  // Login
  res.oidc.login({});
  // Logout
  res.oidc.logout({});
});
```

## Custom Session Handling

The ability to add custom session stores to the SDK using `appSession: false` has been removed and will be added back in a later release.

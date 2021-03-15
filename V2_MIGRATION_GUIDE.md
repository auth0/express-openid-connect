# V2 Migration Guide

`v2.x` brings a number of breaking changes in the library behaviour, configuration options as well as its cookie format. As a result, `v1.x` session will not be accepted by the library after upgrading to `v2.x`, they will in fact be silently ignored and cleaned up.

## Configuration

### Required Configuration Properties

- `appSession.secret` is now just `secret` (because it is now used to sign the transient cookies as well as the `appSession` cookie). The environment variable has changed from `APP_SESSION_SECRET` to `SECRET`.

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

Session duration was being refreshed (e.g. it was "rolling") for another 24 hours (default value unchanged) with every page visit and configured using `appSession.duration`. In addition to that being optional behaviour now (`appSession.rolling`) every session may also have a an absolute duration it will be "rolled" for, when that duration is passed the session is not accepted as valid anymore. The default for this "absolute" duration is 7 days.

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

- **`idTokenAlg` is now `idTokenSigningAlg`** - to specify an id token signing algorithm, use `idTokenSigningAlg`
- **`httpOptions`** was removed - it is no longer possible to pass custom http request options to the underlying library. It will be again in the future in a more curated and comprehensive feature we have in mind for this library.
- **`handleCallback`** and **`getUser`** were removed - These "hooks" will be made available in the future in a more curated and comprehensive feature we have in mind for this library. (**Note** These were added back in [v2.2.0](https://github.com/auth0/express-openid-connect/releases/tag/v2.2.0))

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

The ability to add custom session stores to the SDK using `appSession: false` has been removed but could be added back in a later release (**Note:** Custom session stores have been added to [v2.3.0](https://github.com/auth0/express-openid-connect/releases/tag/v2.3.0). See [the docs](https://auth0.github.io/express-openid-connect/interfaces/sessionconfigparams.html#store) or [an example](./EXAMPLES.md#9-use-a-custom-session-store)).

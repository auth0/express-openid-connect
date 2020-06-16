# Public API

## Configuration

Please see the [Getting Started section of the README](https://github.com/auth0/express-openid-connect#getting-started) for examples of how to apply the configuration options to the `auth()` middleware.

### Required Configuration

The `auth()` middleware has a few configuration properties that are required for initialization.

- **`secret`** - The secret used to derive various keys utilized by the library for signing, encryption, etc. It must be a string, buffer, or an array of strings or buffers. When an array is provided, the first member is used for current operations while the other array members are used for decrypting/verifying old cookies, this enables secret rotation. This can be set automatically with a `SECRET` variable in your environment.
- **`baseURL`** - The root URL for the application router. This can be set automatically with a `BASE_URL` variable in your environment.
- **`clientID`** - The Client ID for your application. This can be set automatically with a `CLIENT_ID`  variable in your environment.
- **`issuerBaseURL`** - The root URL for the token issuer with no trailing slash. In Auth0, this is your Application's **Domain** prepended with `https://`. This can be set automatically with an `ISSUER_BASE_URL` variable in your environment.

If you are using a response type that includes `code`, you will need an additional configuration property:

- **`clientSecret`** - The Client Secret for your application. This can be set automatically with a `CLIENT_SECRET` variable in your environment.

### Optional Configuration

Additional configuration properties that can be passed to `auth()` on initialization:

- **`secret`** - See the **Required Configuration** section above.
- **`session`** - Object defining application session configuration. If this is set to `false`, the internal storage will not be used (see [this example](https://github.com/auth0/express-openid-connect/blob/master/EXAMPLES.md#4-custom-user-session-handling) for how to provide your own session mechanism). Otherwise, the `secret` property is required (see above).
  - **`session.rolling`** - Boolean value, for TODO. Set to `true` by default.
  - **`session.rollingDuration`** - Integer value, in seconds, for TODO. Default is 1 day.
  - **`session.absoluteDuration`** - Integer value, in seconds, for TODO. Default is 7 days.
  - **`session.name`** - String value for the cookie name used for the internal session. This value must only include letters, numbers, and underscores. Default is `appSession`.
  - **`session.cookie`** - Object defining application session cookie configuration.
  - **`session.cookie.transient`** - Sets the application session cookie expiration to `0` to create a transient cookie. Set to `false` by default.
  - **`session.cookie.domain`** - Passed to the [Response cookie](https://expressjs.com/en/api.html#res.cookie) as `domain`.
  - **`session.cookie.httpOnly`** - Passed to the [Response cookie](https://expressjs.com/en/api.html#res.cookie) as `httponly`. Set to `true` by default.
  - **`session.cookie.secure`** - Passed to the [Response cookie](https://expressjs.com/en/api.html#res.cookie) as `secure`.
  - **`session.cookie.sameSite`** - Passed to the [Response cookie](https://expressjs.com/en/api.html#res.cookie) as `samesite`. Set to `"Lax"` by default.
- **`auth0Logout`** - Boolean value to enable Auth0's logout feature. Default is `false`.
- **`attemptSilentLogin`** - Boolean value to enable silent login attempt when anonymous user is encountered. Default is `false`.
- **`authorizationParams`** - Object that describes the authorization server request. [See below](#authorization-params-property) for defaults and more details.
- **`clockTolerance`** - Integer value for the system clock's tolerance (leeway) in seconds for ID token verification. Default is `60`.
- **`enableTelemetry`** - Opt-in to sending the library and node version to your authorization server via the `Auth0-Client` header. Default is `true`.
- **`errorOnRequiredAuth`** - Boolean value to throw a `Unauthorized 401` error instead of triggering the login process for routes that require authentication. Default is `false`.
- **`identityClaimFilter`** - Array value of claims to remove from the ID token before storing the cookie session. Default is `['aud', 'iss', 'iat', 'exp', 'nonce', 'azp', 'auth_time']`.
- **`idpLogout`** - Boolean value to log the user out from the identity provider on application logout. Requires the issuer to provide a `end_session_endpoint` value. Default is `false`.
- **`idTokenSigningAlg`** - String value for the expected ID token algorithm. Default is `RS256`.
- **`legacySameSiteCookie`** - Set a fallback cookie with no SameSite attribute when `authorizationParams.response_mode` is `form_post`. Default is `true`.
- **`authRequired`** - Use a boolean value to require authentication for all routes. Default is `true` (authentication is required for all routes). TODO: for fine grained control apply `requiresAuth` middlewares.
- **`routes`** -
  - **`routes.login`** - Relative path to application login route which triggers the login flow. Default is `/login`. Set to `false` when you want to completely omit the route from being exposed.
  - **`routes.logout`** - Relative path to application logout route which triggers the logout flow. Default is `/logout`. Set to `false` when you want to completely omit the route from being exposed.
  - **`routes.callback`** - Relative path to the application callback to process the response from the authorization server. This value is combined with the `baseUrl` and sent to the authorize endpoint as the `redirect_uri` parameter. Default is `/callback`. The resulting URL used must be registered at the authorization server.
  - **`routes.postLogoutRedirectUri`** - Either a relative path to the application or a valid URI to an external domain. The user will be redirected to this after logout has been performed. Adding a `returnTo` parameter on the logout route will override this value. The value used must be registered at the authorization server. Default is `baseUrl`.

### Authorization Params Property

The `authorizationParams` property defines the URL parameters used when redirecting users to the authorization server to log in. If this property is not provided by your application, its default values will be:

```js
{
  response_type: "id_token",
  response_mode: "form_post",
  scope: "openid profile email"
}
```

New values can be passed in to change what is returned from the authorization server depending on your specific scenario.

For example, to receive an access token for an API, you could initialize like the sample below. Note that `response_mode` can be omitted because the OAuth2 default mode of `query` is fine:

```js
app.use(auth({
  authorizationParams: {
    response_type: "code",
    scope: "openid profile email read:reports",
    audience: "https://your-api-identifier"
  }
}));
```

Additional custom parameters can be added as well:

```js
app.use(auth({
  authorizationParams: {
    // Note: you need to provide required parameters if this object is set.
    response_type: "id_token",
    response_mode: "form_post",
    scope: "openid profile email"

    // Additional parameters
    acr_value: "tenant:test-tenant",
    custom_param: "custom-value"
  }
}));
```

## `requiresAuth()`

The `requiresAuth()` function is an optional middleware that protects specific application routes when the `authRequired` configuration property is set to `false`:

```js
const { auth, requiresAuth } = require('express-openid-connect');
app.use( auth( { authRequired: false } ) );
app.use( '/admin', requiresAuth(), (req, res) => res.render('admin') );
```

Using `requiresAuth()` on its own without initializing `auth()` will throw a `401 Unauthorized` error instead of triggering the login process:

```js
// app.use(auth({ authRequired: true }));
app.get('/', requiresAuth(), (req, res) => res.render('home'));
```

## Session and Context

This library adds properties and methods to the request and response objects used within route handling.

### Request

Every request object (typically named `req` in your route handler) is augmented with the following:

- **`req.oidc.isAuthenticated()`** - Returns `true` when the request is authenticated, `false` when it is not.
- **`req.oidc.idTokenClaims`** - Returns the ID Token claims from an ID Token returned by the authorization server. Is `undefined` when there's no authenticated user.
- **`req.oidc.user`** - Contains the authenticated user information from the authorization server. Is `undefined` when there's no authenticated user.
- **`req.oidc.idToken`** - Contains the value of the ID Token as returned by the authorization server. Is `undefined` when there's no authenticated user.
- **`req.oidc.accessToken`** - Contains an object with Access Token details. Is `undefined` when there's no authenticated user or authentication flow resulted in no Access Token being issued.
  - **`req.oidc.accessToken.access_token`** - Contains the String value of an Access Token as returned by the authorization server.
  - **`req.oidc.accessToken.token_type`** - Contains the String value of the Access Token `token_type` as returned by the authorization server.
  - **`req.oidc.accessToken.expires_in`** - Contains the Number value representing the number of seconds until the Access Token expires.
  - **`req.oidc.accessToken.isExpired()`** - Returns `true` when the Access Token is expired, `false` when it is not.
- **`req.oidc.refreshToken`** - Contains the value of a Refresh Token as optionally returned by the authorization server. Is `undefined` when there's no authenticated user or authentication flow resulted in no Refresh Token being issued.

### Response

Every response object (typically named `res` in your route handler) is augmented with the following:

- **`res.oidc.login({})`** - trigger an authentication request from any route. It receives an object with the following properties:
  - `returnTo`: The URL to return to after authentication. Defaults to the current URL for `GET` routes and `baseURL` for other methods.
  - `authorizationParams`: Additional parameters for the authorization call.
- **`res.oidc.logout({})`** - trigger the openid connect logout if supported by the issuer. It receives an object with the following properties:
  - `returnTo`: The URL to return to after signing out at the authorization server. Defaults to the `baseURL`.

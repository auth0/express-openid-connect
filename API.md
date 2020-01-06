# Public API

## Configuration Keys

Please see the [Getting Started section of the README](https://github.com/auth0/express-openid-connect#getting-started) for examples of how to apply the configuration options to the `auth()` middleware.

### Required Keys

The `auth()` middleware has a few configuration keys that are required for initialization.

- **`appSessionSecret`** - The secret used to derive an encryption key for the user identity in a session cookie.  It must be a string, an array of strings, or `false` to skip this internal storage and provide your own session mechanism in `getUser`. When array is provided the first member is used for signing and other members can be used for decrypting old cookies, this is to enable appSessionSecret rotation. This can be set automatically with an `APP_SESSION_SECRET` variable in your environment.
- **`baseURL`** - The root URL for the application router. This can be set automatically with a `BASE_URL` variable in your environment.
- **`clientID`** - The Client ID for your application. This can be set automatically with a `CLIENT_ID`  variable in your environment.
- **`issuerBaseURL`** - The root URL for the token issuer with no trailing slash. In Auth0, this is your Application's **Domain** prepended with `https://`. This can be set automatically with an `ISSUER_BASE_URL` variable in your environment.

If you are using a response type that includes `code` (typically combined with an `audience` parameter), you will need an additional key:

- **`clientSecret`** - The Client Secret for your application. This can be set automatically with a `CLIENT_SECRET` variable in your environment.

### Optional Keys

Additional configuration keys that can be passed to `auth()` on initialization:

- **`appSessionCookie`** - Object defining application session cookie attributes. Allowed keys are `domain`, `httpOnly`, `path`, `secure`, and `sameSite`. Defaults are `true` for `httpOnly` and `Lax` for `sameSite`.
- **`appSessionDuration`** - Integer value, in seconds, for application session duration. Set to `0` to indicate the cookie should be ephemeral (no expiration). Default is 7 days.
- **`appSessionName`** - String value for the cookie name used for the internal session. This value must only include letters, numbers, and underscores. Default is `identity`.
- **`auth0Logout`** - Boolean value to enable Auth0's logout feature. Default is `false`.
- **`authorizationParams`** - Object that describes the authorization server request. [See below](#authorization-params-key) for defaults and more details.
- **`clockTolerance`** - Integer value for the system clock's tolerance (leeway) in seconds for ID token verification. Default is `60`.
- **`errorOnRequiredAuth`** - Boolean value to throw a `Unauthorized 401` error instead of triggering the login process for routes that require authentication. Default is `false`.
- **`getUser`** - Function that returns the profile for `req.openid.user`. This runs on each application page load for authenticated users. Default is [here](lib/hooks/getUser.js).
- **`handleCallback`** - Function that runs on the callback route, after callback processing but before redirection. Default is [here](lib/hooks/handleCallback.js).
- **`httpOptions`** - Default options object used for all HTTP calls made by the library ([possible options](https://github.com/sindresorhus/got/tree/v9.6.0#options)). Default is empty.
- **`identityClaimFilter`** - Array value of claims to remove from the ID token before storing the cookie session. Default is `['aud', 'iss', 'iat', 'exp', 'nonce', 'azp', 'auth_time']`.
- **`idpLogout`** - Boolean value to log the user out from the identity provider on application logout. Requires the issuer to provide a `end_session_endpoint` value. Default is `false`.
- **`idTokenAlg`** - String value for the expected ID token algorithm. Default is `RS256`.
- **`legacySameSiteCookie`** - Set a fallback cookie with no SameSite attribute when `authorizationParams.response_mode` is `form_post`. Default is `true`.
- **`loginPath`** - Relative path to application login. Default is `/login`.
- **`logoutPath`** - Relative path to application logout. Default is `/logout`.
- **`redirectUriPath`** - Relative path to the application callback to process the response from the authorization server. This value is combined with the `baseUrl` and sent to the authorize endpoint as the `redirectUri` parameter. Default is `/callback`.
- **`required`** - Use a boolean value to require authentication for all routes. Pass a function instead to base this value on the request. Default is `true`.
- **`routes`** - Boolean value to automatically install the login and logout routes. See [the examples](EXAMPLES.md) for more information on how this key is used. Default is `true`.

### Authorization Params Key

The `authorizationParams` key defines the URL parameters used when redirecting users to the authorization server to log in. If this key is not provided by your application, its default value will be:

```js
{
  response_type: "id_token",
  response_mode: "form_post",
  scope: "openid profile email"
}
```

A new object can be passed in to change what is returned from the authorization server depending on your specific scenario.

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

The `requiresAuth()` function is an optional middleware that protects specific application routes when the `required` configuration key is set to `false`:

```javascript
const { auth, requiresAuth } = require('express-openid-connect');
app.use( auth( { required: false } ) );
app.use( '/admin', requiresAuth(), (req, res) => res.render('admin') );
```

Using `requiresAuth()` on its own without initializing `auth()` will throw a `401 Unauthorized` error instead of triggering the login process:

```js
// app.use(auth({required: true}));
app.get('/', requiresAuth(), (req, res) => res.render('home'));
```

## Session and Context

This library adds properties and methods to the request and response objects used within route handling.

### Request

Every request object (typically named `req` in your route handler) is augmented with the following when the request is authenticated. If the request is not authenticated, `req.openid` is `undefined` and `req.isAuthenticated()` returns `false`.

- **`req.openid.user`** - Contains the user information returned from the authorization server. You can change what is provided here by passing a function to the `getUser` configuration key.
- **`req.openid.client`** - Is the [OpenID Client](https://github.com/panva/node-openid-client/blob/master/docs/README.md#client) instance that can be used for additional OAuth2 and OpenID calls. See [the examples](EXAMPLES.md) for more information on how this is used.
- **`req.isAuthenticated()`** - Returns true if the request is authenticated.
- **`req.makeTokenSet()`** - Make a TokenSet object from a JSON representation of one.

### Response

Every response object (typically named `res` in your route handler) is augmented with the following:

- **`res.openid.login({})`** - trigger an authentication request from any route. It receives an object with the following keys:
  - `returnTo`: The URL to return to after authentication. Defaults to the current URL for `GET` routes and `baseURL` for other methods.
  - `authorizationParams`: Additional parameters for the authorization call.
- **`res.openid.logout({})`** - trigger the openid connect logout if supported by the issuer. It receives an object with the following key:
  - `returnTo`: The URL to return to after signing out at the authorization server. Defaults to the `baseURL`.

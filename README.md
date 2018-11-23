[![Build Status](https://travis-ci.org/auth0/express-openid-client.svg?branch=master)](https://travis-ci.org/auth0/express-openid-client)

Express.js middleware for OpenID Relying Party (aka OAuth 2.0 Client).

This module exposes two middlewares:

-  `.routes()`: install two routes one called `/login` and the other one `/callback`.
-  `.protect()`: is a middleware that redirects to `/login` if `req.openid` is not set. This middleware preserves the url that the user tried to access in the session, so the callback can redirect back to it after a succesful login.

## Install

```
npm i express-openid-connect --save
```

## Requirements

Before installing the routes,

-  a body parser middleware for urlencoded content, eg: https://www.npmjs.com/package/body-parser
-  a session middleware like [express-session](https://www.npmjs.com/package/express-session) or [cookie-session](https://www.npmjs.com/package/cookie-session).
-  node v8 or greater
-  express v3 or greater

## Usage

```javascript
const auth = require('express-openid-client');

app.use(auth.routes({
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
  baseURL: 'https://myapplication.com',
  clientID: process.env.AUTH0_CLIENT_ID,
}))

app.use('/user', auth.protect(), (req, res) => {
  res.send(`hello ${req.openid.user.name}`);
});

app.get('/', (req, res) => res.send("hello!"));
```

## Configuration through environment variables

Settings can be provided by environment variables as follows:

```
ISSUER_BASE_URL=https://my-domain.auth0.com
BASE_URL=https://myapplication.com
CLIENT_ID=xyz
```

then:

```javascript
const auth = require('express-openid-client');
app.use(auth.routes())
```

## auth.routes parameters

In general, you won't need to configure this middleware besides the required parameters that can be specified through environment variables.

| Name                | Default                         | Description                                                                    |
|---------------------|---------------------------------|--------------------------------------------------------------------------------|
| issuerBaseURL       | `env.ISSUER_BASE_URL`           | The url address for the token issuer.                                          |
| baseURL             | `env.BASE_URL`                  | The url of the web application where you are installing the router.            |
| clientID            | `env.CLIENT_ID`                 | The client id.                                                                 |
| clientSecret        | `env.CLIENT_SECRET`             | The client secret, only required for some grants.                              |
| clockTolerance      | `5`                             | The clock's tolerance in seconds for token verification.                       |
| profileMapper       | `(tokenSet) => tokenSet.claims` | An async function receiving a tokenset and returning the profile for req.user. |
| authorizationParams | See bellow                      | The parameters for the authorization call. Defaults to                         |

Default value for `authorizationParams` is:

```javascript
{
  response_type: 'id_token',
  response_mode: 'form_post',
  scope: 'openid profile email'
}
```

Commonly used `authorizationParams`:

| Name                | Default                | Description                                                                                                  |
|---------------------|------------------------|--------------------------------------------------------------------------------------------------------------|
| response_type       | **Required**           | The desired authorization processing flow, including what parameters are returned from the endpoints used.   |
| response_mode       | `undefined` / optional | The mechanism to be used for returning Authorization Response parameters from the Authorization Endpoint.    |
| scope               | `openid profile email` | The scope of the access token.                                                                               |
| audience            | `undefined` / optional | The audience for the access token.                                                                           |


## Debugging

Start your application with the following environment variable to make this module output the debug logs.

```
DEBUG=express-openid-client:*
```

**WARNING:** this feature is intended only for development and must not be used in production since it will log sensitive information.

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.


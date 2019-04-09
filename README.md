[![Build Status](https://travis-ci.org/auth0/express-openid-connect.svg?branch=master)](https://travis-ci.org/auth0/express-openid-connect)

Express.js middleware for OpenID Relying Party (aka OAuth 2.0 Client).

The purpose of this middleware is to give a tool to our customers to easily add authentication to their applications, the goals for this project are:

1.  **Secure by default**:
  -  The middleware implements the best practices to work with OpenID Connect providers.
  -  All routes after the middleware require authentication by default.
2.  **Simple setup**: Pain-free configuration by using OpenID Connect metadata and the best defaults.
3.  **Standard**: The library is standard enough to work with many OpenID Connect providers.

## Install

```
npm i express-openid-connect --save
```

## Requirements

Before installing the routes,

-  a body parser middleware for urlencoded content, eg: https://www.npmjs.com/package/body-parser
-  a session middleware like [express-session](https://www.npmjs.com/package/express-session) or [cookie-session](https://www.npmjs.com/package/cookie-session).
-  node v8 or higher
-  express v3 or higher

## Usage

Using the auth middleware:

```javascript
const { auth } = require('express-openid-connect');

//insert your session and body parser middlewares here
// app.use(session());
// app.use(bodyParser());

app.use(auth())

app.use('/', (req, res) => {
  res.send(`hello ${req.openid.user.name}`);
});
```

- Every route after the `auth()` requires authentication.
- If a user try to access a resource without being authenticated, the application will trigger the authentication process. After completion the user is redirected back to the resource.
- The application also gets a `GET /login` and `GET /logout` route for easy linking.



This application needs the following environment variables to work:

-  `ISSUER_BASE_URL`: The url of the issuer.
-  `CLIENT_ID`: The client id of the application.
-  `BASE_URL`: The url of your application. For development environments you can omit this.

For more examples check the [EXAMPLES](EXAMPLES.md) document.

The `auth()` middleware can be customized, please check the [API](API.md) document.

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

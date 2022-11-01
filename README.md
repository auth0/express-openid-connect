![Express JS middleware implementing sign on for Express web apps using OpenID Connect.](https://cdn.auth0.com/website/sdks/banner/express-openid-connect-banner.png)

![Release](https://img.shields.io/npm/v/express-openid-connect)
[![Codecov](https://img.shields.io/codecov/c/github/auth0/express-openid-connect)](https://codecov.io/gh/auth0/express-openid-connect)
![Downloads](https://img.shields.io/npm/dw/express-openid-connect)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)
![CircleCI](https://img.shields.io/circleci/build/github/auth0/express-openid-connect)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💻 [API Reference](#api-reference) - 💬 [Feedback](#feedback)

## Documentation

- [Quickstart](https://auth0.com/docs/quickstart/webapp/express) - our guide for quickly adding Auth0 to your Express app.
- [Sample](https://github.com/auth0-samples/auth0-express-webapp-sample/tree/master/01-Login) - an Express app integrated with Auth0.
- [FAQs](https://github.com/auth0/express-openid-connect/blob/master/FAQ.md) - Frequently asked questions about express-openid-connect.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### Requirements

This library supports the following tooling versions:

- Node.js `^10.19.0 || >=12.0.0`

## Install

Using [npm](https://npmjs.org) in your project directory, run the following command:

```bash
npm install express-openid-connect
```

## Getting Started

Follow our [Secure Local Development guide](https://auth0.com/docs/libraries/secure-local-development) to ensure that applications using this library are running over secure channels (HTTPS URLs). Applications using this library without HTTPS may experience "invalid state" errors.

### Configure Auth0

Create a **Regular Web Application** in the [Auth0 Dashboard](https://manage.auth0.com/#/applications).

> **If you're using an existing application**, verify that you have configured the following settings in your Regular Web Application:
>
> - Click on the "Settings" tab of your application's page.
> - Ensure that "Token Endpoint Authentication Method" under "Application Properties" is set to "None"
> - Scroll down and click on the "Show Advanced Settings" link.
> - Under "Advanced Settings", click on the "OAuth" tab.
> - Ensure that "JsonWebToken Signature Algorithm" is set to `RS256` and that "OIDC Conformant" is enabled.
>   Next, configure the following URLs for your application under the "Application URIs" section of the "Settings" page:

- **Allowed Callback URLs**: `http://localhost:3000`
- **Allowed Logout URLs**: `http://localhost:3000`

> These URLs should reflect the origins that your application is running on. **Allowed Callback URLs** may also include a path, depending on where you're handling the callback (see below).

Take note of the **Client ID** and **Domain** values under the "Basic Information" section. You'll need these values in the next step.

### Configuring the SDK

The library needs [issuerBaseURL](https://auth0.github.io/express-openid-connect/interfaces/ConfigParams.html#issuerbaseurl), [baseURL](https://auth0.github.io/express-openid-connect/interfaces/ConfigParams.html#baseurl), [clientID](https://auth0.github.io/express-openid-connect/interfaces/ConfigParams.html#clientid) and [secret](https://auth0.github.io/express-openid-connect/interfaces/ConfigParams.html#secret) to request and accept authentication. These can be configured with environmental variables:

```text
ISSUER_BASE_URL=https://YOUR_DOMAIN
CLIENT_ID=YOUR_CLIENT_ID
BASE_URL=https://YOUR_APPLICATION_ROOT_URL
SECRET=LONG_RANDOM_VALUE
```

... or in the library initialization:

```js
// index.js

const { auth } = require('express-openid-connect');
app.use(
  auth({
    issuerBaseURL: 'https://YOUR_DOMAIN',
    baseURL: 'https://YOUR_APPLICATION_ROOT_URL',
    clientID: 'YOUR_CLIENT_ID',
    secret: 'LONG_RANDOM_STRING',
    idpLogout: true,
  })
);
```

With this basic configuration, your application will require authentication for all routes and store the user identity in an encrypted and signed cookie.

### Error Handling

Errors raised by this library are handled by the [default Express error handler](https://expressjs.com/en/guide/error-handling.html#the-default-error-handler) which, in the interests of security, does not include the stack trace or error message in the production environment. If you write your own error handler, you should not render the error message or the OAuth `error`/`error_description` properties without using a templating engine that will properly escape them first.

To write your own error handler, see the Express documentation on writing [Custom error handlers](https://expressjs.com/en/guide/error-handling.html#writing-error-handlers).

For other comprehensive examples such as route-specific authentication, custom application session handling, requesting and using access tokens for external APIs, and more, see the [EXAMPLES.md](https://github.com/auth0/express-openid-connect/blob/master/EXAMPLES.md) document.

See the [examples](https://github.com/auth0/express-openid-connect/blob/master/EXAMPLES.md) for route-specific authentication, custom application session handling, requesting and using access tokens for external APIs, and more.

### Use of Custom Session Stores and `genid`

If you create your own session id when using [Custom Session Stores](https://github.com/auth0/express-openid-connect/blob/master/EXAMPLES.md#9-use-a-custom-session-store) by overriding the `genid` configuration, you must use a suitable cryptographically strong random value of sufficient size to prevent collisions and reduce the ability to hijack a session by guessing the session ID.

## API Reference

Explore the express-openid-connect API.

- [ConfigParams](https://auth0.github.io/express-openid-connect/interfaces/ConfigParams.html)

**Provided middleware:**

- [attemptSilentLogin](https://auth0.github.io/express-openid-connect/functions/attemptSilentLogin.html)
- [auth](https://auth0.github.io/express-openid-connect/functions/auth.html)
- [claimCheck](https://auth0.github.io/express-openid-connect/functions/claimCheck.html)
- [claimEquals](https://auth0.github.io/express-openid-connect/functions/claimEquals.html)
- [claimIncludes](https://auth0.github.io/express-openid-connect/functions/claimIncludes.html)
- [requiresAuth](https://auth0.github.io/express-openid-connect/functions/requiresAuth.html)

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](https://github.com/auth0/express-openid-connect/blob/master/CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/express-openid-connect/issues).

### Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## What is Auth0?

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">
  Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a>
</p>
<p align="center">
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/express-openid-connect/blob/master/LICENSE"> LICENSE</a> file for more info.
</p>

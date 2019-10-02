# Express OpenID Connect

Express.js middleware for OpenID Relying Party (aka OAuth 2.0 Client). Easily add secure and standards-based authentication to Express applications.

This library requires:

- Node v10.13 or higher
- Express v4.16 or higher
- A session middleware like [express-session](https://www.npmjs.com/package/express-session) or [cookie-session](https://www.npmjs.com/package/cookie-session)

**Please Note:** This library is currently in pre-release status and has not had a complete security review. We **do not** recommend using this library in production yet. As we move towards early access, please be aware that releases may contain breaking changes. We will be monitoring the Issues queue here for feedback and questions. PRs and comments on existing PRs are welcome!

[![Build Status](https://travis-ci.org/auth0/express-openid-connect.svg?branch=master)](https://travis-ci.org/auth0/express-openid-connect)

[![NPM version](https://img.shields.io/npm/v/express-openid-connect.svg?style=flat-square)](https://npmjs.org/package/express-openid-connect)

[![Downloads](https://img.shields.io/npm/dm/express-openid-connect.svg.svg?style=flat-square)](https://npmjs.org/package/express-openid-connect.svg)

## Table of Contents

- [Documentation](#documentation)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [Support + Feedback](#support--feedback)
- [Vulnerability Reporting](#vulnerability-reporting)
- [What is Auth0](#what-is-auth0)
- [License](#license)

## Documentation

More complete documentation coming soon!

- [Examples for common configurations](EXAMPLES.md)
- [API documentation](API.md)
- [Sample application](https://github.com/joshcanhelp/express-oidc-connect-starter)
- [Sample implementation](https://github.com/auth0/node-sample-with-openid-client)

## Installation

This library is installed with [npm](https://npmjs.org/package/express-openid-connect):

```
npm i express-openid-connect --save
```

## Getting Started

The library needs the following values to request and accept authentication:

- **Issuer Base URL**: The base URL of the authorization server. If you're using Auth0, this is your tenant **Domain** pre-pended with `https://` (like `https://tenant.auth0.com`) found on the **Settings** tab for your Application in the [Auth0 dashboard](https://manage.auth0.com).
- **Client ID**: The identifier for your Application. If you're using Auth0, this value can also be found on the **Settings** tab for your Application.
- **Base URL**: The  root URL for your application.

These can be configured in a `.env` file in the root of your application:

```text
# .env

ISSUER_BASE_URL=https://YOUR_DOMAIN
CLIENT_ID=YOUR_CLIENT_ID
BASE_URL=https://YOUR_APPLICATION_ROOT_URL
```

... or in the library initialization:

```js
// index.js

app.use(auth({
  issuerBaseURL: 'https://YOUR_DOMAIN',
  baseURL: 'https://YOUR_APPLICATION_ROOT_URL',
  clientID: 'YOUR_CLIENT_ID'
}));
```

See [Examples](EXAMPLES.md) for how to get started authenticating users.

## Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/.github/blob/master/CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)

Contributions can be made to this library through PRs to fix issues, improve documentation or add features. Please fork this repo, create a well-named branch, and submit a PR with a complete template filled out.

Code changes in PRs should be accompanied by tests covering the changed or added functionality. Tests can be run for this library with:

```bash
npm install
npm test
```

When you're ready to push your changes, please run the lint command first:

```bash
npm run lint
```

## Support + Feedback

Please use the [Issues queue](https://github.com/auth0/express-openid-connect/issues) in this repo for questions and feedback.

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## What is Auth0?

Auth0 helps you to easily:

- implement authentication with multiple identity providers, including social (e.g., Google, Facebook, Microsoft, LinkedIn, GitHub, Twitter, etc), or enterprise (e.g., Windows Azure AD, Google Apps, Active Directory, ADFS, SAML, etc.)
- log in users with username/password databases, passwordless, or multi-factor authentication
- link multiple user accounts together
- generate signed JSON Web Tokens to authorize your API calls and flow the user identity securely
- access demographics and analytics detailing how, when, and where users are logging in
- enrich user profiles from other data sources using customizable JavaScript rules

[Why Auth0?](https://auth0.com/why-auth0)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

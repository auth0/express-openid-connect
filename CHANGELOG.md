# CHANGELOG

## [v0.6.0](https://github.com/auth0/express-openid-connect/tree/v0.6.0) (2020-01-14)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v0.5.0...v0.6.0)

**Breaking changes in this release:**

This release includes important changes to user session and token handling which will require an update for all applications. 

First, a new, required configuration key - `appSessionSecret`- has been added. The value here will be used to generate keys which are in turn used to encrypt the user identity returned from the identity provider. This encrypted and signed identity is stored in a cookie and used to populate the `req.openid.user` property, as before. This key should be set to either a secure, random value to use this built-in session or `false` to provide [your own custom application session handling](https://github.com/auth0/express-openid-connect/blob/master/EXAMPLES.md#4-custom-user-session-handling). A value for this can be generated with `openssl` like so:

```
❯ openssl rand -hex 32
f334eb9ee5898101f90047ec46f18c2f4c082f5eeef109920d6b0fc5b79b6f29
```

As part of these changes, a session middleware is no longer required for this library. One can be added and used for application session and tokens (see above and below, respectively) but initialization will no longer fail if one is not present.

Additionally, tokens returned from the identity provider will no longer be stored in a session middleware automatically. If your application requires access, refresh, or ID tokens to be retrieved and stored (not just the user identity), you will need to provide a method for that storage in version 0.6.0 and beyond. [See our examples page for guidance](https://github.com/auth0/express-openid-connect/blob/master/EXAMPLES.md#5-obtaining-and-storing-access-tokens-to-call-external-apis).

**Closed issues**

- "legacySameSiteCookie" for auth config params is not yet available in the typings file. [\#44](https://github.com/auth0/express-openid-connect/issues/44)
- Validate configured routes [\#21](https://github.com/auth0/express-openid-connect/issues/21)

**Added**

- Add path validation [\#47](https://github.com/auth0/express-openid-connect/pull/47) ([joshcanhelp](https://github.com/joshcanhelp))
- Add typescript defs new config [\#46](https://github.com/auth0/express-openid-connect/pull/46) ([joshcanhelp](https://github.com/joshcanhelp))
- Add SameSite support [\#39](https://github.com/auth0/express-openid-connect/pull/39) ([joshcanhelp](https://github.com/joshcanhelp))
- Add custom callback handling [\#37](https://github.com/auth0/express-openid-connect/pull/37) ([joshcanhelp](https://github.com/joshcanhelp))
- Add body parser to login and callback route [\#33](https://github.com/auth0/express-openid-connect/pull/33) ([davidpatrick](https://github.com/davidpatrick))

**Changed**

- Change session and token handling [\#42](https://github.com/auth0/express-openid-connect/pull/42) ([joshcanhelp](https://github.com/joshcanhelp))

## [v0.5.0](https://github.com/auth0/express-openid-connect/tree/v0.5.0) (2019-10-17)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v0.4.0...v0.5.0)

**Closed issues**

- Removal of automatic refresh [\#11](https://github.com/auth0/express-openid-connect/issues/11)

**Added**

- Add configurable HTTP options [\#29](https://github.com/auth0/express-openid-connect/pull/29) ([joshcanhelp](https://github.com/joshcanhelp))
- add typescript types [\#27](https://github.com/auth0/express-openid-connect/pull/27) ([jbarrus](https://github.com/jbarrus))
- Add telemetry to HTTP requests [\#23](https://github.com/auth0/express-openid-connect/pull/23) ([joshcanhelp](https://github.com/joshcanhelp))
- feat: allow custom login and logout paths [\#14](https://github.com/auth0/express-openid-connect/pull/14) ([joshcanhelp](https://github.com/joshcanhelp))

**Changed**

- Update default leeway and re-write API documentation [\#30](https://github.com/auth0/express-openid-connect/pull/30) ([joshcanhelp](https://github.com/joshcanhelp))

## [v0.4.0](https://github.com/auth0/express-openid-connect/tree/v0.4.0) (2019-09-26)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v0.3.0...v0.4.0)

**Important note:** This release bumps the minimum Node version required to `^10.13.0`.

**Closed issues**
- GetUser [\#10](https://github.com/auth0/express-openid-connect/issues/10)
- Thoughts on user info endpoint? [\#7](https://github.com/auth0/express-openid-connect/issues/7)

**Changed**
- feat: bump openid-client [\#12](https://github.com/auth0/express-openid-connect/pull/12) ([panva](https://github.com/panva))

**Removed**
- Remove debugging callbacks [\#17](https://github.com/auth0/express-openid-connect/pull/17) ([joshcanhelp](https://github.com/joshcanhelp))

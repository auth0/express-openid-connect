# CHANGELOG

## [2.4.0](https://github.com/auth0/express-openid-connect/tree/v2.4.0) (2021-05-11)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.3.1...v2.4.0)

**Added**
- Swallor error on silent auth [#230](https://github.com/auth0/express-openid-connect/pull/230) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Token Endpoint Parameters [#228](https://github.com/auth0/express-openid-connect/pull/228) ([davidpatrick](https://github.com/davidpatrick))

## [2.3.1](https://github.com/auth0/express-openid-connect/tree/v2.3.1) (2021-04-09)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.3.0...v2.3.1)

**Fixed**
- Set cookie headers on header write (before res.end) [#214](https://github.com/auth0/express-openid-connect/pull/214) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Prompt should be passed as an auth param  [#217](https://github.com/auth0/express-openid-connect/pull/217) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [2.3.0](https://github.com/auth0/express-openid-connect/tree/v2.3.0) (2021-03-10)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.2.1...v2.3.0)

**Added**
- Custom session stores [#190](https://github.com/auth0/express-openid-connect/pull/190) ([davidpatrick](https://github.com/davidpatrick))

## [2.3.0-beta.0](https://github.com/auth0/express-openid-connect/tree/v2.3.0-beta.0) (2021-02-23)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.2.1...v2.3.0-beta.0)

To install: `npm install express-openid-connect@beta`

**Added**
- Custom session stores [#190](https://github.com/auth0/express-openid-connect/pull/190) ([davidpatrick](https://github.com/davidpatrick))

## [2.2.1](https://github.com/auth0/express-openid-connect/tree/v2.2.1) (2021-01-25)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.2.0...v2.2.1)

**Fixed**
- missing base64url dependency [#180](https://github.com/auth0/express-openid-connect/pull/180) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [2.2.0](https://github.com/auth0/express-openid-connect/tree/v2.2.0) (2021-01-14)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.1.0...v2.2.0)

**Added**
- afterCallback Hook [#171](https://github.com/auth0/express-openid-connect/pull/171) ([davidpatrick](https://github.com/davidpatrick))

**Changed**
- Move transient cookies into single cookie [#168](https://github.com/auth0/express-openid-connect/pull/168) ([davidpatrick](https://github.com/davidpatrick))
- Use native node hkdf when available (Node >=15) [#177](https://github.com/auth0/express-openid-connect/pull/177) ([panva](https://github.com/panva))

## [2.1.0](https://github.com/auth0/express-openid-connect/tree/v2.1.0) (2020-12-15)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.0.0...v2.1.0)

**Changed**
- Default cookie.secure config to the protocol of baseURL [#159](https://github.com/auth0/express-openid-connect/pull/159) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**
- Fix session.cookie TS definitions [#157](https://github.com/auth0/express-openid-connect/pull/157) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [2.0.0-beta.0](https://github.com/auth0/express-openid-connect/tree/v2.0.0-beta.0) (2020-08-31)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v1.0.2...v2.0.0-beta.0)

For a full list of breaking changes and migration guide, checkout https://github.com/auth0/express-openid-connect/blob/master/V2_MIGRATION_GUIDE.md

**Breaking Changes**
- postLogoutRedirect and response_type check [#123](https://github.com/auth0/express-openid-connect/pull/123) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Logout returnTo param [#115](https://github.com/auth0/express-openid-connect/pull/115) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Session duration behaviour [#114](https://github.com/auth0/express-openid-connect/pull/114) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Update Session cookie [#111](https://github.com/auth0/express-openid-connect/pull/111) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Configuration and API updates [#109](https://github.com/auth0/express-openid-connect/pull/109) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Update token set [#108](https://github.com/auth0/express-openid-connect/pull/108) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Added**
- attemptSilentLogin feature [#121](https://github.com/auth0/express-openid-connect/pull/121) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Add refresh method to access token [#124](https://github.com/auth0/express-openid-connect/pull/124) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Architecture [#128](https://github.com/auth0/express-openid-connect/pull/128) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.0.2](https://github.com/auth0/express-openid-connect/tree/v1.0.2) (2020-05-12)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v1.0.1...v1.0.2)

**Fixed**
- Fix returnTo on Login [\#95](https://github.com/auth0/express-openid-connect/pull/95) ([davidpatrick](https://github.com/davidpatrick)) 

## [v1.0.1](https://github.com/auth0/express-openid-connect/tree/v1.0.1) (2020-04-17)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v1.0.0...v1.0.1)

**Fixed**
- Fix issue where authz header was overridden in code exchange [\#86](https://github.com/auth0/express-openid-connect/pull/86) ([adamjmcgrath](https://github.com/adamjmcgrath)) 

## [v1.0.0](https://github.com/auth0/express-openid-connect/tree/v1.0.0) (2020-03-30)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v0.8.1...v1.0.0)

**Added**
- Allow to opt-out from sending SDK Telemetry [\#78](https://github.com/auth0/express-openid-connect/pull/78) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Changed**
- Change the default session duration to 1 day [\#80](https://github.com/auth0/express-openid-connect/pull/80) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**
- Fix case where APP_SESSION_SECRET is set and appSession is not [\#74](https://github.com/auth0/express-openid-connect/pull/74) ([adamjmcgrath](https://github.com/adamjmcgrath)) 
- Fix cookie options case [\#76](https://github.com/auth0/express-openid-connect/pull/76) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v0.8.1](https://github.com/auth0/express-openid-connect/tree/v0.8.1) (2020-03-02)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v0.8.0...v0.8.1)

**Fixed**
- Remove returnTo parameter for logout [\#72](https://github.com/auth0/express-openid-connect/pull/72) ([joshcanhelp](https://github.com/joshcanhelp))

## [v0.8.0](https://github.com/auth0/express-openid-connect/tree/v0.8.0) (2020-02-26)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v0.7.0...v0.8.0)

This release contains a breaking change for all applications. Please see the PR below for migration info.

**Changed**
- App session settings [\#68](https://github.com/auth0/express-openid-connect/pull/68) ([joshcanhelp](https://github.com/joshcanhelp))

## [v0.7.0](https://github.com/auth0/express-openid-connect/tree/v0.7.0) (2020-02-18)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v0.6.0...v0.7.0)

**Added**
- Update TS defs for config functions [\#65](https://github.com/auth0/express-openid-connect/pull/65) ([joshcanhelp](https://github.com/joshcanhelp))
- Register Express as a peer dependency [\#63](https://github.com/auth0/express-openid-connect/pull/63) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Add custom state handling [\#60](https://github.com/auth0/express-openid-connect/pull/60) ([joshcanhelp](https://github.com/joshcanhelp))

**Changed**
- Merge seperate config schemas [\#57](https://github.com/auth0/express-openid-connect/pull/57) ([joshcanhelp](https://github.com/joshcanhelp))
- Update hapi to v16 and fix breaking changes [\#56](https://github.com/auth0/express-openid-connect/pull/56) ([joshcanhelp](https://github.com/joshcanhelp))
- Update hapi/joi to 15.x; update other deps to minor/patch [\#51](https://github.com/auth0/express-openid-connect/pull/51) ([joshcanhelp](https://github.com/joshcanhelp))

**Fixed**
- Additional allowed cookieOptions [\#53](https://github.com/auth0/express-openid-connect/pull/53) ([joshcanhelp](https://github.com/joshcanhelp))
- Fix TS definition for appSessionSecret [\#52](https://github.com/auth0/express-openid-connect/pull/52) ([joshcanhelp](https://github.com/joshcanhelp))
- Fix post logout redirect, add config for default [\#40](https://github.com/auth0/express-openid-connect/pull/40) ([balazsorban44](https://github.com/balazsorban44))

## [v0.6.0](https://github.com/auth0/express-openid-connect/tree/v0.6.0) (2020-01-14)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v0.5.0...v0.6.0)

**Breaking changes in this release:**

This release includes important changes to user session and token handling which will require an update for all applications.

First, a new, required configuration key - `appSessionSecret` (changed to `appSession.secret` in v0.8.0) - has been added. The value here will be used to generate keys which are in turn used to encrypt the user identity returned from the identity provider. This encrypted and signed identity is stored in a cookie and used to populate the `req.openid.user` property, as before. This key should be set to either a secure, random value to use this built-in session or `false` to provide [your own custom application session handling](https://github.com/auth0/express-openid-connect/blob/master/EXAMPLES.md#4-custom-user-session-handling). A value for this can be generated with `openssl` like so:

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

# Change Log

## [v2.16.0](https://github.com/auth0/express-openid-connect/tree/v2.16.0) (2023-05-05)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.15.0...v2.16.0)

**Added**
- [SDK-4135] Add Pushed Authorization Requests [\#470](https://github.com/auth0/express-openid-connect/pull/470) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.15.0](https://github.com/auth0/express-openid-connect/tree/v2.15.0) (2023-04-19)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.14.0...v2.15.0)

**Added**
- Make genid async [\#464](https://github.com/auth0/express-openid-connect/pull/464) ([Will956](https://github.com/Will956))

## [v2.14.0](https://github.com/auth0/express-openid-connect/tree/v2.14.0) (2023-04-13)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.13.0...v2.14.0)

**Added**
- Add httpAgent option [\#458](https://github.com/auth0/express-openid-connect/pull/458) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.13.0](https://github.com/auth0/express-openid-connect/tree/v2.13.0) (2023-03-28)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.12.1...v2.13.0)

**Added**
- [SDK-3873] Discovery cache max age [\#449](https://github.com/auth0/express-openid-connect/pull/449) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.12.1](https://github.com/auth0/express-openid-connect/tree/v2.12.1) (2023-03-10)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.12.0...v2.12.1)

**Fixed**
- [SDK-3887] Always honor auth0Logout config [\#447](https://github.com/auth0/express-openid-connect/pull/447) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.12.0](https://github.com/auth0/express-openid-connect/tree/v2.12.0) (2023-01-24)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.11.0...v2.12.0)

**Added**
- [SDK-3911] Add support for providing a custom callback route [\#438](https://github.com/auth0/express-openid-connect/pull/438) ([ewanharris](https://github.com/ewanharris))

**Fixed**
- Use custom client assertion signing alg [\#437](https://github.com/auth0/express-openid-connect/pull/437) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.11.0](https://github.com/auth0/express-openid-connect/tree/v2.11.0) (2022-12-08)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.10.0...v2.11.0)

**Added**
- [SDK-3808] Optionally sign the session store cookie [\#419](https://github.com/auth0/express-openid-connect/pull/419) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**
- Remove dependency on `cb` lib [\#424](https://github.com/auth0/express-openid-connect/pull/424) ([kmannislands](https://github.com/kmannislands))

## [v2.10.0](https://github.com/auth0/express-openid-connect/tree/v2.10.0) (2022-11-11)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.9.0...v2.10.0)

**Added**
- Add option to override transaction cookie name [\#414](https://github.com/auth0/express-openid-connect/pull/414) ([MatthewBacalakis](https://github.com/MatthewBacalakis))

## [v2.9.0](https://github.com/auth0/express-openid-connect/tree/v2.9.0) (2022-10-17)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.8.0...v2.9.0)

**Added**
- [SDK-3717] Add cookie prop to support more express-session stores [\#395](https://github.com/auth0/express-openid-connect/pull/395) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.8.0](https://github.com/auth0/express-openid-connect/tree/v2.8.0) (2022-07-20)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.7.3...v2.8.0)

**Added**
- [SDK-3503] Add *_jwt token endpoint auth methods [\#376](https://github.com/auth0/express-openid-connect/pull/376) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.7.3](https://github.com/auth0/express-openid-connect/tree/v2.7.3) (2022-06-29)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.7.2...v2.7.3)

**Fixed**
- discovery errors should be handled in express middleware [\#371](https://github.com/auth0/express-openid-connect/pull/371) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Allow periods in cookie name [\#350](https://github.com/auth0/express-openid-connect/pull/350) ([moberegger](https://github.com/moberegger))

## [v2.7.2](https://github.com/auth0/express-openid-connect/tree/v2.7.2) (2022-03-29)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.7.1...v2.7.2)

**Security**
- URL Redirection to Untrusted Site ('Open Redirect') in express-openid-connect [GHSA-7p99-3798-f85c](https://github.com/auth0/express-openid-connect/security/advisories/GHSA-7p99-3798-f85c)

## [v2.7.1](https://github.com/auth0/express-openid-connect/tree/v2.7.1) (2022-02-24)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.7.0...v2.7.1)

**Fixed**
- transactionCookie configuration should be optional [\#338](https://github.com/auth0/express-openid-connect/pull/338) ([BitPatty](https://github.com/BitPatty))

## [v2.7.0](https://github.com/auth0/express-openid-connect/tree/v2.7.0) (2022-02-17)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.6.0...v2.7.0)

**Added**
- [SDK-3109] Add ability to pass custom logout params [\#329](https://github.com/auth0/express-openid-connect/pull/329) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-3111] Add Oauth error props to http error when available [\#328](https://github.com/auth0/express-openid-connect/pull/328) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-3110] Allow customising the UA header in client reqs [\#327](https://github.com/auth0/express-openid-connect/pull/327) ([adamjmcgrath](https://github.com/adamjmcgrath))
- allow configuration of same site attribute on auth_verification cookie [\#323](https://github.com/auth0/express-openid-connect/pull/323) ([BitPatty](https://github.com/BitPatty))

**Changed**
- Looser cookie name validation [\#330](https://github.com/auth0/express-openid-connect/pull/330) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.6.0](https://github.com/auth0/express-openid-connect/tree/v2.6.0) (2022-01-31)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.5.2...v2.6.0)

**Added**
- Add cross domain iframe support for modern browsers [\#317](https://github.com/auth0/express-openid-connect/pull/317) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.5.2](https://github.com/auth0/express-openid-connect/tree/v2.5.2) (2021-12-09)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.5.1...v2.5.2)

**Security**

- Session fixation fix [CVE-2021-41246](https://github.com/auth0/express-openid-connect/security/advisories/GHSA-7rg2-qxmf-hhx9)

**Fixed**
- Fix refresh signature in ts defs [\#294](https://github.com/auth0/express-openid-connect/pull/294) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.5.1](https://github.com/auth0/express-openid-connect/tree/v2.5.1) (2021-09-28)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.5.0...v2.5.1)

**Fixed**
- Fix cookie chunking [\#275](https://github.com/auth0/express-openid-connect/pull/275) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [2.5.0](https://github.com/auth0/express-openid-connect/tree/v2.5.0) (2021-07-14)
[Full Changelog](https://github.com/auth0/express-openid-connect/compare/v2.4.0...v2.5.0)

**Added**

- Add custom session id generation [#252](https://github.com/auth0/express-openid-connect/pull/252) ([nholik](https://github.com/nholik))
- Add `httpTimeout` Option [#251](https://github.com/auth0/express-openid-connect/pull/251) ([jmacvey](https://github.com/jmacvey))

**Fixed**

- Chunked cookies should not exceed browser max [#237](https://github.com/auth0/express-openid-connect/pull/237) ([davidpatrick](https://github.com/davidpatrick))

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

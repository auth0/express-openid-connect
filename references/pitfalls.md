# Common Pitfalls

- **Network is disabled in unit tests.** `test/setup.js` calls `nock.disableNetConnect()` (localhost allowed). Any code path that makes an outbound HTTP call will fail a unit test unless you register a `nock` interceptor. Stub the OIDC discovery/JWKS/token endpoints rather than hitting the network.

- **`index.d.ts` is hand-written and drifts.** It is not generated from the JS. When you add or change a config option (`lib/config.js`) or an export (`index.js`), update `index.d.ts` in the same PR and run `npm run test:types` — `tsd` will catch mismatches against `index.test-d.ts`.

- **Config options are validated by Joi, with defaults.** Reading config directly or forgetting to add a schema rule in `lib/config.js` means the option is silently dropped (Joi strips unknown keys where `.unknown(true)` isn't set) or missing its default. Declare every new option in the schema.

- **`lib/context.js` is large and central.** Most login/callback/session behavior flows through it. Changes here have wide blast radius; add targeted unit tests and prefer surgical edits.

- **Cookie/session format is a compatibility surface.** `lib/appSession.js` + `lib/crypto.js` encrypt the session cookie. Changing the format, encryption, or cookie flags can invalidate existing user sessions — treat as a breaking change (Ask First).

- **`response_type` drives PKCE and `response_mode` defaults.** The default flow is `id_token` (Implicit + Form Post). When `response_type` includes `code`, PKCE and different `response_mode` validation apply (`lib/config.js`). Don't assume Authorization Code semantics for the default config.

- **Telemetry must ride the shared fetch wrapper.** New outbound OIDC requests should go through `createCustomFetch` (`lib/client.js`) so they carry the `Auth0-Client` header and `User-Agent`; a hand-rolled client bypasses telemetry and the `enableTelemetry` opt-out.

- **Two npm-release paths exist.** Releases are cut via the release workflows; don't bump versions or edit `CHANGELOG.md` by hand as part of a feature change. Keep `.version` and `package.json` `"version"` in sync when a version does change.

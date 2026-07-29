# Testing

## Frameworks & layout

- **Unit tests** — Mocha (`mocha` config in `package.json`) + Chai (`assert`) + Sinon (stubs/spies) + `nock` (HTTP interception). Located in `test/`, files named `*.tests.js`.
- **Type tests** — `tsd` validates `index.d.ts` against `index.test-d.ts` (`npm run test:types`).
- **End-to-end tests** — Mocha + Puppeteer driving the runnable apps in `examples/` against a **local** `oidc-provider` (not a live Auth0 tenant). Located in `end-to-end/`, files named `*.test.js`. Slow (30s timeout) and launch a headless browser.
- **Coverage** — `nyc` (Istanbul), lcov reporter, uploaded to Codecov (`codecov.yml`). Run via `npm run test:ci`.

The default `npm run test` suite is unit-only and requires no credentials: `test/setup.js` disables outbound network (`nock.disableNetConnect()`) and only allows localhost, so every external call must be stubbed.

## Running

```bash
npm run test                                   # all unit tests
npm run test -- --grep "login"                 # filter by describe/it name
npx mocha test/login.tests.js                   # a single unit file
npm run test:ci                                 # unit + coverage
npm run test:end-to-end                         # browser integration tier
```

## Conventions

- **Structure:** `describe('feature', () => { ... })` with `it('should ... when ...', ...)`; `beforeEach`/`afterEach` for setup/teardown.
- **Assertions:** Chai `assert` style (`const { assert } = require('chai')` or `require('chai').assert`), plus `chai-as-promised` for promises.
- **HTTP stubbing:** `test/setup.js` (loaded via the mocha `file` option) sets up `nock` interceptors for the well-known OIDC discovery and JWKS endpoints and stubs `console.warn`. Add new `nock` mocks in your test rather than reaching the network.
- **Request helpers:** unit tests drive the middleware with `request-promise-native` (configured `simple: false, resolveWithFullResponse: true`) against a fixture server in `test/fixture/`.
- **Doubles:** use `sinon` for stubs/spies; restore them in `afterEach`.

## End-to-end tier

Uses `puppeteer` (with `--no-sandbox` in CI) and a local `oidc-provider` started on port 3001; `end-to-end/fixture/` provides the provider and helpers, and env is stubbed (`stubEnv`) with test-only client credentials — no real tenant involved. Still slower and heavier than unit tests, so run the unit suite first while iterating.

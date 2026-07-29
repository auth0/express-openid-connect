# Commands

Full command reference for express-openid-connect. All commands are `npm run <script>` unless noted, and map to scripts in `package.json` and jobs in `.github/workflows/test.yml`.

## Everyday

```bash
npm install              # install dependencies (NODE_ENV=development in CI build step)
npm run test             # unit tests — Mocha with --max-http-header-size=16384
npm run lint             # ESLint over the repo (eslint .)
```

## Testing tiers

```bash
npm run test:ci          # unit tests with coverage: nyc --reporter=lcov npm test
npm run test:types       # type-definition tests: tsd . (validates index.d.ts)
npm run test:end-to-end  # browser integration: mocha end-to-end --timeout 30000 (Puppeteer + local oidc-provider)
```

## Docs & examples

```bash
npm run docs             # generate TypeDoc API docs into docs/ (typedoc --options typedoc.js index.d.ts)
npm run start:example    # run the local example app (node ./examples/run_example.js), serves http://localhost:3000
```

## What CI runs

`.github/workflows/test.yml` runs, gated on a build job:

- **unit** — `npm run test:ci` on Node 20.x / 22.x / 24.x, then uploads coverage to Codecov
- **types** — `npm run test:types`
- **mocha** — `npm run test:end-to-end`
- **lint** — `npm run lint`

Other workflows: `codeql.yml`, `snyk.yml`, `rl-secure.yml` (security scans), `release.yml` / `npm-release.yml` (release — cut by the release process, not by an agent).

> There is no separate build/compile step — this is plain CommonJS. The "Build Package" CI job just installs dependencies and caches them.

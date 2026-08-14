# AI Agent Guidelines for express-openid-connect

This document provides context and guidelines for AI coding assistants working with the express-openid-connect codebase.

## Your Role

You are a Node.js SDK engineer working on express-openid-connect, the Express middleware that adds OpenID Connect Relying Party sign-on to Express web applications. You work in idiomatic CommonJS, treat the middleware's config surface and its Joi validation schema as the public contract, and keep the session/cookie handling and OIDC flow correctness front of mind because they are what protect a consumer's users.

---

## Project Overview

**express-openid-connect** is Express middleware to protect web applications using OpenID Connect.

- **Language:** JavaScript (CommonJS), with hand-written TypeScript types in `index.d.ts`
- **Tech Stack:** Express (peer dep `>= 4.17.0`) · `openid-client` v6 (OIDC/OAuth) · `jose` (JWT/keys) · `joi` (config validation) · `http-errors`
- **Package Manager:** npm
- **Minimum Platform Version:** Node.js `^20.19.0 || ^22.12.0 || >= 23.0.0` (see `engines` in `package.json`)
- **Dependencies:** `openid-client` 6, `jose` 6, `joi` 17, `cookie` 0.7 (+7 more) · test: Mocha, Chai, Sinon, nock, tsd, Puppeteer — see `package.json` for the full list

---

## Project Structure

```
.
├── index.js              # Public entry — re-exports auth, requiresAuth, attemptSilentLogin, SessionExpiredError
├── index.d.ts            # Hand-written TypeScript type definitions (the typed public contract)
├── .version              # Version source of truth (mirrors package.json "version")
├── middleware/           # The exported middleware factories
│   ├── auth.js           # `auth()` — mounts login/logout/callback routes + session
│   ├── requiresAuth.js   # `requiresAuth()` / claim guards
│   ├── attemptSilentLogin.js
│   └── unauthorizedHandler.js
├── lib/                  # Internal implementation (key modules shown; others: cookies.js, tokenset.js, once.js, weakCache.js, debug.js)
│   ├── config.js         # Joi schema — the config/public-option contract
│   ├── client.js         # openid-client setup + telemetry / User-Agent headers
│   ├── context.js        # Request context, OIDC flow logic (largest module)
│   ├── appSession.js     # Encrypted cookie session handling
│   ├── crypto.js         # Cookie encryption/signing
│   ├── transientHandler.js
│   ├── errors.js         # SessionExpiredError (typed error)
│   └── hooks/, utils/    # getLoginState hook, helpers
├── test/                 # Unit tests (Mocha + Chai + Sinon + nock)
├── end-to-end/           # Slow browser integration tests (Puppeteer + local oidc-provider)
├── examples/             # Runnable example apps (referenced by EXAMPLES.md and e2e tests)
└── docs/                 # Generated TypeDoc API output (do not hand-edit)
```

### Key Files

| File | Why it matters |
|------|----------------|
| `index.js` | Public export surface — anything not re-exported here is internal |
| `index.d.ts` | Hand-written types; must stay in lockstep with the runtime config/options |
| `lib/config.js` | Joi schema defining every valid config option and its default — the option contract |
| `lib/context.js` | Core OIDC flow (login/callback/session) — most behavior changes land here |
| `lib/client.js` | Where the `Auth0-Client` telemetry header and `User-Agent` are set |
| `.version` | Version source of truth, kept in sync with `package.json` |

---

## Boundaries

### ✅ Always Do

- Run `npm run test` (unit) and `npm run lint` before committing.
- Follow existing CommonJS style and naming conventions (Prettier: single quotes, 80-col width).
- Add unit tests under `test/` for new functionality; use `nock` to stub HTTP, never real network.
- Keep `index.d.ts` in sync with runtime behavior — a new/changed config option or export must update the types in the same PR.
- Keep `.version` and `package.json` `"version"` in sync (both are version sources).
- Update `README.md` and `EXAMPLES.md` in the same PR when you change a config option, the public API, or a supported integration pattern; update the affected app under `examples/` when you change what it demonstrates.
- When adding a **new outbound request path to the OIDC provider**, route it through the existing `createCustomFetch` in `lib/client.js` (and the equivalent in `lib/context.js`) so it carries the `Auth0-Client` telemetry header and `User-Agent` — don't hand-roll a separate HTTP client — and preserve the `enableTelemetry` opt-out.

### ⚠️ Ask First

- **Any breaking change — always ask first.** Never change or remove a public config option, export, default, or cookie/session format on your own initiative; stop and ask the maintainer.
- Adding new dependencies or bumping existing ones.
- Modifying public API signatures or the `lib/config.js` Joi schema (options and defaults are the public contract).
- Changes to CI/CD configuration (`.github/workflows/`).
- Changing session storage or cookie encryption/format (`lib/appSession.js`, `lib/crypto.js`) — it affects existing sessions.
- Modifying security-related code (token handling, PKCE/state/nonce, cookie flags).

### 🚫 Never Do

- Commit secrets, API keys, client secrets, or tokens.
- Log tokens, `id_token`/`access_token` contents, session cookies, or client secrets.
- Modify generated files by hand: `docs/` (TypeDoc output), `CHANGELOG.md`, `coverage/`, `.nyc_output/`, lock files.
- Remove or skip failing tests without fixing the underlying cause.
- Modify `node_modules/`.
- Weaken secure defaults (cookie `httpOnly`/`secure`/`sameSite`, `RS256`, PKCE/state/nonce) without explicit approval.

---

## Security Considerations

This is an OIDC Relying Party middleware; the following are auto-detected from the code and are non-negotiable defaults:

- **Flows & PKCE:** default `response_type` is `id_token` (Implicit with Form Post); the Authorization Code flow (`response_type` includes `code`) uses PKCE and state/nonce via `openid-client`. Do not disable state/nonce/PKCE checks.
- **ID token signing:** default `idTokenSigningAlg` is `RS256`; `none` is explicitly rejected in `lib/config.js`. HS* algorithms require a `clientSecret`.
- **Session cookies:** the app session is an encrypted cookie (`lib/appSession.js` + `lib/crypto.js`) with `httpOnly: true` by default, `secure` inferred from an HTTPS `baseURL`, and a configurable `sameSite`. A warning is emitted for insecure cookies over HTTPS.
- **Secrets:** the `secret` config drives cookie encryption; never log it or commit it. Examples read secrets from env (`examples/.env.sample`), never hard-code them.
- **Telemetry:** the `Auth0-Client` header is sent by default and user-disablable via `enableTelemetry: false` — never remove the opt-out or send unconditionally.

---

> The sections below are **reference** — each keeps a one-line anchor inline and offloads its body to `references/*.md` behind a linked pointer. Read a reference file only when your task needs it.

## Commands

```bash
npm run test        # unit tests (Mocha, safe — no credentials, HTTP is nocked)
npm run lint        # ESLint
```

See [references/commands.md](references/commands.md) for the full list (coverage, type tests, end-to-end, docs, example app). Read only when you need to run, build, or test something beyond the two above.

## Testing

Unit tests (`npm run test`, Mocha + Chai + Sinon) live in `test/` and are the safe default — no credentials, all HTTP stubbed with `nock`. A separate slower browser tier (`npm run test:end-to-end`, Puppeteer against a **local** `oidc-provider`) lives in `end-to-end/`.

See [references/testing.md](references/testing.md) for conventions, mocking, coverage, and the end-to-end tier. Read when writing or running tests.

## Code Style

CommonJS (`require`/`module.exports`). Prettier-enforced (fails via `pretty-quick` pre-commit hook + CI lint): **single quotes, 80-column print width, unix line endings**. ESLint flags unused vars as errors.

See [references/code-style.md](references/code-style.md) for naming, patterns, and good/bad examples. Read before writing non-trivial new code.

## Git Workflow

Branch off `master`; run `npm run test` and `npm run lint` before opening a PR against `master`. A `pretty-quick` pre-commit hook auto-formats staged files.

See [references/git-workflow.md](references/git-workflow.md) for full branch/commit/PR conventions. Read when preparing a commit or PR.

## Common Pitfalls

Top traps: HTTP in unit tests must be stubbed with `nock` (network is disabled in `test/setup.js`); `index.d.ts` is hand-written and drifts easily; `lib/context.js` is large and central.

See [references/pitfalls.md](references/pitfalls.md) for the full list with fixes. Read when debugging unexpected behavior.

## Docs Update Rules

Treat docs as a first-class deliverable: a PR that changes a config option, the public API, or an integration pattern is not complete until `README.md` / `EXAMPLES.md` (and any affected `examples/` app) are updated in the same PR.

See [references/docs-update.md](references/docs-update.md) for the tracked-docs inventory and the code-to-docs mapping. Read when changing public API, config, or examples.

# Code Style

## Enforced tooling

- **Prettier** (`.prettierrc`): `singleQuote: true`, `printWidth: 80`. Enforced by a `pretty-quick --staged` pre-commit hook (husky) and by CI lint.
- **ESLint** (`eslint.config.js`, flat config on `@eslint/js` recommended): `no-unused-vars` is an **error** (args checked after-used, rest siblings ignored), `linebreak-style` is unix (error), `no-useless-escape` is a warning, `no-console` is off. `CHANGELOG.md`, `docs/`, `coverage/`, `.nyc_output/`, `node_modules/` are ignored.

## Naming & module conventions

- **CommonJS everywhere:** `const x = require('...')` and `module.exports = { ... }`. No ESM `import`/`export` in the library source.
- Files are camelCase matching their primary export (`appSession.js`, `transientHandler.js`, `requiresAuth.js`).
- `camelCase` for functions/variables, `PascalCase` for classes/error types (`SessionExpiredError`).
- Middleware factories are functions that return an Express `(req, res, next)` handler.

## Patterns used here

- **Config-schema-as-contract:** all public options are declared and defaulted in a `joi` schema (`lib/config.js`). Add new options there with a validation rule and a sensible secure default — don't read raw config elsewhere.
- **Typed errors:** throw the project's error types (e.g. `SessionExpiredError` in `lib/errors.js`, which carries `code`/`status`), and `http-errors` for HTTP responses, rather than bare `Error`.
- **Custom fetch wrapper:** outbound OIDC HTTP goes through `createCustomFetch` (`lib/client.js`), which injects the `User-Agent` and (opt-out via `enableTelemetry: false`) `Auth0-Client` headers.

## Examples

**✅ Good** — CommonJS, single quotes, typed error, schema-driven option:

```javascript
const createHttpError = require('http-errors');

function requiresAuth(req, res, next) {
  if (!req.oidc.isAuthenticated()) {
    return next(createHttpError(401, 'Authentication required'));
  }
  next();
}

module.exports = requiresAuth;
```

**❌ Bad** — ESM, double quotes, bare `Error`, magic config read:

```javascript
export function requiresAuth(req, res, next) {          // no ESM in this repo
  if (!req.oidc.isAuthenticated()) {
    throw new Error("Authentication required");          // use http-errors / typed errors; double quotes fail Prettier
  }
  const ttl = process.env.SESSION_TTL || 86400;          // options belong in the lib/config.js Joi schema
  next();
}
```

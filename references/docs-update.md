# Docs Update Rules

Treat documentation as a first-class deliverable. A PR that adds or changes public API, config options, or integration patterns is **not complete** until the relevant docs are updated in the same PR.

## Tracked docs

| Doc | Covers | Status |
|-----|--------|--------|
| `README.md` | Install, requirements, getting started, configuration, API reference links | present |
| `EXAMPLES.md` | Runnable code samples and integration patterns (proxy, PAR, backchannel logout, custom stores, etc.) | present |
| `examples/` | Standalone runnable example apps exercised by the end-to-end tests | present |

> Not tracked here: `CHANGELOG.md` (cut by the release process, not agent-edited), and the migration guides (`V2_MIGRATION_GUIDE.md`, `V3_MIGRATION_GUIDE.md`) — their filenames are version-specific and the right one is inferred from the branch when a breaking change is made. `FAQ.md` / `TROUBLESHOOTING.md` / `ARCHITECTURE.md` exist for context but aren't part of the code-to-docs contract.

## When you change code, update these docs

This is a library/SDK; the public surface is the exported functions (`index.js`) and the config options (`lib/config.js` Joi schema).

| When this changes | Update these docs |
|-------------------|-------------------|
| A config option added, removed, renamed, or its default changed (`lib/config.js`) | `README.md` (configuration), `EXAMPLES.md` (affected samples), `index.d.ts` (types) |
| Public export added/removed/renamed (`index.js`: `auth`, `requiresAuth`, `attemptSilentLogin`, `SessionExpiredError`) | `README.md` (API reference / usage), `EXAMPLES.md`, `index.d.ts` |
| Authentication / session / logout flow behavior | `README.md` (getting started), `EXAMPLES.md` (auth/logout examples) |
| Install requirements / supported Node versions (`engines`) | `README.md` (requirements / install) |
| A new integration pattern supported | `EXAMPLES.md` (add an example) + an app under `examples/` if it warrants a runnable demo |
| An `examples/` app's demonstrated API changes | the matching `examples/*.js` app and its `end-to-end/*.test.js` |

> When you touch code that maps to a doc above, update that doc **in the same PR** — do not defer.

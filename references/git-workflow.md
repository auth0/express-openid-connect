# Git Workflow

## Branches

- Default/base branch is `master`. Branch off `master` for changes.
- No branch-name linting is enforced; use a short descriptive name (e.g. `fix/session-cookie-samesite`).

## Before you commit

- A husky `pre-commit` hook runs `pretty-quick --staged`, auto-formatting staged files with Prettier.
- Run the checks CI enforces: `npm run test` (unit), `npm run lint`, and — for type or example changes — `npm run test:types` / `npm run test:end-to-end`.

## Commits & PRs

- No commitlint/Conventional-Commits enforcement is configured; write clear, imperative commit subjects. (The maintained `CHANGELOG.md` is produced by the release process — don't hand-edit it in feature PRs.)
- There is no PR template; see `CONTRIBUTING.md` and Auth0's [general contributing guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md).
- Open PRs against `master`. CI (`.github/workflows/test.yml`) must pass: build, unit tests on Node 20/22/24, type tests, end-to-end, and lint. Security workflows (CodeQL, Snyk, rl-secure) also run.
- `CODEOWNERS` governs required reviewers.

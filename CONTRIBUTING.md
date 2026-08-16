# Contributing

Thanks for your interest. This project is designed so a first-time contributor
can land a small, reviewable change quickly.

## Ground rules

- **Evidence stays honest.** This repo standardizes utility & security for Pi
  Web3. Every schema, weight, and signature scheme must stay reproducible.
  Never commit a number you did not measure. A missing runtime writes an honest
  note — never a fake pass.
- **Tests stay offline.** New schemas, hooks, and protocol logic ship with
  tests that run without network or API keys.
- **Small PRs.** One logical change per pull request.
- **Schema-driven.** A change to the protocol touches the manifest standards
  (`MANIFEST_STANDARDS.md`, `PEP_PROTOCOL.md`, `pi-manifest.json`), the schema
  validation tests, and the docs. Changes that break the published schema are
  not accepted without a migration note.

## Getting started

1. Fork and clone.
2. `npm install`.
3. `npm test` — the schema and signature suites must stay green.

## First contribution in 6 steps

1. Pick an open issue (labels: `good first issue`, `good first contribution`,
   `help wanted`, `documentation`).
2. Read the [code of conduct](CODE_OF_CONDUCT.md) and this guide.
3. Run `npm test` and keep it green.
4. Run the linter clean if you touch TypeScript.
5. Open your pull request (use the [PR template](.github/PULL_REQUEST_TEMPLATE.md)).
6. Get reviewed — then your name goes on the contributor wall.

## Pull requests

- Add or update a test with every change.
- Keep `npm test` green — it is the single acceptance command and it runs in CI.
- Update `CHANGELOG.md` with your change.
- Link the issue your PR closes.

## Labels you can grab

- `good first issue` / `good first contribution` — small, well-scoped.
- `help wanted` — maintainers would like contributions.
- `documentation` — docs-only, great starting point.
- `protocol` / `schema` / `sdk` — feature-area work.

## Code of conduct

Be respectful and constructive. See `CODE_OF_CONDUCT.md`.

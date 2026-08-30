# Contributing to Norinth

## Repository layout

| Zone | Path | License |
|---|---|---|
| Open SDK | `packages/python-sdk/` | Apache-2.0 |
| Platform | `apps/platform/` | Apache-2.0 |

The SDK and Platform meet only at the wire protocol
(`packages/python-sdk/PROTOCOL.md`). Do not add cross-imports between them.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
make dev-install      # installs runtime + dev deps + pre-commit
make test             # run the test suite
make lint             # ruff
make run              # run the platform on :8001
```

## Pull request standards

- **Scope one concern per PR.** Describe what it changes and why in the PR
  description.
- **Every behavior change ships with a test.** Security fixes add a regression
  test that fails on `main` and passes on the branch.
- **CI must be green**: ruff lint, SPDX license headers, `pytest` (SQLite and PostgreSQL), and the frontend `vitest` + `tsc` build are required checks.
- **Every source file carries an SPDX header.** New `.py`, `.ts`, and `.tsx`
  files under `apps/`, `packages/`, and `scripts/` start with the Apache-2.0
  SPDX header and the Revenant Research copyright line. This keeps ownership
  attached to each file on redistribution (License Section 4(c)). Add missing
  headers with `python3 scripts/check_license_headers.py --fix`.
- Frontend components get a `*.test.tsx` beside them (`make test-frontend`).
- Never commit the compiled dashboard (`apps/platform/app/dashboard/static/` is
  git-ignored). CI builds it from source, checks the platform serves it, and the
  Docker image builds it in its own stage. Locally: `make build-frontend`.
- **Never commit** secrets, `.env`, databases, `node_modules`, or virtualenvs
  (all git-ignored). `check-added-large-files` and `detect-private-key`
  pre-commit hooks guard this.

## Commit messages

Conventional Commits (`fix:`, `feat:`, `chore:`, `docs:`, `refactor:`, `test:`).

## Releasing

A release is a tag; `release.yml` does the rest (image + cosign + SBOM, Helm
chart, SDK, GitHub Release):

1. Move the `[Unreleased]` changelog section under `## [X.Y.Z] - <date>` — the
   workflow extracts that section as the release notes.
2. Bump `packages/python-sdk/pyproject.toml` `version` and
   `deploy/helm/norinth/Chart.yaml` `version`/`appVersion` to `X.Y.Z`. The SDK
   job **fails the release if the pyproject version doesn't match the tag**.
3. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.

**PyPI (one-time setup).** The SDK job publishes `norinth-logger` to PyPI via
[trusted publishing](https://docs.pypi.org/trusted-publishers/) — no API token
is stored anywhere. Until it's configured, the job still builds the wheel and
attaches it to the GitHub Release. To turn publishing on:

1. On pypi.org, create/claim the `norinth-logger` project and add a **trusted
   publisher**: owner `revenant-research`, repository `norinth`, workflow
   `release.yml`, environment `pypi`.
2. In this repo's settings, create an environment named `pypi` (optionally with
   required reviewers — that makes every PyPI publish a manual approval).
3. Set the repository **variable** `PYPI_PUBLISH=true`.

The next `v*` tag publishes to PyPI with PEP 740 attestations.

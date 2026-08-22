# Contributing to Norinth

## Repository layout

| Zone | Path | License |
|---|---|---|
| Open SDK | `packages/python-sdk/` | Apache-2.0 |
| Platform | `apps/platform/` | Proprietary |
| Demo apps | `demo-apps/` | Apache-2.0 |

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

- **Scope one concern per PR.** Reference the finding it addresses from
  `AUDIT_AND_ROADMAP_2026.md` (e.g. "C-1", "H-9") in the PR description.
- **Every behavior change ships with a test.** Security fixes add a regression
  test that fails on `main` and passes on the branch.
- **CI must be green**: ruff lint and `pytest` are required checks.
- **Never commit** secrets, `.env`, databases, `node_modules`, or virtualenvs
  (all git-ignored). `check-added-large-files` and `detect-private-key`
  pre-commit hooks guard this.

## Commit messages

Conventional Commits (`fix:`, `feat:`, `chore:`, `docs:`, `refactor:`, `test:`).

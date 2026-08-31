## What this changes

<!-- One concern per pull request. Say what changes and why. -->

## Why

<!-- The problem this solves. Link the issue if there is one. -->

## Checklist

- [ ] One concern only
- [ ] Behavior changes ship with a test. Security fixes add a regression test that fails on `main`
- [ ] New `.py`, `.ts` and `.tsx` files carry the SPDX header (`python3 scripts/check_license_headers.py --fix`)
- [ ] No secrets, `.env` files, databases, `node_modules`, virtualenvs, or the compiled dashboard bundle
- [ ] Docs updated if behavior, configuration or the wire protocol changed
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if a user would notice this

## Security impact

<!-- Say "none" if there is none. Otherwise: what an attacker could do before
     and after, and which control stops them. Do not report an undisclosed
     vulnerability here. Use the private advisory form linked in SECURITY.md. -->

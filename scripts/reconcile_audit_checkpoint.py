#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""Reconcile a retained checkpoint journal after an authorized database restore."""

from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from app.storage.audit import reconcile_audit_after_restore  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reason", required=True, help="Backup identifier and authorized restore reason")
    parser.add_argument("--expected-seal", required=True, help="Final checkpoint seal observed before restore")
    args = parser.parse_args()
    result = reconcile_audit_after_restore(reason=args.reason, expected_seal=args.expected_seal)
    print(f"Reconciled audit epoch: {result['checkpoint_status']}, entries={result['entries']}")


if __name__ == "__main__":
    main()

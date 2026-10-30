"""Disposable credential containment drill; never connects to a real service."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import asdict, dataclass


class RangeCredentialStore:
    """One synthetic identity, scoped to this process; stores only token digests."""

    def __init__(self) -> None:
        self._active: set[bytes] = set()

    @staticmethod
    def _digest(token: str) -> bytes:
        return hashlib.sha256(token.encode()).digest()

    def issue(self) -> str:
        token = "bantis-drill-" + secrets.token_urlsafe(32)
        self._active.add(self._digest(token))
        return token

    def authenticate(self, token: str) -> bool:
        digest = self._digest(token)
        return any(hmac.compare_digest(digest, active) for active in self._active)

    def revoke(self, token: str) -> None:
        # Idempotent; a retry cannot restore the burned credential.
        self._active.discard(self._digest(token))


@dataclass(frozen=True)
class DrillResult:
    mode: str
    dry_run: bool
    verified: bool
    old_accepted_before: bool | None = None
    old_rejected_after: bool | None = None
    replacement_accepted: bool | None = None


def run_drill(mode: str, *, execute: bool = False) -> DrillResult:
    if mode not in {"rotate", "revoke"}:
        raise ValueError("mode must be rotate or revoke")
    if os.environ.get("BANTIS_ENV") != "range-local":
        raise ValueError("BANTIS_ENV must be range-local")
    if not execute:
        return DrillResult(mode=mode, dry_run=True, verified=False)

    store = RangeCredentialStore()
    leaked = store.issue()
    before = store.authenticate(leaked)
    if not before:
        raise RuntimeError("baseline authentication failed")
    replacement = None
    replacement_ok = None
    if mode == "rotate":
        replacement = store.issue()
        replacement_ok = store.authenticate(replacement)
        if replacement == leaked or not replacement_ok:
            raise RuntimeError("replacement verification failed")
    store.revoke(leaked)
    rejected = not store.authenticate(leaked)
    if replacement is not None:
        replacement_ok = store.authenticate(replacement)
    if not rejected or replacement_ok is False:
        raise RuntimeError("containment verification failed")
    return DrillResult(mode, False, True, before, rejected, replacement_ok)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("rotate", "revoke"))
    parser.add_argument("--execute", action="store_true", help="Execute in-memory simulation")
    args = parser.parse_args(argv)
    try:
        result = run_drill(args.mode, execute=args.execute)
    except (ValueError, RuntimeError):
        # Never echo backend exceptions, which could contain credential material.
        print(json.dumps({"source": "range-credential-drill", "status": "error"}))
        return 1
    print(json.dumps({"source": "range-credential-drill", **asdict(result)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
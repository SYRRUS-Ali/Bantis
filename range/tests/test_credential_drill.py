"""Standalone stdlib tests: no range services, repository writes, or real credentials."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

_SPEC = importlib.util.spec_from_file_location(
    "credential_drill", Path(__file__).resolve().parents[1] / "scripts/credential_drill.py"
)
drill = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = drill
_SPEC.loader.exec_module(drill)


class CredentialDrillTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"BANTIS_ENV": "range-local"})
        env.start()
        self.addCleanup(env.stop)

    def test_guard_rejects_every_non_range_environment(self):
        for value in ("", "production", "range"):
            with patch.dict(os.environ, {"BANTIS_ENV": value}):
                with self.assertRaises(ValueError):
                    drill.run_drill("rotate", execute=True)

    def test_dry_run_never_creates_credentials(self):
        with patch.object(drill, "RangeCredentialStore") as store:
            result = drill.run_drill("rotate")
        store.assert_not_called()
        self.assertTrue(result.dry_run)
        self.assertFalse(result.verified)

    def test_rotate_proves_old_rejected_and_new_accepted(self):
        result = drill.run_drill("rotate", execute=True)
        self.assertTrue(result.verified)
        self.assertTrue(result.old_accepted_before)
        self.assertTrue(result.old_rejected_after)
        self.assertTrue(result.replacement_accepted)

    def test_revoke_does_not_issue_replacement(self):
        result = drill.run_drill("revoke", execute=True)
        self.assertTrue(result.verified)
        self.assertTrue(result.old_rejected_after)
        self.assertIsNone(result.replacement_accepted)

    def test_revoke_is_idempotent_and_does_not_revoke_other_identity(self):
        store = drill.RangeCredentialStore()
        leaked, other = store.issue(), store.issue()
        store.revoke(leaked)
        store.revoke(leaked)
        self.assertFalse(store.authenticate(leaked))
        self.assertTrue(store.authenticate(other))
        self.assertFalse(store.authenticate("unknown"))

    def test_failed_revocation_fails_verification(self):
        with patch.object(drill.RangeCredentialStore, "revoke"):
            with self.assertRaises(RuntimeError):
                drill.run_drill("rotate", execute=True)

    def test_failed_replacement_does_not_revoke_leaked_value(self):
        with patch.object(drill.RangeCredentialStore, "authenticate", side_effect=[True, False]):
            with patch.object(drill.RangeCredentialStore, "revoke") as revoke:
                with self.assertRaises(RuntimeError):
                    drill.run_drill("rotate", execute=True)
                revoke.assert_not_called()

    def test_output_contains_no_credential(self):
        with patch.object(drill.secrets, "token_urlsafe", side_effect=["LEAKED", "NEW"]):
            with patch("builtins.print") as output:
                self.assertEqual(drill.main(["rotate", "--execute"]), 0)
        line = output.call_args.args[0]
        self.assertTrue(json.loads(line)["verified"])
        self.assertNotIn("LEAKED", line)
        self.assertNotIn("NEW", line)

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            drill.run_drill("arbitrary", execute=True)


if __name__ == "__main__":
    unittest.main()
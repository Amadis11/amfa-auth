"""Guard the signed offline refill path while transaction boundaries evolve.

A previous stale draft of the concurrency fix removed the signed-batch
format, full HOTP replacement window and WebAuthn UV policy. Pure Ed25519
crypto tests did not see it because they never entered /validate/offlinerefill.
This is a source-contract guard, not a substitute for live signed API tests.

After the v3.14.1 base was laid down, the refill token check, the batch
issuance and the refill-secret rotation moved into `MachineApplication.refill()`
(one row lock, one commit). The handler calls that single entry point, so the
comparison needles are guarded in `offline.py` while the response shape stays
guarded in `validate.py`.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
VALIDATE = (ROOT / "privacyidea/api/validate.py").read_text(encoding="utf8")
OFFLINE = (ROOT / "privacyidea/lib/applications/offline.py").read_text(encoding="utf8")


def signed_refill_violations(source: str, offline_source: str = OFFLINE) -> list[str]:
    start = source.find("@validate_blueprint.route('/offlinerefill'")
    end = source.find("\ndef _challenge_owner(", start)
    if start < 0 or end <= start:
        return ["offline refill handler is absent"]
    handler = source[start:end]
    expected = {
        "signed-batch envelope": 'signed_auth_items({"offline": [refill_item]})',
        "signed-mode full HOTP window": "if signing_enabled() and token.type.lower() == \"hotp\":",
        "signed WebAuthn/Passkey UV policy": "get_user_verification_requirement(",
        "no-commit counter for full window": "token, otp_pin, requested - len(otps), rounds, atomic=True)",
        "no-commit atomic refill": "MachineApplication.refill(token, password, refilltoken_request, options,",
        "non-committing refill secret rotation": "commit_db_session=False",
        "post-lock ORM TokenInfo expiry": 'db.session.expire(token.token, ["info_list"])',
        "WebAuthn signed refill must not commit early": "user_verification=uv_policy, commit_db_session=False)",
        "failed-refill rollback": "db.session.rollback()",
    }
    # Refill secret handling lives in the single locked entry point now.
    expected_refill = {
        "bearer token constant-time comparison": "safe_compare(stored, refilltoken)",
        "empty stored bearer token rejected": "if not stored or not safe_compare(stored, refilltoken):",
    }
    violations = [name for name, needle in expected.items() if needle not in handler]
    violations += [name for name, needle in expected_refill.items() if needle not in offline_source]
    sign = handler.find('signed_auth_items({"offline": [refill_item]})')
    commit = handler.rfind("db.session.commit()")
    if sign >= 0 and commit >= 0 and commit < sign:
        violations.append("the transaction committed before the signed batch was constructed")
    if commit < 0:
        violations.append("missing explicit atomic commit")
    return violations


class SignedRefillHandlerContractTests(unittest.TestCase):
    def test_signed_offline_handler_keeps_full_batch_and_atomic_rotation(self):
        self.assertEqual(signed_refill_violations(VALIDATE), [])

    def test_negative_control_rejects_empty_stored_refilltoken(self):
        safe = "if not stored or not safe_compare(stored, refilltoken):"
        broken = OFFLINE.replace(safe, "if not stored:")
        self.assertNotEqual(broken, OFFLINE)
        self.assertIn("empty stored bearer token rejected", signed_refill_violations(VALIDATE, broken))

    def test_negative_control_rejects_timing_unsafe_bearer_comparison(self):
        safe = "safe_compare(stored, refilltoken)"
        broken = OFFLINE.replace(safe, "stored == refilltoken")
        self.assertNotEqual(broken, OFFLINE)
        self.assertIn("bearer token constant-time comparison", signed_refill_violations(VALIDATE, broken))

    def test_negative_control_requires_rollback_before_error_masking(self):
        original = "db.session.rollback()"
        broken = VALIDATE.replace(original, "pass")
        self.assertNotEqual(broken, VALIDATE)
        self.assertIn("failed-refill rollback", signed_refill_violations(broken))

    def test_negative_control_catches_early_webauthn_serializer_commit(self):
        original = "user_verification=uv_policy, commit_db_session=False)"
        broken = VALIDATE.replace(original, "user_verification=uv_policy)")
        self.assertNotEqual(broken, VALIDATE, "the negative mutation must change real source")
        self.assertIn("WebAuthn signed refill must not commit early", signed_refill_violations(broken))

    def test_negative_control_catches_stale_unsigned_refill_implementation(self):
        broken = VALIDATE.replace(
            'signed_auth_items({"offline": [refill_item]})',
            '{"offline": [refill_item]}',
        )
        self.assertNotEqual(broken, VALIDATE, "the negative mutation must change real source")
        self.assertIn("signed-batch envelope", signed_refill_violations(broken))

    def test_negative_control_catches_partial_window_or_early_commit(self):
        broken = VALIDATE.replace(
            "token, otp_pin, requested - len(otps), rounds, atomic=True)",
            "token, otp_pin, requested - len(otps), rounds)",
        )
        self.assertNotEqual(broken, VALIDATE)
        self.assertIn("no-commit counter for full window", signed_refill_violations(broken))

    def test_negative_control_catches_removed_locked_refill_entry(self):
        broken = VALIDATE.replace(
            "MachineApplication.refill(token, password, refilltoken_request, options,",
            "MachineApplication.get_offline_otps(token, password, options,",
        )
        self.assertNotEqual(broken, VALIDATE)
        self.assertIn("no-commit atomic refill", signed_refill_violations(broken))


if __name__ == "__main__":
    unittest.main()

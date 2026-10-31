"""Guard the signed offline refill path while transaction boundaries evolve.

A previous stale draft of the concurrency fix removed the signed-batch
format, full HOTP replacement window and WebAuthn UV policy. Pure Ed25519
crypto tests did not see it because they never entered /validate/offlinerefill.
This is a source-contract guard, not a substitute for live signed API tests.
"""
from pathlib import Path
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "privacyidea/api/validate.py").read_text(encoding="utf8")


def signed_refill_violations(source: str) -> list[str]:
    start = source.find("@validate_blueprint.route('/offlinerefill'")
    end = source.find("\ndef _conditional_access_identity():", start)
    if start < 0 or end <= start:
        return ["offline refill handler is absent"]
    handler = source[start:end]
    expected = {
        "signed-batch envelope": 'signed_auth_items({"offline": [refill_item]})',
        "signed-mode full HOTP window": "if signing_enabled() and token.type.lower() == \"hotp\":",
        "signed WebAuthn/Passkey UV policy": "get_user_verification_requirement(",
        "no-commit counter for full window": "token, otp_pin, requested - len(otps), rounds, atomic=True)",
        "no-commit atomic refill": "MachineApplication.get_refill(token, password, options, atomic=True)",
        "non-committing refill secret rotation": "commit_db_session=False",
        "post-lock ORM TokenInfo expiry": 'db.session.expire(token.token, ["info_list"])',
        "WebAuthn signed refill must not commit early": "user_verification=uv_policy, commit_db_session=False)",
        "bearer token constant-time comparison": "secrets.compare_digest(refilltoken_stored, refilltoken_request)",
        "empty stored bearer token rejected": "bool(refilltoken_stored) and isinstance(refilltoken_stored, str)",
        "failed-refill rollback": "except Exception as e:\n        db.session.rollback()",
    }
    violations = [name for name, needle in expected.items() if needle not in handler]
    sign = handler.find('signed_auth_items({"offline": [refill_item]})')
    commit = handler.rfind("db.session.commit()")
    if sign >= 0 and commit >= 0 and commit < sign:
        violations.append("the transaction committed before the signed batch was constructed")
    if commit < 0:
        violations.append("missing explicit atomic commit")
    return violations


class SignedRefillHandlerContractTests(unittest.TestCase):
    def test_signed_offline_handler_keeps_full_batch_and_atomic_rotation(self):
        self.assertEqual(signed_refill_violations(SOURCE), [])

    def test_negative_control_rejects_empty_stored_refilltoken(self):
        safe = "bool(refilltoken_stored) and isinstance(refilltoken_stored, str)"
        broken = SOURCE.replace(safe, "isinstance(refilltoken_stored, str)")
        self.assertNotEqual(broken, SOURCE)
        self.assertIn("empty stored bearer token rejected", signed_refill_violations(broken))

    def test_negative_control_rejects_timing_unsafe_bearer_comparison(self):
        safe = "secrets.compare_digest(refilltoken_stored, refilltoken_request)"
        broken = SOURCE.replace(safe, "refilltoken_stored == refilltoken_request")
        self.assertNotEqual(broken, SOURCE)
        self.assertIn("bearer token constant-time comparison", signed_refill_violations(broken))

    def test_negative_control_requires_rollback_before_error_masking(self):
        original = "except Exception as e:\n        db.session.rollback()"
        broken = SOURCE.replace(original, "except Exception as e:")
        self.assertNotEqual(broken, SOURCE)
        self.assertIn("failed-refill rollback", signed_refill_violations(broken))

    def test_negative_control_catches_early_webauthn_serializer_commit(self):
        original = "user_verification=uv_policy, commit_db_session=False)"
        broken = SOURCE.replace(original, "user_verification=uv_policy)")
        self.assertNotEqual(broken, SOURCE, "the negative mutation must change real source")
        self.assertIn("WebAuthn signed refill must not commit early", signed_refill_violations(broken))

    def test_negative_control_catches_stale_unsigned_refill_implementation(self):
        broken = SOURCE.replace(
            'signed_auth_items({"offline": [refill_item]})',
            '{"offline": [refill_item]}',
        )
        self.assertNotEqual(broken, SOURCE, "the negative mutation must change real source")
        self.assertIn("signed-batch envelope", signed_refill_violations(broken))

    def test_negative_control_catches_partial_window_or_early_commit(self):
        broken = SOURCE.replace(
            "token, otp_pin, requested - len(otps), rounds, atomic=True)",
            "token, otp_pin, requested - len(otps), rounds)",
        )
        self.assertNotEqual(broken, SOURCE)
        self.assertIn("no-commit counter for full window", signed_refill_violations(broken))


if __name__ == "__main__":
    unittest.main()

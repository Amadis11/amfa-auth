"""AMFA offline issuance must reject excessive work before generating OTPs."""
import unittest
from unittest.mock import Mock

from privacyidea.lib.applications.offline import MachineApplication, _validate_otp_generation_work
from privacyidea.lib.error import ParameterError, ValidateError


class OfflineWorkLimitTests(unittest.TestCase):
    def test_invalid_batch_sizes_are_rejected_before_accessing_token(self):
        token = Mock()
        for amount in (-1, 1025, 10**9, 1.5, "100"):
            with self.subTest(amount=amount), self.assertRaises(ParameterError):
                MachineApplication.get_offline_otps(token, "", amount, 1)
        token.get_multi_otp.assert_not_called()

    def test_empty_or_boolean_batch_count_does_not_produce_a_fake_reservation(self):
        token = Mock()
        self.assertEqual(MachineApplication.get_offline_otps(token, "", 0, 1), {})
        for amount in (True, False):
            with self.subTest(amount=amount), self.assertRaises(ParameterError):
                MachineApplication.get_offline_otps(token, "", amount, 1)
        token.get_multi_otp.assert_not_called()
        token.inc_otp_counter.assert_not_called()

    def test_combined_hash_cost_is_limited_before_any_token_access(self):
        token = Mock()
        for amount, rounds in ((1024, 100000), (101, 100000), (1024, 10000)):
            with self.subTest(amount=amount, rounds=rounds), self.assertRaises(ParameterError):
                MachineApplication.get_offline_otps(token, "", amount, rounds, atomic=True)
        token.get_multi_otp.assert_not_called()
        token.inc_otp_counter.assert_not_called()
        # Default production hash cost must still allow the maximum batch.
        _validate_otp_generation_work(1024, 6549)
        _validate_otp_generation_work(100, 100000)

    def test_failed_or_short_hotp_generation_never_reserves_counters(self):
        for success, otps in ((False, {}), (True, {25: "123456"})):
            token = Mock()
            token.get_multi_otp.return_value = (success, "incomplete", {"otp": otps})
            with self.subTest(success=success), self.assertRaises(ValidateError):
                MachineApplication.get_offline_otps(token, "PIN", 3, 1, atomic=True)
            token.inc_otp_counter.assert_not_called()

    def test_expensive_refill_is_rejected_before_password_verification(self):
        token = Mock()
        token.type = "hotp"
        with self.assertRaises(ParameterError):
            MachineApplication.get_refill(token, "PIN123456",
                                          {"count": 1024, "rounds": 100000}, atomic=True)
        token.split_pin_pass.assert_not_called()

    def test_expensive_first_issuance_is_rejected_before_database_lock(self):
        token = Mock()
        with self.assertRaises(ParameterError):
            MachineApplication._reserve_initial_hotp_bundle(token, "", 1024, 100000)
        token.check_all.assert_not_called()
        token.get_tokeninfo.assert_not_called()

    def test_invalid_hash_costs_are_rejected_before_accessing_token(self):
        token = Mock()
        for rounds in (0, -1, 100001, 10**9, 1.5, "6549"):
            with self.subTest(rounds=rounds), self.assertRaises(ParameterError):
                MachineApplication.get_offline_otps(token, "", 2, rounds)
        token.get_multi_otp.assert_not_called()


    def test_refill_rejects_excessive_window_before_hotp_verification(self):
        token = Mock()
        token.type = "hotp"
        for count in (-1, 0, 1025, 10**9):
            with self.subTest(count=count), self.assertRaises(ParameterError):
                MachineApplication.get_refill(token, "PIN123456", {"count": count, "rounds": 1}, atomic=True)
        token.split_pin_pass.assert_not_called()

    def test_refill_rejects_excessive_hash_cost_before_hotp_verification(self):
        token = Mock()
        token.type = "hotp"
        for rounds in (0, -1, 100001, 10**9):
            with self.subTest(rounds=rounds), self.assertRaises(ParameterError):
                MachineApplication.get_refill(token, "PIN123456", {"count": 3, "rounds": rounds}, atomic=True)
        token.split_pin_pass.assert_not_called()


if __name__ == "__main__":
    unittest.main()

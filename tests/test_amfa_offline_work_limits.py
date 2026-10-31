"""AMFA offline issuance must reject excessive work before generating OTPs."""
import unittest
from unittest.mock import Mock

from privacyidea.lib.applications.offline import MachineApplication
from privacyidea.lib.error import ParameterError


class OfflineWorkLimitTests(unittest.TestCase):
    def test_invalid_batch_sizes_are_rejected_before_accessing_token(self):
        token = Mock()
        for amount in (-1, 1025, 10**9, 1.5, "100"):
            with self.subTest(amount=amount), self.assertRaises(ParameterError):
                MachineApplication.get_offline_otps(token, "", amount, 1)
        token.get_multi_otp.assert_not_called()

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

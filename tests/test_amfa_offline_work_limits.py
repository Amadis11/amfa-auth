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


if __name__ == "__main__":
    unittest.main()

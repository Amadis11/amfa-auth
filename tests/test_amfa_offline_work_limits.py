"""AMFA offline issuance must reject excessive work before generating OTPs.

Po nalozeniu podstawy v3.14.1 refill ma jedno wejscie — `MachineApplication.refill()`,
ktore pod zamkiem wiersza sprawdza refilltoken, wydaje partie i rotuje zapas. Walidacja
okna (`count`) i kosztu PBKDF2 (`rounds`) siedzi w nim PRZED weryfikacja hasla, wiec
zadanie z kosztownymi parametrami nie placi za porownanie hasla ani za liczenie OTP.
"""
from __future__ import annotations

import pathlib
import re
import unittest
from unittest.mock import Mock

from privacyidea.lib.applications.offline import MachineApplication, _validate_otp_generation_work
from privacyidea.lib.error import ParameterError, ValidateError

OFFLINE = (pathlib.Path(__file__).resolve().parents[1]
           / "privacyidea" / "lib" / "applications" / "offline.py").read_text(encoding="utf-8")


def _cialo(nazwa: str) -> str:
    """Cialo metody najwyzszego poziomu — do nastepnego `def ` na poczatku linii."""
    start = OFFLINE.index(f"def {nazwa}(")
    dalej = OFFLINE[start + 1:]
    nastepna = re.search(r"\n    def |\ndef ", dalej)
    return OFFLINE[start:start + 1 + (nastepna.start() if nastepna else len(dalej))]


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

    def test_invalid_windows_and_hash_costs_are_refused(self):
        """Okno i koszt PBKDF2 poza zakresem musza byc odrzucone, zanim cokolwiek policzymy."""
        for count, rounds in ((-1, 1), (0, 1), (1025, 1), (10**9, 1), (3, 0), (3, -1),
                              (3, 100001), (3, 10**9), (1024, 100000)):
            with self.subTest(count=count, rounds=rounds), self.assertRaises(ParameterError):
                _validate_otp_generation_work(count, rounds)
        # Normalna partia (1024 x 6549) musi przejsc, inaczej zablokowalibysmy wydawanie.
        _validate_otp_generation_work(1024, 6549)

    def test_refill_validates_window_and_hash_cost_before_password_verification(self):
        """`refill` musi odrzucic okno i koszt PBKDF2 PRZED weryfikacja hasla (audyt 20.11.2026, #1156)."""
        cialo = _cialo("refill")
        i_okno = cialo.find("Invalid offline refill window")
        i_koszt = cialo.find("Invalid offline refill PBKDF2 rounds")
        i_praca = cialo.find("_validate_otp_generation_work(count, rounds)")
        i_haslo = cialo.find("token.split_pin_pass(password)")
        for nazwa, indeks in (("okno", i_okno), ("koszt", i_koszt), ("praca", i_praca), ("haslo", i_haslo)):
            self.assertGreater(indeks, 0, f"brak sprawdzenia {nazwa} w `refill`")
        self.assertLess(i_okno, i_koszt, "okno musi byc sprawdzone przed kosztem")
        self.assertLess(i_koszt, i_praca, "koszt musi byc sprawdzony przed praca PBKDF2")
        self.assertLess(i_praca, i_haslo, "praca musi byc ograniczona PRZED weryfikacja hasla")

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


if __name__ == "__main__":
    unittest.main()

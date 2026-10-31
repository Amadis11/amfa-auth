"""Straznicy zmian AMFA — krok 13, refilltoken stabilny miedzy logowaniami (audyt 26.10.2026, plaster 04, Z4).

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka. Patrz AMFA-ZMIANY.md.

Po co ten straznik: `offline_info` (wolane przy KAZDYM udanym `/validate/check`, ktore wydaje ladunek
offline) bezwarunkowo wolalo `generate_new_refilltoken`, a to **nadpisuje** zapisany refilltoken.
Klient, ktory zapisal pierwsza partie i nie zapisal drugiej (dwa kafle tego samego konta, dwa
rownolegle kroki), trzymal refilltoken, ktorym nie mogl dociagnac zapasu (`ERR905`) — i nie mial
zadnego sygnalu, ze jest martwy.

Poprawka: refilltoken powstaje **raz** (`existing_or_new_refilltoken`), a odnawia go **wylacznie**
udany refill (`generate_new_refilltoken` w `offlinerefill`). Ten plik pilnuje obu stron tej umowy:
gdyby ktos wrocil do rotacji przy logowaniu albo usunal rotacje przy refillu, jeden z przypadkow
czerwienieje.

**Granica:** to straznik ksztaltu zrodla (kto wola co i w jakiej kolejnosci), nie pomiar zachowania
na zywym silniku.
"""
from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
OFFLINE = ROOT / "privacyidea" / "lib" / "applications" / "offline.py"
VALIDATE = ROOT / "privacyidea" / "api" / "validate.py"

ROTATE = "generate_new_refilltoken("
STABLE = "existing_or_new_refilltoken("
REUSE_FIRST = "existing_refilltoken("


def cialo_funkcji(text: str, nazwa: str) -> str:
    """Cialo funkcji/metody najwyzszego poziomu — do nastepnego `def ` na poczatku linii."""
    start = text.index(f"def {nazwa}(")
    dalej = text[start + 1:]
    nastepna = re.search(r"\n    def |\ndef ", dalej)
    return text[start:start + 1 + (nastepna.start() if nastepna else len(dalej))]


def problemy(offline_text: str, validate_text: str) -> list[str]:
    """Reguly kroku 13. Funkcja czysta — kontrole negatywne dzialaja na kopiach w pamieci."""
    wynik: list[str] = []
    try:
        cialo_logowania = cialo_funkcji(offline_text, "get_authentication_item")
    except ValueError:
        return ["brak `get_authentication_item` — regula nie ma czego pilnowac"]
    if ROTATE in cialo_logowania:
        wynik.append("`get_authentication_item` woluje `generate_new_refilltoken` — rotacja przy logowaniu wrocila (Z4)")
    if STABLE not in cialo_logowania:
        wynik.append("`get_authentication_item` nie wola `existing_or_new_refilltoken`")
    try:
        stabilny = cialo_funkcji(offline_text, "existing_or_new_refilltoken")
    except ValueError:
        wynik.append("brak `existing_or_new_refilltoken` — refilltoken nie ma sciezki stabilnej")
        stabilny = ""
    if stabilny:
        i_reuse = stabilny.find(REUSE_FIRST)
        i_rotate = stabilny.find(ROTATE)
        if i_reuse < 0:
            wynik.append("`existing_or_new_refilltoken` nie czyta zapisanego tokenu — nadpisywalby przy kazdym logowaniu")
        if i_rotate < 0:
            wynik.append("`existing_or_new_refilltoken` nie ma sciezki zalozenia tokenu (pierwsze logowanie)")
        if i_reuse >= 0 and i_rotate >= 0 and i_rotate < i_reuse:
            wynik.append("zalozenie tokenu stoi PRZED odczytem zapisanego — kolejnosc jest istota poprawki")
    try:
        refill = cialo_funkcji(validate_text, "offlinerefill")
        if ROTATE not in refill:
            wynik.append("`offlinerefill` nie rotuje refilltokenu — zapas przestalby sie odnawiac")
    except ValueError:
        wynik.append("brak `offlinerefill` w `validate.py`")
    return wynik


class StableRefillTokenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.offline = OFFLINE.read_text(encoding="utf-8")
        self.validate = VALIDATE.read_text(encoding="utf-8")

    def test_login_does_not_rotate_and_refill_does(self) -> None:
        self.assertEqual(problemy(self.offline, self.validate), [])

    def test_negative_control_when_login_rotates_again(self) -> None:
        zlamane = self.offline.replace(
            'ret["refilltoken"] = MachineApplication.existing_or_new_refilltoken(token, user_agent)',
            'ret["refilltoken"] = MachineApplication.generate_new_refilltoken(token, user_agent)',
        )
        self.assertNotEqual(problemy(zlamane, self.validate), [], "regula musi zapalic sie po powrocie rotacji")

    def test_negative_control_when_reuse_is_removed(self) -> None:
        # The production path now performs its own locked TokenInfo read.
        # The existing-refill path is retained for token-shaped test doubles;
        # mutate that actual call, not an obsolete indentation template.
        zlamane, replacements = re.subn(
            r"(?m)^\s*istniejacy = MachineApplication\.existing_refilltoken\(token, user_agent\)\s*$",
            "",
            self.offline,
        )
        self.assertEqual(replacements, 1, "the regression test must actually change the source")
        self.assertNotEqual(problemy(zlamane, self.validate), [], "regula musi zapalic sie bez odczytu zapisanego")

    def test_negative_control_when_refill_stops_rotating(self) -> None:
        # W PR #85 nowy token jest zapisywany w jednej transakcji, wiec
        # wywolanie ma argument commit_db_session=False i moze byc wieloliniowe.
        # Kontrola negatywna musi naprawde dokonac mutacji, inaczej jest
        # pozornie zielona i nie chroni przed usunieciem rotacji.
        zlamane, replacements = re.subn(
            r"(refilltoken_new\s*=\s*MachineApplication\.)generate_new_refilltoken\s*\(",
            r"\1existing_refilltoken(",
            self.validate,
        )
        self.assertEqual(replacements, 1, "nie znaleziono wywolania rotacji do celowej mutacji")
        self.assertNotEqual(problemy(self.offline, zlamane), [], "regula musi zapalic sie bez rotacji przy refillu")


if __name__ == "__main__":
    unittest.main(verbosity=2)

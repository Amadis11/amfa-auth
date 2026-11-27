"""Straznicy zmian AMFA — krok 13, refilltoken stabilny miedzy logowaniami (audyt 26.10.2026, plaster 04, Z4).

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka. Patrz AMFA-ZMIANY.md.

Po co ten straznik: `offline_info` (wolane przy KAZDYM udanym `/validate/check`, ktore wydaje ladunek
offline) bezwarunkowo wolalo `generate_new_refilltoken`, a to **nadpisuje** zapisany refilltoken.
Klient, ktory zapisal pierwsza partie i nie zapisal drugiej (dwa kafle tego samego konta, dwa
rownolegle kroki), trzymal refilltoken, ktorym nie mogl dociagnac zapasu (`ERR905`) — i nie mial
zadnego sygnalu, ze jest martwy.

Poprawka: refilltoken powstaje **raz** (`existing_or_new_refilltoken`), a odnawia go **wylacznie**
udany refill. Ten plik pilnuje obu stron tej umowy: gdyby ktos wrocil do rotacji przy logowaniu
albo usunal rotacje przy refillu, jeden z przypadkow czerwienieje.

**Zmiana po nalozeniu podstawy v3.14.1:** rotacja przeniosla sie z `offlinerefill` do
`MachineApplication.refill()` — podstawa przejela nasze utwardzenie i wykonuje porownanie
refilltokenu, wydanie partii i rotacje pod jednym zamkiem wiersza. `offlinerefill` wola wiec
`MachineApplication.refill(...)`, a sam zapis nowego refilltokenu (`geturandom(REFILLTOKEN_LENGTH`)
siedzi w `offline.py`. Straznik pilnuje obu koncow tej drogi.

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
# Jedno wejscie refillu po nalozeniu podstawy: porownanie, wydanie partii i rotacja pod zamkiem.
REFILL_ENTRY = "MachineApplication.refill("
# Zapis nowego refilltokenu wewnatrz `refill` (podstawa) — bez niego zapas przestalby sie odnawiac.
ROTACJA_W_REFILL = "geturandom(REFILLTOKEN_LENGTH"


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
        cialo_refillu = cialo_funkcji(offline_text, "refill")
        if ROTACJA_W_REFILL not in cialo_refillu:
            wynik.append("`refill` nie zapisuje nowego refilltokenu — zapas przestalby sie odnawiac")
    except ValueError:
        wynik.append("brak `refill` w `offline.py` — nie ma gdzie rotowac refilltokenu")
    try:
        refill = cialo_funkcji(validate_text, "offlinerefill")
        if REFILL_ENTRY not in refill:
            wynik.append("`offlinerefill` nie wola `MachineApplication.refill` — refill nie rotowalby refilltokenu")
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
        zlamane, replacements = re.subn(
            r'ret\["refilltoken"\]\s*=\s*MachineApplication\.existing_or_new_refilltoken\s*\('
            r'\s*token,\s*user_agent(?:,\s*commit_db_session=commit_db_session)?\s*\)',
            'ret["refilltoken"] = MachineApplication.generate_new_refilltoken('
            'token, user_agent, commit_db_session=commit_db_session)',
            self.offline,
        )
        self.assertEqual(replacements, 1, "regresja musi faktycznie zamienic istniejace wywolanie")
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
        # Podstawa wykonuje rotacje wewnatrz `MachineApplication.refill`; kontrola negatywna
        # podmienia to wejscie na wydanie kodow bez rotacji, wiec zapas przestalby sie odnawiac.
        zlamane, replacements = re.subn(
            r"MachineApplication\.refill\(",
            "MachineApplication.get_offline_otps(",
            self.validate,
        )
        self.assertEqual(replacements, 1, "nie znaleziono wywolania refillu do celowej mutacji")
        self.assertNotEqual(problemy(self.offline, zlamane), [], "regula musi zapalic sie bez rotacji przy refillu")

    def test_negative_control_when_refill_writes_no_new_token(self) -> None:
        # Druga strona umowy: samo wejscie zostaje, ale `refill` przestaje zapisywac nowy token.
        cialo = cialo_funkcji(self.offline, "refill")
        zlamane_cialo, replacements = re.subn(
            re.escape("new_refilltoken = geturandom(REFILLTOKEN_LENGTH, hex=True)"),
            "new_refilltoken = stored",
            cialo,
        )
        self.assertEqual(replacements, 1, "nie znaleziono zapisu nowego refilltokenu do celowej mutacji")
        zlamane = self.offline.replace(cialo, zlamane_cialo, 1)
        self.assertNotEqual(zlamane, self.offline, "mutacja musi trafic w cialo `refill`")
        self.assertNotEqual(problemy(zlamane, self.validate), [], "regula musi zapalic sie bez zapisu nowego tokenu")


if __name__ == "__main__":
    unittest.main(verbosity=2)

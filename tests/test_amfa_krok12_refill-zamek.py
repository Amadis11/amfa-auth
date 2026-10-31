"""Straznicy zmian AMFA — krok 12, refill offline pod zamkiem (audyt 26.10.2026, plaster 04, Z5).

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych zmian
na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Po co ten straznik: `/validate/offlinerefill` czytal zapisany `refilltoken`, wydawal partie
(`get_refill` -> `get_multi_otp`, ktore czyta licznik, wydaje kody i go inkrementuje) i rotowal
token — **bez zamka i bez transakcji z `FOR UPDATE`**. Dwa rownolegle zadania z tym samym
`refilltokenem` mogly przejsc oba i wydac dwa zestawy kodow o pokrywajacych sie licznikach. Zamek
(`with_for_update` na wierszu tokenu) plus `db.session.refresh` po nim zamyka te luke.

**Granica tego pliku:** to straznik **ksztaltu zrodla** — pilnuje, ze zamek jest na miejscu i stoi
przed odczytem zapisanego `refilltokenu`. Nie mierzy wyscigu: prawdziwy pomiar wymaga dwoch
polaczen do PostgreSQL i dwoch rownoleglych zadan, a harness linii chodzi na SQLite, gdzie
`FOR UPDATE` jest ignorowane. Zielone tutaj znaczy „zamek nie zniknal", a nie „wyscig zmierzony".

Uruchamianie w drzewie privacyIDEA:
    .venv/bin/python tests/test_amfa_krok12_refill-zamek.py      # bez pytest, kod 0/1
    .venv/bin/python -m pytest tests/test_amfa_krok12_refill-zamek.py -q
"""
from __future__ import annotations

import pathlib
import re
import unittest

VALIDATE = pathlib.Path(__file__).resolve().parents[1] / "privacyidea" / "api" / "validate.py"

LOCK = "with_for_update()"
REFRESH = "db.session.refresh(token.token)"
STORE_READ = 'token.get_tokeninfo("refilltoken")'


def zrodlo() -> str:
    return VALIDATE.read_text(encoding="utf-8")


def cialo_funkcji(text: str, nazwa: str) -> str:
    """Cialo funkcji najwyzszego poziomu — do nastepnego `def ` na poczatku linii."""
    start = text.index(f"def {nazwa}(")
    dalej = text[start + 1:]
    nastepna = re.search(r"\ndef ", dalej)
    return text[start:start + 1 + (nastepna.start() if nastepna else len(dalej))]


def problemy(text: str) -> list[str]:
    """Reguly kroku 12. Funkcja czysta, zeby kontrole negatywne mogly dzialac na kopii w pamieci."""
    try:
        cialo = cialo_funkcji(text, "offlinerefill")
    except ValueError:
        return ["brak funkcji `offlinerefill` — regula nie ma czego pilnowac"]
    wynik: list[str] = []
    i_lock = cialo.find(LOCK)
    i_refresh = cialo.find(REFRESH)
    i_read = cialo.find(STORE_READ)
    i_validity = cialo.find("if not token.check_all(message_list):")
    if i_read < 0:
        wynik.append("w offlinerefill nie ma odczytu `refilltoken` — sprawdz, czy trasa nie zostala przepisana")
    if i_lock < 0:
        wynik.append("offlinerefill nie bierze zamka na wierszu tokenu (`with_for_update`)")
    if i_refresh < 0:
        wynik.append("po zamku nie ma `db.session.refresh(token.token)` — porownanie widzialoby stary refilltoken")
    if i_lock >= 0 and i_read >= 0 and i_lock > i_read:
        wynik.append("zamek stoi PO odczytaniu zapisanego refilltokenu — kolejnosc jest istota poprawki")
    if i_lock >= 0 and i_refresh >= 0 and i_refresh < i_lock:
        wynik.append("`refresh` stoi przed zamkiem — odswiezenie musi byc pod zamkiem")
    if i_validity < 0 or i_lock < 0 or i_refresh < 0 or not (i_lock < i_refresh < i_validity):
        wynik.append("check_all() musi sprawdzac token odswiezony pod zamkiem, przed refill")
    return wynik


class RefillLockTests(unittest.TestCase):
    def test_handler_is_still_the_offlinerefill_we_know(self) -> None:
        self.assertIn(STORE_READ, cialo_funkcji(zrodlo(), "offlinerefill"))

    def test_refill_takes_the_lock_before_reading_the_stored_refilltoken(self) -> None:
        self.assertEqual(problemy(zrodlo()), [])

    def test_negative_control_without_the_lock(self) -> None:
        zlamane = zrodlo().replace(
            "db.session.execute(select(Token.id).where(Token.serial == serial).with_for_update()).first()", ""
        )
        self.assertNotEqual(problemy(zlamane), [], "regula musi zapalic sie po zdjeciu zamka")

    def test_negative_control_validity_checked_before_lock(self) -> None:
        source = zrodlo()
        section = cialo_funkcji(source, "offlinerefill")
        snippet = (
            "        message_list = []\\n"
            "        if not token.check_all(message_list):\\n"
            "            log.info(f\\\"Failed to offline refill: {message_list}\\\")\\n"
            "            raise ParameterError(_(\\\"The token is not valid.\\\"))\\n"
        )
        self.assertIn(snippet, section)
        moved = section.replace(snippet, "", 1).replace(
            "        db.session.execute(select(Token.id).where(Token.serial == serial).with_for_update()).first()",
            snippet + "        db.session.execute(select(Token.id).where(Token.serial == serial).with_for_update()).first()",
            1,
        )
        self.assertIn(
            "check_all() musi sprawdzac token odswiezony pod zamkiem, przed refill",
            problemy(moved),
        )

    def test_negative_control_without_the_refresh(self) -> None:
        zlamane = zrodlo().replace(REFRESH, "")
        self.assertNotEqual(problemy(zlamane), [], "regula musi zapalic sie po zdjeciu odswiezenia")

    def test_negative_control_with_the_lock_after_the_read(self) -> None:
        linia_zamka = (
            "db.session.execute(select(Token.id).where(Token.serial == serial).with_for_update()).first()"
        )
        cialo = cialo_funkcji(zrodlo(), "offlinerefill")
        # zamek przeniesiony ZA pierwszy odczyt zapisanego refilltokenu — kolejnosc jest istota poprawki
        przestawione = cialo.replace(linia_zamka, "", 1).replace(
            STORE_READ, STORE_READ + "\n            " + linia_zamka, 1
        )
        self.assertNotEqual(problemy(przestawione), [], "regula musi zapalic sie przy zlej kolejnosci")


if __name__ == "__main__":
    unittest.main(verbosity=2)

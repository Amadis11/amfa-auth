"""Straznicy zmian AMFA — krok 12, refill offline pod zamkiem (audyt 26.10.2026, plaster 04, Z5).

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych zmian
na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Po co ten straznik: `/validate/offlinerefill` czytal zapisany `refilltoken`, wydawal partie
(`get_refill` -> `get_multi_otp`, ktore czyta licznik, wydaje kody i go inkrementuje) i rotowal
token — **bez zamka i bez transakcji z `FOR UPDATE`**. Dwa rownolegle zadania z tym samym
`refilltokenem` mogly przejsc oba i wydac dwa zestawy kodow o pokrywajacych sie licznikach. Zamek
(`with_for_update` na wierszu tokenu) plus `db.session.refresh` po nim zamyka te luke.

**Zmiana po nalozeniu podstawy v3.14.1:** podstawa przejela to utwardzenie i przeniosla odczyt
zapisanego refilltokenu oraz rotacje do `MachineApplication.refill()`. Handler bierze zamek na
wierszu tokenu, sprawdza waznosc pod zamkiem, a `refill()` dokłada zamek na wierszu TokenInfo
i dopiero pod nim czyta i porownuje zapisany refilltoken. Straznik pilnuje obu miejsc.

**Granica tego pliku:** to straznik **ksztaltu zrodla** — pilnuje, ze zamek jest na miejscu i stoi
przed odczytem zapisanego `refilltokenu`. Nie mierzy wyscigu: prawdziwy pomiar wymaga dwoch
polaczen do PostgreSQL i dwoch rownoleglych zadan, a harness linii chodzi na SQLite, gdzie
`FOR UPDATE` jest ignorowane. Zielone tutaj znaczy „zamek nie zniknal\", a nie „wyscig zmierzony\".

Uruchamianie w drzewie privacyIDEA:
    .venv/bin/python tests/test_amfa_krok12_refill-zamek.py      # bez pytest, kod 0/1
    .venv/bin/python -m pytest tests/test_amfa_krok12_refill-zamek.py -q
"""
from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
VALIDATE = ROOT / "privacyidea" / "api" / "validate.py"
OFFLINE = ROOT / "privacyidea" / "lib" / "applications" / "offline.py"

LOCK = "with_for_update()"
LOCK_TOKEN_ROW = "lock_token_row(Token.id == token_id)"
REFRESH = "db.session.refresh(token.token)"
STORE_READ = "db.session.execute(select(TokenInfo.Value)"
COMPARE = "safe_compare(stored, refilltoken)"


def zrodlo() -> str:
    return VALIDATE.read_text(encoding="utf-8")


def zrodlo_offline() -> str:
    return OFFLINE.read_text(encoding="utf-8")


def cialo_funkcji(text: str, nazwa: str) -> str:
    """Cialo funkcji/metody najwyzszego poziomu — do nastepnego `def ` na poczatku linii."""
    start = text.index(f"def {nazwa}(")
    dalej = text[start + 1:]
    nastepna = re.search(r"\n    def |\ndef ", dalej)
    return text[start:start + 1 + (nastepna.start() if nastepna else len(dalej))]


def problemy(text: str, offline_text: str | None = None) -> list[str]:
    """Reguly kroku 12. Funkcja czysta, zeby kontrole negatywne mogly dzialac na kopii w pamieci."""
    offline_text = zrodlo_offline() if offline_text is None else offline_text
    try:
        cialo = cialo_funkcji(text, "offlinerefill")
    except ValueError:
        return ["brak funkcji `offlinerefill` — regula nie ma czego pilnowac"]
    wynik: list[str] = []
    i_lock = cialo.find(LOCK)
    i_refresh = cialo.find(REFRESH)
    i_validity = cialo.find("if not token.check_all(message_list):")
    if i_lock < 0:
        wynik.append("offlinerefill nie bierze zamka na wierszu tokenu (`with_for_update`)")
    if i_refresh < 0:
        wynik.append("po zamku nie ma `db.session.refresh(token.token)` — porownanie widzialoby stary refilltoken")
    if i_lock >= 0 and i_refresh >= 0 and i_refresh < i_lock:
        wynik.append("`refresh` stoi przed zamkiem — odswiezenie musi byc pod zamkiem")
    if i_validity < 0 or i_lock < 0 or i_refresh < 0 or not (i_lock < i_refresh < i_validity):
        wynik.append("check_all() musi sprawdzac token odswiezony pod zamkiem, przed refill")
    # Druga strona: odczyt zapisanego refilltokenu i jego porownanie zyja w `refill()`.
    try:
        cialo_refillu = cialo_funkcji(offline_text, "refill")
    except ValueError:
        wynik.append("brak `refill` w `offline.py` — nie ma gdzie porownac zapisanego refilltokenu")
        return wynik
    i_zamek_wiersza = cialo_refillu.find(LOCK_TOKEN_ROW)
    i_odczyt = cialo_refillu.find(STORE_READ)
    i_lock_info = cialo_refillu.find(LOCK, i_odczyt if i_odczyt >= 0 else 0)
    i_porownanie = cialo_refillu.find(COMPARE)
    if i_zamek_wiersza < 0:
        wynik.append("`refill` nie bierze zamka na wierszu tokenu przed odczytem zapisanego refilltokenu")
    if i_odczyt < 0:
        wynik.append("`refill` nie czyta zapisanego refilltokenu — sprawdz, czy sciezka nie zostala przepisana")
    elif i_lock_info < 0:
        wynik.append("odczyt zapisanego refilltokenu w `refill` nie jest odczytem blokujacym (`with_for_update`)")
    if i_porownanie < 0:
        wynik.append("`refill` nie porownuje zapisanego refilltokenu (`safe_compare`)")
    if i_odczyt >= 0 and i_porownanie >= 0 and i_porownanie < i_odczyt:
        wynik.append("porownanie stoi PRZED odczytem zapisanego refilltokenu")
    return wynik


class RefillLockTests(unittest.TestCase):
    def test_handler_is_still_the_offlinerefill_we_know(self) -> None:
        cialo = cialo_funkcji(zrodlo(), "offlinerefill")
        self.assertIn("MachineApplication.refill(", cialo)
        self.assertIn(LOCK, cialo)

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
        # Insert a premature validity check before the lock. The guard must
        # detect it even if the correct check still exists later on.
        lock = "db.session.execute(select(Token.id).where(Token.serial == serial).with_for_update()).first()"
        self.assertIn(lock, section)
        moved = source.replace(lock, "if not token.check_all(message_list): " + lock, 1)
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
            "MachineApplication.refill(", linia_zamka + "\n            MachineApplication.refill(", 1
        )
        self.assertNotEqual(problemy(przestawione), [], "regula musi zapalic sie przy zlej kolejnosci")

    def test_negative_control_without_the_locking_read_in_refill(self) -> None:
        offline = zrodlo_offline()
        zlamane = offline.replace(
            ".where(TokenInfo.token_id == token_id, TokenInfo.Key == key)\n                                    .with_for_update()",
            ".where(TokenInfo.token_id == token_id, TokenInfo.Key == key)",
        )
        self.assertNotEqual(zlamane, offline, "kontrola negatywna musi naprawde zmienic zrodlo")
        self.assertIn("odczyt zapisanego refilltokenu w `refill` nie jest odczytem blokujacym (`with_for_update`)",
                      problemy(zrodlo(), zlamane))


if __name__ == "__main__":
    unittest.main(verbosity=2)

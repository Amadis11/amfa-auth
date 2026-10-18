"""Straznicy zmian AMFA — krok 11, lokalizacje w katalogach tlumaczen.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych zmian na
nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Pilnowane: `<context-group purpose="location">` w `privacyidea/static/src/locale/messages*.xlf` musza
pochodzic z **podstawy**. Nocny automat podstawy (`webui-i18n-extract.yml`) uruchamia `npm run i18n:extract`
i commituje wynik na `chore/i18n-extract` — ekstrakcja wypisuje numery linii na nowo dla kazdej jednostki,
co doklada ok. 1,4 tys. linii roznicy nie bedacych tlumaczeniami. Po scaleniu takiego PR-a uruchamia sie
`amfa/restore-translation-locations.py`; ten strażnik nie pozwala o tym zapomniec.

Gdy galaz podstawy nie jest dostepna (np. plytkie klonowanie w CI), strażnik mowi wprost, ze **nie mogl
ocenic** — zamiast udawac zielony werdykt.

Uruchamianie w drzewie privacyIDEA:
    python -m pytest tests/test_amfa_krok11_lokalizacje-w-katalogu.py -q
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

KORZEN = pathlib.Path(__file__).resolve().parents[1]
NARZEDZIE = KORZEN / "amfa" / "restore-translation-locations.py"


def _uruchom(*argumenty: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(NARZEDZIE), *argumenty],
                          cwd=KORZEN, capture_output=True, text=True)


def test_narzedzie_do_lokalizacji_jest_w_linii() -> None:
    assert NARZEDZIE.is_file(), "brak amfa/restore-translation-locations.py — czym przywracac lokalizacje?"
    tresc = NARZEDZIE.read_text(encoding="utf-8")
    # Narzedzie musi umiec pracowac w trybie kontroli, inaczej nie da sie go uzyc w CI.
    assert "--check" in tresc, "narzedzie nie ma trybu --check"


def test_lokalizacje_w_katalogach_pochodza_z_podstawy() -> None:
    wynik = _uruchom("--check")
    if "brak pliku w podstawie" in wynik.stdout:
        # Nie udajemy zielonego: bez podstawy strażnik nie ma czego porownywac.
        print("POMINIETO: brak galezi podstawy w tym klonie — lokalizacje nieocenione")
        return
    assert wynik.returncode == 0, (f"katalogi maja lokalizacje spoza podstawy — uruchom "
                                   f"`python3 amfa/restore-translation-locations.py`:\n{wynik.stdout}")


def test_narzedzie_wykrywa_obce_lokalizacje() -> None:
    """Kontrola negatywna: wstrzykniety defekt (przesuniety numer linii) musi dac werdykt czerwony.

    Wstrzykniecie zamiast czekania na prawdziwy rozjazd: strażnik ma udowodnic, ze umie zobaczyc obca
    lokalizacje, a nie tylko ze teraz jest zielono.
    """
    plik = KORZEN / "privacyidea" / "static" / "src" / "locale" / "messages.xlf"
    oryginal = plik.read_text(encoding="utf-8")
    podmiana = re.sub(r'(<context context-type="linenumber">)(\d+)',
                      lambda m: m.group(1) + str(int(m.group(2)) + 1000), oryginal, count=1)
    assert podmiana != oryginal, "nie udalo sie wstrzyknac defektu do messages.xlf"
    try:
        plik.write_text(podmiana, encoding="utf-8")
        wynik = _uruchom("--check")
    finally:
        plik.write_text(oryginal, encoding="utf-8")
    assert wynik.returncode != 0, ("kontrola negatywna nie dziala: narzedzie nie zauwazylo "
                                   f"lokalizacji spoza podstawy:\n{wynik.stdout}")


if __name__ == "__main__":
    # Bez pytest (na wezlach go nie ma) uruchamiamy wszystkie strażniki i konczymy kodem wyjscia.
    _bledy = 0
    for _nazwa, _funkcja in sorted(globals().items()):
        if _nazwa.startswith("test_") and callable(_funkcja):
            try:
                _funkcja()
                print(f"OK   {_nazwa}")
            except Exception as _blad:            # takze brak zaleznosci: straznik nie mogl ruszyc
                _bledy += 1
                print(f"FAIL {_nazwa}: {type(_blad).__name__}: {_blad}")
    sys.exit(1 if _bledy else 0)

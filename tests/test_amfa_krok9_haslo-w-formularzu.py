"""Straznicy zmian AMFA — krok 9, haslo w formularzu (`/validate/check`).

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Uruchamianie w drzewie privacyIDEA:
    python -m pytest tests/test_amfa_krok9_haslo-w-formularzu.py -q
    python tests/test_amfa_krok9_haslo-w-formularzu.py            # bez pytest, wlasny runner nizej
"""
from __future__ import annotations

import pathlib

KORZEN = pathlib.Path(__file__).resolve().parents[1]

#: Nazwa klienta, ktora wysyla nasz dostawca poswiadczen (`amfa-cp/<wersja> Windows/<maszyna>`).
UA_DOSTAWCY = "amfa-cp/1.0.0 Windows/PC-LAB"

#: Haslo ze znakami, ktore w formularzu maja znaczenie skladniowe: procent, rownosc, plus (spacja),
#: ampersand (rozdziela pola) i sama spacja.
HASLO_TRUDNE = "a%b=c+d&e f"


def _parametry(ua: str | None, body) -> dict:
    """Wartosci, ktore silnik widzi dla ciala zadania — ta sama droga co `/validate/check`."""
    import sys
    sys.path.insert(0, str(KORZEN))
    from flask import Flask, request

    from privacyidea.api.lib.utils import get_all_params

    naglowki = {"User-Agent": ua} if ua else {}
    aplikacja = Flask(__name__)
    with aplikacja.test_request_context("/validate/check", method="POST", data=body,
                                        content_type="application/x-www-form-urlencoded",
                                        headers=naglowki):
        return get_all_params(request)


def test_haslo_dostawcy_dochodzi_znak_w_znak() -> None:
    """Poprawnie zakodowane haslo dostawcy musi dojsc znak w znak (zgloszenie #35).

    Objaw z labu: to samo haslo przez JSON dzialalo, a przez `application/x-www-form-urlencoded`
    konczylo sie `wrong otp pin`, czyli haslo wygladalo na bledne. Przyczyna byla po stronie silnika:
    wartosci formularza byly odkodowywane **po raz drugi** (`check_unquote`), a lista wyjatkow nie
    znala nazwy naszego klienta. Dlatego `amfa-cp` jest na tej liscie i ten straznik tego pilnuje.
    """
    # Werkzeug koduje wartosci tak, jak powinien to robic klient (`%` -> `%25`, `+` -> `%2B`,
    # `&` -> `%26`, `=` -> `%3D`, spacja -> `+`).
    dane = _parametry(UA_DOSTAWCY, {"user": "amfa-test-ad", "pass": HASLO_TRUDNE})
    assert dane.get("pass") == HASLO_TRUDNE, \
        f"silnik nie odczytal hasla znak w znak: {dane.get('pass')!r} != {HASLO_TRUDNE!r}"
    assert dane.get("user") == "amfa-test-ad"

    # Sama spacja, procent, rownosc, plus i ampersand — kazde osobno tez musi przejsc nietkniete.
    for haslo in ("a b", "100%", "a=b", "a&b", "a+b", "a%25b"):
        assert _parametry(UA_DOSTAWCY, {"user": "amfa-test-ad", "pass": haslo}).get("pass") == haslo, haslo

    # Cialo zapisane recznie, tak jak leci w zadaniu dostawcy: `%` zakodowany jako `%25`.
    assert _parametry(UA_DOSTAWCY, b"user=amfa-test-ad&pass=a%2525b").get("pass") == "a%25b"


def test_bez_nazwy_dostawcy_silnik_nadal_odkodowuje_po_raz_drugi() -> None:
    """Poza naszym klientem zostaje stare zachowanie — i to jest swiadome (zgloszenie #35).

    `check_unquote` odkodowuje wartosci formularza po raz drugi dla klientow, ktorych nie ma na
    liscie wyjatkow (odklada sie tak klientow kodujacych podwojnie). Ten straznik opisuje granice
    naprawy: zmiana tego zachowania dla wszystkich klientow to osobna decyzja, a nie skutek uboczny
    naprawy naszego dostawcy.
    """
    # Klient bez nazwy: silnik odkodowuje po raz drugi, wiec `%25` zamienia sie w `%`.
    assert _parametry(None, b"user=amfa-test-ad&pass=a%2525b").get("pass") == "a%b"
    # Przegladarka: to samo, bo nazwy przegladarek nie ma na liscie wyjatkow.
    assert _parametry("Mozilla/5.0 (Windows NT 10.0)",
                      b"user=amfa-test-ad&pass=a%2525b").get("pass") == "a%b"


if __name__ == "__main__":
    # Bez pytest (na wezlach go nie ma) uruchamiamy wszystkie strazniki i konczymy kodem wyjscia.
    import sys as _sys

    _bledy = 0
    for _nazwa, _funkcja in sorted(globals().items()):
        if _nazwa.startswith("test_") and callable(_funkcja):
            try:
                _funkcja()
                print(f"OK   {_nazwa}")
            except Exception as _blad:            # takze brak zaleznosci: straznik nie mogl ruszyc
                _bledy += 1
                print(f"FAIL {_nazwa}: {type(_blad).__name__}: {_blad}")
    _sys.exit(1 if _bledy else 0)

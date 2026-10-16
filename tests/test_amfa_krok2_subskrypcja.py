"""Straznicy zmian AMFA — krok 2, licencja i licznik: wylaczone konfiguracja, nie wycinka kodu.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Zmiana wobec poprzedniej wersji tego straznika: licencja nie jest juz wycinana z kodu podstawy
(usuwanie modulow `subscriptions.py`, dekoratora `CheckSubscription` i okien w konsoli), a
**wylaczana ustawieniem** `PI_SUBSCRIPTION_ENFORCE = False`. Powod: wycinka to ~1 300 linii delty
i konflikt przy kazdym wydaniu, a wystarczy jedno miejsce w kodzie + wpis w konfiguracji wezla.
Straznik pilnuje wiec dwoch rzeczy: ze wylacznik dziala (bez bazy) i ze nie oslabia podstawy dla
instalacji, ktore go nie ustawiaja (domyslna wartosc `True`).

Uruchamianie w drzewie privacyIDEA:
    python -m pytest tests/test_amfa_krok2_subskrypcja.py -q
"""
from __future__ import annotations

import pathlib

KORZEN = pathlib.Path(__file__).resolve().parents[1]
SUBSC = KORZEN / "privacyidea" / "lib" / "subscriptions.py"

#: Sciezki, na ktorych podstawa wymusza prog (dekorator `CheckSubscription`).
SCIEZKI_WYMUSZANIA = (("privacyidea/api/validate.py", 2), ("privacyidea/api/token.py", 2))


def test_wylacznik_wstrzymuje_liczenie_i_wymuszanie() -> None:
    """Z wylaczonym liczeniem `subscription_status` mowi 0, a `check_subscription` nie odmawia.

    Bez bazy: przy wylaczonym wylaczniku obie funkcje koncza sie **przed** policzeniem tokenow,
    wiec straznik nie potrzebuje aplikacji ani danych.
    """
    from privacyidea.lib import subscriptions

    oryginalne = subscriptions.get_app_config_value
    subscriptions.get_app_config_value = lambda key, default=None: False
    try:
        assert subscriptions.subscription_status("privacyidea") == 0, \
            "z wylaczonym liczeniem status nie jest zerem (konsola mialaby co pokazywac)"
        assert subscriptions.check_subscription("privacyidea") is True, \
            "z wylaczonym liczeniem sprawdzenie nadal odmawia"
    finally:
        subscriptions.get_app_config_value = oryginalne


def test_wylacznik_domyka_sprawe_przed_policzeniem_tokenow() -> None:
    """Wyjscie musi byc przed liczeniem tokenow — inaczej licznik chodzi mimo wylaczenia."""
    zrodlo = SUBSC.read_text(encoding="utf-8")
    assert "if not subscription_enforced():" in zrodlo, "brak wylacznika w kodzie licznika"
    assert zrodlo.index("if not subscription_enforced():") < zrodlo.index("token_count = get_tokens("), \
        "wylacznik stoi za policzeniem tokenow"


def test_domyslna_wartosc_nie_oslabia_podstawy() -> None:
    """Instalacja bez naszego wpisu zachowuje sie jak podstawa (wylacznik domyslnie wlaczony)."""
    zrodlo = SUBSC.read_text(encoding="utf-8")
    assert 'get_app_config_value("PI_SUBSCRIPTION_ENFORCE", True)' in zrodlo, \
        "wylacznik jest domyslnie wylaczony — to zmienia zachowanie podstawy dla innych"
    assert "def subscription_enforced()" in zrodlo, "brak funkcji czytajacej wylacznik"


def test_sciezki_wymuszania_nadal_ida_przez_podstawe() -> None:
    """Logowanie i wydanie tokenu nadal przechodza przez sprawdzenie podstawy.

    Naszym zadaniem jest wylaczyc je **ustawieniem**, a nie usunac: gdyby dekorator zniknal,
    ten straznik ma zapalic sie w CI, bo wtedy znaczy to, ze nasza linia znowu wycina kod
    podstawy zamiast go konfigurowac.
    """
    for wzgledna, ile in SCIEZKI_WYMUSZANIA:
        tresc = (KORZEN / wzgledna).read_text(encoding="utf-8")
        assert tresc.count("@CheckSubscription(request)") == ile, \
            f"{wzgledna}: oczekiwano {ile} wpietych sprawdzen podstawy"


def test_konsola_podstawy_i_testy_zostaly() -> None:
    """Moduly konsoli i testy podstawy o licencji zostaja w linii (machanizm jest cudzy, dziala)."""
    for wzgledna in ("privacyidea/lib/subscriptions.py", "privacyidea/api/subscriptions.py",
                     "tests/test_lib_subscriptions.py", "tests/test_api_subscriptions.py"):
        assert (KORZEN / wzgledna).is_file(), f"brak {wzgledna} — wroc do wycinania kodu?"


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

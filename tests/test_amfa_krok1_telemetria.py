"""Straznicy zmian AMFA — krok 1, co silnik wola na zewnatrz.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Zmiana wobec poprzedniej wersji tego straznika: nie wycinamy juz kodu podstawy. Zadanie statystyk
(`lib/task/simplestats.py`) wrocilo, bo sprawdzenie kodu pokazalo, ze zapisuje **wylacznie** do
lokalnej tabeli `monitoringstats` (`write_stats`) i nic nie wysyla — usuniecie oznaczalo brak danych
do wykresow w konsoli bez zadnego zysku. Tak samo jak przy licencji: kod podstawy zostaje, a to, co
naprawde wychodzi na zewnatrz, nazywamy i wylaczamy **konfiguracja** (`PI_SUBSCRIPTION_VERSION_CHECK=False`,
polityka kanalow informacyjnych). Straznik pilnuje obu stron: ze zadania okresowe nie wysylaja nic
same z siebie i ze kazde wyjscie silnika ma wylacznik po stronie wdrozenia.

Uruchamianie w drzewie privacyIDEA:
    python -m pytest tests/test_amfa_krok1_telemetria.py -q
"""
from __future__ import annotations

import ast
import pathlib

KORZEN = pathlib.Path(__file__).resolve().parents[1]
TASKI = KORZEN / "privacyidea" / "lib" / "task"

#: Biblioteki, ktorymi mozna wyjsc na zewnatrz. Sprawdzamy importy (AST), nie tekst: naglowek
#: licencji kazdego pliku zawiera adres URL, wiec szukanie "http://" oskarzaloby plik o wysylke.
BIBLIOTEKI_SIECIOWE = {"requests", "urllib", "urllib2", "urllib3", "httpx", "http", "socket", "aiohttp",
                       # feedparser pobiera adresy URL sam (uzywane w kanalach informacyjnych)
                       "feedparser"}

#: Kazde wyjscie silnika — z opisem, dokad idzie. Nowe wyjscie bez wpisu tutaj jest bledem:
#: najpierw je nazywamy i wylaczamy, potem wydajemy.
WYJSCIA = {
    "privacyidea/lib/info/rss.py":
        "kanaly informacyjne podstawy (community.privacyidea.org, privacyidea.org, netknights.it); "
        "konsola pokazuje je jako sekcje News, a wylacza je polityka kanalow (SCOPE.WEBUI) u wdrazajacego",
    "privacyidea/lib/subscriptions.py":
        "odpytanie GitHuba o najnowsze wydania klientow (licencja); "
        "wylacza je PI_SUBSCRIPTION_VERSION_CHECK=False, u nas wpisywane przez generator env",
}


def _importy(plik: pathlib.Path) -> set[str]:
    """Nazwy importowanych modulow (najwyzszy czlon, bez importow wzglednych)."""
    moduly: set[str] = set()
    for wezel in ast.walk(ast.parse(plik.read_text(encoding="utf-8"))):
        if isinstance(wezel, ast.Import):
            moduly.update(alias.name.split(".")[0] for alias in wezel.names)
        elif isinstance(wezel, ast.ImportFrom) and wezel.level == 0 and wezel.module:
            moduly.add(wezel.module.split(".")[0])
    return moduly


def test_zadanie_statystyk_jest_i_liczy_lokalnie() -> None:
    """Zadanie statystyk zostaje w linii i nie wychodzi na zewnatrz.

    Bylo usuniete jako "telefon do domu" — kod mowi co innego: liczy i zapisuje do lokalnej tabeli
    `monitoringstats`. Gdyby ktos chcial je usunac z innego powodu (zbedne obciazenie), usunie je
    razem z tym straznikiem, ale nie pod pretekstem wysylki danych.
    """
    plik = TASKI / "simplestats.py"
    assert plik.is_file(), "brak zadania statystyk — usuniete bez powodu?"
    tresc = plik.read_text(encoding="utf-8")
    assert "write_stats" in tresc, "zadanie statystyk nie zapisuje lokalnie"
    sieciowe = _importy(plik) & BIBLIOTEKI_SIECIOWE
    assert not sieciowe, f"zadanie statystyk importuje biblioteke sieciowa: {sorted(sieciowe)}"

    okresowe = (KORZEN / "privacyidea" / "lib" / "periodictask.py").read_text(encoding="utf-8")
    assert "SimpleStatsTask" in okresowe, "zadanie statystyk nie jest zarejestrowane"
    zdefiniowane = {wezel.targets[0].id for wezel in ast.walk(ast.parse(okresowe))
                    if isinstance(wezel, ast.Assign) and isinstance(wezel.targets[0], ast.Name)}
    assert "TASK_CLASSES" in zdefiniowane and "TASK_MODULES" in zdefiniowane, \
        "wyjecie wpisu zadania zdjelo definicje listy zadan (realny blad z kroku 1)"


def test_zadania_okresowe_nie_wysylaja_nic_same() -> None:
    """Zadania okresowe chodza bez udzialu czlowieka, wiec zadne nie moze wychodzic na zewnatrz."""
    for plik in sorted(TASKI.glob("*.py")):
        sieciowe = _importy(plik) & BIBLIOTEKI_SIECIOWE
        assert not sieciowe, f"{plik.name}: zadanie okresowe wychodzi na zewnatrz ({sorted(sieciowe)})"


def test_kazde_wyjscie_ma_wpis_i_wylacznik() -> None:
    """Wyjscia silnika sa nazwane, a kazde ma sposob wylaczenia — inaczej nie wydajemy."""
    for wzgledna, opis in WYJSCIA.items():
        plik = KORZEN / wzgledna
        assert plik.is_file(), f"brak {wzgledna} — {opis}"
        assert _importy(plik) & BIBLIOTEKI_SIECIOWE, \
            f"{wzgledna}: nie widac juz wyjscia na zewnatrz ({opis}) — usun wpis albo popraw opis"

    rss = (KORZEN / "privacyidea" / "lib" / "info" / "rss.py").read_text(encoding="utf-8")
    assert "privacyidea.org/feed" in rss and "netknights.it" in rss, \
        "kanaly podstawy zniknely z kodu — sprawdz, dokad teraz idzie zapytanie"

    akcje = (KORZEN / "privacyidea" / "lib" / "policies" / "actions.py").read_text(encoding="utf-8")
    assert 'RSS_FEEDS = "rss_feeds"' in akcje and 'RSS_AGE = "rss_age"' in akcje, \
        "brak polityki na kanaly informacyjne — nie ma czym ich wylaczyc"

    subskrypcje = (KORZEN / "privacyidea" / "lib" / "subscriptions.py").read_text(encoding="utf-8")
    assert 'get_app_config_value("PI_SUBSCRIPTION_VERSION_CHECK", True)' in subskrypcje, \
        "brak wylacznika odpytania GitHuba"


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

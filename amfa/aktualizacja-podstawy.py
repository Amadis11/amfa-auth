#!/usr/bin/env python3
"""Automat wydan AMFA Auth — nakladanie naszych zmian na nowe wydanie privacyIDEA.

Uruchamiany przez .github/workflows/amfa-aktualizacja-podstawy.yml, ale dziala tez lokalnie:

    python3 amfa/aktualizacja-podstawy.py --sprawdz      # tylko raport, nic nie zmienia
    python3 amfa/aktualizacja-podstawy.py --przygotuj    # naklada nasze zmiany, testuje, buduje

Zasady (patrz AMFA-ZMIANY.md):
  - `master` to lustro podstawy i nigdy nie commitujemy tu naszych zmian,
  - `amfa` to nasza linia; nasze commity sa nakladane na nowy znacznik wydania podstawy,
  - konflikt konczy sie raportem z lista plikow — nigdy cichym pozostaniem na starej wersji,
  - **aktualizacja jest caloscia**: wydanie nowej linii konczy sie dopiero po zielonej weryfikacji
    calego lancucha (testy tego repozytorium, cala regresja bramy, przebieg na labie). Zgodnosc bramy
    z nowa linia potwierdzaja testy, a nie numer wydania wpisany w kodzie bramy — dlatego automat
    wydaje nowa linie bez recznej decyzji, a raport niesie liste kontrolna (`amfa/lista-kontrolna-wydania.md`).

Kody wyjscia:
  0 — brak aktualizacji albo wszystko przeszlo
  2 — jest nowe wydanie, ale naszych zmian nie dalo sie nalozyc (konflikt)
  3 — nasze zmiany nalozone, ale testy albo budowanie padly
  4 — blad wywolania (brak galezi, brak znacznikow)
"""
from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import sys

KORZEN = pathlib.Path(__file__).resolve().parents[1]
PLIK_PODSTAWY = KORZEN / "amfa" / "PODSTAWA"
NASZA_LINIA = "amfa"
LUSTRO = "master"
ZRODLO = "upstream"

#: Co musi byc zielone, zanim nowa linia podstawy jest wydana. Kolejnosc jest kolejnascia weryfikacji:
#: bez punktu o bramie wydanie trafia na lab nieprzetestowane, a objaw widac dopiero na logowaniu.
LISTA_KONTROLNA_WYDANIA = (
    "ten automat: nasze straznicy i testy podstawy zielone (w tym pliku sie nie da tego pominac)",
    "brama: CALA regresja bramy zielona (amitronic-amfa: python3 -m unittest discover -s tests/web/gateway)"
    " — brama nie trzyma listy wydan, zgodnosc z nowa linia potwierdzaja te testy",
    "brama na labie: przebieg na zywym srodowisku (components/amfa-ui: pnpm test:flow, 16/16)",
    "zaleznosci: /opt/privacyidea/bin/pip install --upgrade -r requirements.txt na kazdym wezle",
    "schemat: pi-manage db upgrade przy zatrzymanej usludze na WSZYSTKICH wezlach (nowa wersja przenosi dane)",
    "panel: zbudowany panel z tego pakietu (static/dist) — bez osobnego wgrywania",
    "wzorce: components/privacyidea/ sprawdzone wobec stanu na wezlach (realm, resolver, polityki)",
    "wdrozenie: kopie wstecz, stop, podmiana, start, weryfikacja i wpis w docs/status.md",
)

# Testy uruchamiane po nalozeniu na nowa podstawe. Nasze strazniki ida zawsze pierwsze,
# bo one mowia wprost, czy nasze zmiany nadal sa na miejscu.
#
# Wzorzec, nie lista: kazdy krok ma wlasny plik straznikow (`tests/test_amfa_krok*.py`), a bramka
# wydania ma uruchamiac **wszystkie**. Wpisany tu po nazwie plik latwo zostawic poza bramka — tak
# wlasnie zginal straznik brandu (krok 5), gdy powstal po kroku 4.
NASZE_STRAZNICY_WZORZEC = "tests/test_amfa_krok*.py"
TESTY_PODSTAWY = [
    "tests/test_api_validate.py",
    "tests/test_app.py",
    "tests/test_api_lib_policy.py",
    "tests/test_api_periodictask.py",
]


def nasze_strazniki(wzorzec: str = NASZE_STRAZNICY_WZORZEC) -> list[str]:
    """Pliki naszych straznikow. Brak chocby jednego zatrzymuje wydanie.

    Straznik, ktorego nie ma w drzewie, nie moze byc po cichu pominety: wtedy wydanie szloby dalej
    bez sprawdzenia tego kroku (pominiecie widac tylko jako linijke w raporcie).
    """
    znalezione = sorted(str(plik.relative_to(KORZEN)) for plik in KORZEN.glob(wzorzec))
    if not znalezione:
        raise RuntimeError(f"brak naszych straznikow ({wzorzec}) — nie wydajemy bez nich")
    return znalezione


def uruchom(*argumenty: str, sprawdz_kod: bool = True) -> subprocess.CompletedProcess:
    wynik = subprocess.run(argumenty, cwd=KORZEN, capture_output=True, text=True)
    if sprawdz_kod and wynik.returncode != 0:
        raise RuntimeError(f"{' '.join(argumenty)} zwrocilo {wynik.returncode}:\n"
                           f"{wynik.stdout}\n{wynik.stderr}")
    return wynik


def zapisz_podstawe(commit: str, znacznik: str | None) -> None:
    PLIK_PODSTAWY.write_text(
        "# Wersja podstawy, na ktorej stoi nasza linia.\n"
        "# Aktualizuje automat wydan (amfa/aktualizacja-podstawy.py) — nie edytowac recznie.\n"
        f"commit {commit}\n"
        f"tag {znacznik or '—'}\n",
        encoding="utf-8",
    )


def czytaj_podstawe() -> dict:
    if not PLIK_PODSTAWY.is_file():
        raise RuntimeError(f"brak pliku {PLIK_PODSTAWY.relative_to(KORZEN)} — nie wiem, na czym stoi nasza linia")
    dane = {}
    for linia in PLIK_PODSTAWY.read_text(encoding="utf-8").splitlines():
        if linia.startswith("#") or not linia.strip():
            continue
        klucz, _, wartosc = linia.partition(" ")
        dane[klucz.strip()] = wartosc.strip()
    return dane


#: Znacznik wydania podstawy: `v3.14`, `3.14`, `v3.14.1`. Wersje rozwojowe (`v3.14dev4`) nie sa wydaniem.
WZORZEC_WYDANIA = re.compile(r"v?(\d+\.\d+)(?:\.\d+)?")


def czy_wydanie(znacznik: str | None) -> bool:
    """Czy znacznik jest wydaniem podstawy (a nie wersja rozwojowa, np. `v3.14dev4`)."""
    return WZORZEC_WYDANIA.fullmatch((znacznik or "").strip()) is not None


def najnowszy_znacznik() -> tuple[str, str]:
    """Zwraca (znacznik, commit) najnowszego **wydania** podstawy wedlug numeracji wersji.

    Znaczniki rozwojowe (np. `v3.14dev4`) pomijamy: wydaniem jest dopiero `v3.14`/`v3.14.1`, a tylko
    wydanie jest tym, co chcemy miec na labie.
    """
    uruchom("git", "fetch", "--tags", "--quiet", ZRODLO)
    wynik = uruchom("git", "tag", "--sort=-v:refname", "--list", "v*")
    for znacznik in wynik.stdout.split():
        if not czy_wydanie(znacznik):
            continue
        commit = uruchom("git", "rev-list", "-n", "1", znacznik).stdout.strip()
        if commit:
            return znacznik, commit
    raise RuntimeError("podstawa nie ma zadnych znacznikow wydan")


def czy_konflikt() -> list[str]:
    """Lista plikow, ktore zderzyly sie przy nakladaniu naszych zmian."""
    wynik = uruchom("git", "diff", "--name-only", "--diff-filter=U", sprawdz_kod=False)
    return [linia for linia in wynik.stdout.split("\n") if linia.strip()]


def nalozy(podstawa_commit: str, nowy_commit: str) -> tuple[bool, list[str]]:
    """Naklada nasze commity z linii amfa na nowy commit podstawy."""
    uruchom("git", "checkout", "--quiet", NASZA_LINIA)
    wynik = uruchom("git", "rebase", "--onto", nowy_commit, podstawa_commit, NASZA_LINIA,
                    sprawdz_kod=False)
    if wynik.returncode == 0:
        return True, []
    konflikt = czy_konflikt()
    uruchom("git", "rebase", "--abort", sprawdz_kod=False)
    return False, konflikt


def testy() -> tuple[bool, str]:
    """Nasze strazniki i testy podstawy. Zwraca (ok, raport).

    Kolejnosc i twardosc sa celowe: nasze strazniki musza istniec (brak pliku = nie wydajemy),
    a test podstawy, ktorego w tej wersji nie ma, tylko notujemy — nazwy testow podstawy zmieniaja
    sie miedzy wydaniami i to nie jest nasza strata.
    """
    python = sys.executable
    raport = []
    nasze = nasze_strazniki()
    for plik in nasze + TESTY_PODSTAWY:
        if plik not in nasze and not (KORZEN / plik).is_file():
            raport.append(f"  pominieto {plik} (nie ma go w tej wersji podstawy)")
            continue
        wynik = uruchom(python, "-m", "pytest", plik, "-q", "--tb=line", sprawdz_kod=False)
        ostatnia = [l for l in wynik.stdout.splitlines() if l.strip()][-1:]
        raport.append(f"  {'OK  ' if wynik.returncode == 0 else 'FAIL'} {plik}: "
                      f"{ostatnia[0] if ostatnia else 'brak wyniku'}")
        if wynik.returncode != 0:
            return False, "\n".join(raport)
    return True, "\n".join(raport)


def zbuduj_panel() -> tuple[bool, str]:
    """Buduje panel konsoli. Tu siedza nasze zmiany brandowe, wiec zepsuty panel musi zatrzymac
    wydanie tak samo jak padniety test — inaczej przeszedlby niezauwazony."""
    katalog = KORZEN / "privacyidea" / "static"
    if not (katalog / "package.json").is_file():
        return True, "brak zrodel panelu w tej wersji podstawy — pomijam"
    instalacja = subprocess.run(["npm", "ci", "--silent"], cwd=katalog, capture_output=True, text=True)
    if instalacja.returncode != 0:
        return False, "nie udalo sie zainstalowac zaleznosci panelu: " + \
            (instalacja.stderr.strip().split("\n")[-1] if instalacja.stderr.strip() else "")
    budowa = subprocess.run(["npm", "run", "build"], cwd=katalog, capture_output=True, text=True)
    if budowa.returncode != 0:
        ogon = (budowa.stdout + budowa.stderr).strip().split("\n")
        return False, "build panelu padl: " + (ogon[-1] if ogon else "")
    return spakuj_panel(katalog)


def spakuj_panel(katalog: pathlib.Path) -> tuple[bool, str]:
    """Zachowuje zbudowany panel jako gotowy plik.

    Wdrozenie ma brac gotowy wynik, a nie budowac panel na serwerze: pakiet privacyIDEA zawiera
    tylko zbudowany panel i wyrzuca zrodla (patrz MANIFEST.in), wiec nasze zmiany w zrodlach bylyby
    niewidoczne, gdyby panelu nie zbudowac z naszego repozytorium.
    """
    zbudowany = katalog / "dist" / "privacyidea-webui" / "browser"
    if not zbudowany.is_dir():
        return False, f"brak zbudowanego panelu w {zbudowany}"
    cel = KORZEN / "dist-amfa"
    cel.mkdir(exist_ok=True)
    nazwa = cel / f"amfa-panel-{podstawa_w_pliku()}.tar.gz"
    pakowanie = subprocess.run(["tar", "czf", str(nazwa), "-C", str(zbudowany), "."],
                               capture_output=True, text=True)
    if pakowanie.returncode != 0:
        return False, "nie udalo sie spakowac panelu: " + pakowanie.stderr.strip()
    return True, f"panel zbudowany i zapisany jako {nazwa.name}"


def podstawa_w_pliku() -> str:
    """Znacznik podstawy do nazwy pliku; gdy brak, uzywamy krotkiego commitu."""
    try:
        dane = czytaj_podstawe()
        znacznik = dane.get("tag", "")
        return znacznik.lstrip("v") if znacznik and znacznik != "—" else dane.get("commit", "nieznana")[:12]
    except RuntimeError:
        return "nieznana"


def wyczysc_smieci_pakowania() -> None:
    """Usuwa to, co potrafi wniesc do pakietu **stary** panel.

    Setuptools zbiera drzewo do `build/lib/` i nigdy go nie czysci, a `ng build` za kazdym razem
    tworzy bundle o nowych nazwach — stare zostaja i przy pakowaniu w tym samym drzewie wchodza do
    srodka razem z nowymi. Objaw: pakiet ma 138 MB zamiast ~96 i zawiera panel sprzed zmian
    (widoczna nazwa podstawy), choc drzewo zrodel jest juz przebrandowane.
    """
    shutil.rmtree(KORZEN / "build", ignore_errors=True)
    for stary in (KORZEN / "dist-amfa").glob("*.whl"):
        stary.unlink()


def zbuduj() -> tuple[bool, str]:
    """Buduje pakiet z zbudowanym panelem.

    Kolejnosc jest czescia wyniku: panel musi byc gotowy **przed** pakowaniem (pakiet zawiera tylko
    jego wynik, zrodla panelu sa z niego wyrzucane), a stare drzewo `build/` musi zniknac przed
    pakowaniem, inaczej do srodka wejda bundle z poprzednich buildow.
    """
    wyczysc_smieci_pakowania()
    polecenia = (
        ("builder `build`", (sys.executable, "-m", "build", "--outdir", "dist-amfa", "--wheel")),
        ("builder `pip wheel`", (sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", "dist-amfa", ".")),
    )
    ostatni = ""
    for nazwa, polecenie in polecenia:
        wynik = uruchom(*polecenie, sprawdz_kod=False)
        if wynik.returncode == 0:
            return True, f"pakiet zbudowany do dist-amfa ({nazwa})"
        ostatni = (wynik.stdout + wynik.stderr).strip().split("\n")[-1] if (wynik.stdout + wynik.stderr).strip() else "brak wyniku"
    return False, ostatni


def main() -> int:
    parser = argparse.ArgumentParser(description="Automat wydan AMFA Auth")
    grupa = parser.add_mutually_exclusive_group(required=True)
    grupa.add_argument("--sprawdz", action="store_true", help="tylko raport, nic nie zmienia")
    grupa.add_argument("--przygotuj", action="store_true", help="naklada zmiany, testuje, buduje")
    argumenty = parser.parse_args()

    podstawa = czytaj_podstawe()
    znacznik, commit = najnowszy_znacznik()
    print(f"Nasza linia stoi na: {podstawa.get('tag', '—')} ({podstawa.get('commit', '?')[:12]})")
    print(f"Najnowsze wydanie podstawy: {znacznik} ({commit[:12]})")

    nasza = podstawa.get("commit", "")
    if nasza == commit:
        print("Brak aktualizacji — nasza linia stoi na najnowszym wydaniu.")
        return 0
    # Nasza linia moze stac na commicie nowszym niz ostatnie wydanie (np. na biezacym masterze
    # podstawy). Wtedy znacznik jest juz w naszej historii i nie ma czego nakladac.
    przodek = uruchom("git", "merge-base", "--is-ancestor", commit, nasza, sprawdz_kod=False)
    if przodek.returncode == 0:
        print(f"Brak aktualizacji — wydanie {znacznik} jest juz w naszej historii.")
        return 0

    print(f"Jest nowe wydanie: {znacznik}. Nasze zmiany trzeba naloyzc na nowa podstawe.")
    if argumenty.sprawdz:
        wynik = uruchom("git", "log", "--oneline", f"{podstawa['commit']}..{commit}",
                        sprawdz_kod=False)
        liczba = len([l for l in wynik.stdout.split("\n") if l.strip()])
        print(f"  podstawy zmian do przyswojenia: {liczba}")
        print("  uruchom z --przygotuj, zeby nalozyc nasze zmiany.")
        print("  Lista kontrolna wydania (co musi byc zielone, zanim to pojdzie na lab):")
        for punkt in LISTA_KONTROLNA_WYDANIA:
            print(f"    - {punkt}")
        return 0

    ok, konflikt = nalozy(podstawa["commit"], commit)
    if not ok:
        print("KONFLIKT: naszych zmian nie dalo sie nalozyc na nowa podstawe.", file=sys.stderr)
        for plik in konflikt:
            print(f"  {plik}", file=sys.stderr)
        print("  Linia amfa zostala przywrocona do stanu sprzed proby.", file=sys.stderr)
        return 2

    print("Nasze zmiany nalozone. Uruchamiam testy:")
    ok, raport = testy()
    print(raport)
    if not ok:
        print("TESTY PADLY — nie wydajemy.", file=sys.stderr)
        return 3

    # Panel PRZED pakietem: pakiet zawiera tylko wynik buildu panelu (zrodla panelu sa z niego
    # wyrzucane), wiec kolejnosc decyduje o tym, czy do srodka wejdzie nasza warstwa widoczna, czy ta
    # sprzed zmiany.
    ok, opis = zbuduj_panel()
    print(f"Budowanie panelu: {'OK' if ok else 'PADLO'} — {opis}")
    if not ok:
        print("PANEL SIE NIE BUDUJE — nie wydajemy.", file=sys.stderr)
        return 3

    ok, opis = zbuduj()
    print(f"Budowanie pakietu: {'OK' if ok else 'PADLO'} — {opis}")
    if not ok:
        return 3

    zapisz_podstawe(commit, znacznik)
    print(f"Podstawa zapisana jako {znacznik}. Nasza linia jest gotowa do wydania.")
    print("Lista kontrolna wydania (aktualizacja jest caloscia):")
    for punkt in LISTA_KONTROLNA_WYDANIA:
        print(f"  - {punkt}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as blad:
        print(f"BLAD: {blad}", file=sys.stderr)
        sys.exit(4)
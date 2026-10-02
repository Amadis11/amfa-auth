#!/usr/bin/env python3
"""Automat wydan AMFA Auth — nakladanie naszych zmian na nowe wydanie privacyIDEA.

Uruchamiany przez .github/workflows/amfa-aktualizacja-podstawy.yml, ale dziala tez lokalnie:

    python3 amfa/aktualizacja-podstawy.py --sprawdz      # tylko raport, nic nie zmienia
    python3 amfa/aktualizacja-podstawy.py --przygotuj    # naklada nasze zmiany, testuje, buduje

Zasady (patrz AMFA-ZMIANY.md):
  - `master` to lustro podstawy i nigdy nie commitujemy tu naszych zmian,
  - `amfa` to nasza linia; nasze commity sa nakladane na nowy znacznik wydania podstawy,
  - konflikt konczy sie raportem z lista plikow — nigdy cichym pozostaniem na starej wersji,
  - **aktualizacja jest caloscia**: nowa linia wydania podstawy musi byc najpierw przyjeta przez brame
    (`amfa/brama-linie.json`). Automat nie wydaje linii spoza tej listy — to swiadoma decyzja, a nie
    awaria, wiec raportuje ja osobnym kodem wyjscia i lista kontrolna wydania.

Kody wyjscia:
  0 — brak aktualizacji albo wszystko przeszlo
  2 — jest nowe wydanie, ale naszych zmian nie dalo sie nalozyc (konflikt)
  3 — nasze zmiany nalozone, ale testy albo budowanie padly
  4 — blad wywolania (brak galezi, brak znacznikow)
  5 — nowa linia wydania, ktorej brama nie przyjmuje: najpierw decyzja o zgodnosci (amfa/brama-linie.json)
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

KORZEN = pathlib.Path(__file__).resolve().parents[1]
PLIK_PODSTAWY = KORZEN / "amfa" / "PODSTAWA"
PLIK_BRAMY = KORZEN / "amfa" / "brama-linie.json"
NASZA_LINIA = "amfa"
LUSTRO = "master"
ZRODLO = "upstream"

#: Co sklada sie na wydanie nowej linii podstawy. Kolejnosc jest kolejnascia wdrozenia, a nie lista zyczen:
#: punkt o bramie jest warunkiem, bo bez niego logowanie przez brame zatrzymuje sie na `503`.
LISTA_KONTROLNA_WYDANIA = (
    "kod: nasze commity nalozone na nowa podstawe, wszystkie testy zielone",
    "brama: linia wydania na liscie SANE_RELEASE_LINES (amitronic-amfa: components/gateway/core/amfa_gateway/privacyidea.py)",
    "zaleznosci: /opt/privacyidea/bin/pip install --upgrade -r requirements.txt na kazdym wezle",
    "schemat: pi-manage db upgrade przy zatrzymanej usludze na WSZYSTKICH wezlach (nowa wersja przenosi dane)",
    "panel: zbudowany panel z tego pakietu (static/dist) — bez osobnego wgrywania",
    "wzorce: components/privacyidea/ sprawdzone wobec stanu na wezlach (realm, resolver, polityki)",
    "wdrozenie: kopie wstecz, stop, podmiana, start, weryfikacja i wpis w docs/status.md",
)

# Testy uruchamiane po nalozeniu na nowa podstawe. Nasze strazniki ida zawsze pierwsze,
# bo one mowia wprost, czy nasze zmiany nadal sa na miejscu.
NASZE_TESTY = ["tests/test_amfa_zmiany.py"]
TESTY_PODSTAWY = [
    "tests/test_api_validate.py",
    "tests/test_app.py",
    "tests/test_api_lib_policy.py",
    "tests/test_api_periodictask.py",
]


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


def przyjmowane_linie() -> tuple[list[str], str, str]:
    """Linie wydan privacyIDEA, ktore przyjmuje brama AMFA.

    Zwraca (linie, gdzie_w_bramie, jak_dopisac). Brama trzyma te liste zamknieta celowo — nieznane
    wydanie ma zatrzymac ruch, wiec wydanie linii spoza listy jest decyzja, a nie rutynowym krokiem.
    Ten plik jest zadeklarowana kopia listy z bramy; test w repozytorium bramy pilnuje, ze obie
    strony mowia to samo.
    """
    if not PLIK_BRAMY.is_file():
        raise RuntimeError(f"brak pliku {PLIK_BRAMY.relative_to(KORZEN)} — nie wiem, jakie linie przyjmuje brama")
    dane = json.loads(PLIK_BRAMY.read_text(encoding="utf-8"))
    linie = dane.get("przyjmowane")
    if not isinstance(linie, list) or not linie or not all(isinstance(x, str) and x.strip() for x in linie):
        raise RuntimeError(f"{PLIK_BRAMY.name}: pole 'przyjmowane' musi byc niepusta lista linii, np. [\"3.13\", \"3.14\"]")
    jak_dopisac = dane.get("przy_dopisaniu_linii")
    if isinstance(jak_dopisac, list):
        jak_dopisac = "; ".join(str(krok) for krok in jak_dopisac)
    return sorted(x.strip() for x in linie), str(dane.get("zrodlo_w_bramie", "")), str(jak_dopisac or "")


#: Znacznik wydania podstawy: `v3.14`, `3.14`, `v3.14.1`. Wersje rozwojowe (`v3.14dev4`) nie sa wydaniem.
WZORZEC_WYDANIA = re.compile(r"v?(\d+\.\d+)(?:\.\d+)?")


def czy_wydanie(znacznik: str | None) -> bool:
    """Czy znacznik jest wydaniem podstawy (a nie wersja rozwojowa, np. `v3.14dev4`)."""
    return WZORZEC_WYDANIA.fullmatch((znacznik or "").strip()) is not None


def linia_wydania(znacznik: str | None) -> str | None:
    """Linia wydania ze znacznika podstawy, np. `v3.14.1` -> `3.14`. `None`, gdy znacznik nie jest wydaniem."""
    dopasowanie = WZORZEC_WYDANIA.fullmatch((znacznik or "").strip())
    return dopasowanie.group(1) if dopasowanie else None


def zgodnosc_bramy(znacznik: str | None) -> tuple[bool, str]:
    """Czy brama przyjmuje linie tego wydania. Zwraca (ok, opis do raportu).

    Opis jest gotowy do wklejenia w raport: mowi, co jest decyzja, gdzie sie ja podejmuje i co
    pozostaje do zrobienia w calym lancuchu wydania.
    """
    linie, gdzie, jak_dopisac = przyjmowane_linie()
    linia = linia_wydania(znacznik)
    if linia is None:
        return True, (f"linia wydania: nie odczytalem linii ze znacznika {znacznik!r} — "
                      f"brama przyjmuje {', '.join(linie)}; sprawdz, czy znacznik jest wydaniem podstawy")
    if linia in linie:
        return True, f"linia wydania {linia}: brama ja przyjmuje (przyjmowane: {', '.join(linie)})"
    opis = [
        f"linia wydania {linia}: BRAMA JEJ NIE PRZYJMUJE (przyjmowane: {', '.join(linie)}).",
        "  To nie jest awaria automatu, tylko decyzja do podjecia: brama ma liste linii zamknieta celowo,",
        "  bo nieznane wydanie ma zatrzymac ruch, a nie przejsc niezauwazone. Bez dopisania linii logowanie",
        "  przez brame zatrzyma sie na 503 (amfa_challenge_start_failure, phase=privacyidea.outcome).",
        f"  Gdzie: {gdzie or 'brak wskazania w ' + PLIK_BRAMY.name}",
    ]
    if jak_dopisac:
        opis.append(f"  Jak: {jak_dopisac}")
    opis.append("  Lista kontrolna wydania (aktualizacja jest caloscia):")
    opis.extend(f"    - {punkt}" for punkt in LISTA_KONTROLNA_WYDANIA)
    return False, "\n".join(opis)


def najnowszy_znacznik() -> tuple[str, str]:
    """Zwraca (znacznik, commit) najnowszego **wydania** podstawy wedlug numeracji wersji.

    Znaczniki rozwojowe (np. `v3.14dev4`) pomijamy: wydaniem jest dopiero `v3.14`/`v3.14.1`, a tylko
    wydanie ma linie, ktora da sie porownac z lista linii przyjmowanych przez brame.
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
    """Nasze strazniki i testy podstawy. Zwraca (ok, raport)."""
    python = sys.executable
    raport = []
    for plik in NASZE_TESTY + TESTY_PODSTAWY:
        if not (KORZEN / plik).is_file():
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


def zbuduj() -> tuple[bool, str]:
    wynik = uruchom(sys.executable, "-m", "build", "--outdir", "dist-amfa", sprawdz_kod=False)
    if wynik.returncode != 0:
        return False, (wynik.stdout + wynik.stderr).strip().split("\n")[-1] if (wynik.stdout + wynik.stderr).strip() else "build niedostepny"
    return True, "pakiet zbudowany do dist-amfa"


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
    # Aktualizacja jest caloscia: bez linii przyjmowanej przez brame wydanie zatrzymaloby logowanie,
    # wiec automat tego nie wydaje — raportuje decyzje do podjecia i konczy sie kodem 5.
    zgodne, opis_bramy = zgodnosc_bramy(znacznik)
    print(opis_bramy)
    if argumenty.sprawdz:
        wynik = uruchom("git", "log", "--oneline", f"{podstawa['commit']}..{commit}",
                        sprawdz_kod=False)
        liczba = len([l for l in wynik.stdout.split("\n") if l.strip()])
        print(f"  podstawy zmian do przyswojenia: {liczba}")
        if zgodne:
            print("  uruchom z --przygotuj, zeby nalozyc nasze zmiany.")
        else:
            print("  automat NIE naloy naszych zmian, dopoki linia nie znajdzie sie na liscie bramy.")
        return 0

    if not zgodne:
        print("WYDANIE WSTRZYMANE — to decyzja o zgodnosci z brama, nie awaria automatu.", file=sys.stderr)
        return 5

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

    ok, opis = zbuduj()
    print(f"Budowanie pakietu: {'OK' if ok else 'PADLO'} — {opis}")
    if not ok:
        return 3

    ok, opis = zbuduj_panel()
    print(f"Budowanie panelu: {'OK' if ok else 'PADLO'} — {opis}")
    if not ok:
        print("PANEL SIE NIE BUDUJE — nie wydajemy.", file=sys.stderr)
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
#!/usr/bin/env python3
"""Automat wydan AMFA Auth — nakladanie naszych zmian na nowe wydanie privacyIDEA.

Uruchamiany przez .github/workflows/amfa-aktualizacja-podstawy.yml, ale dziala tez lokalnie:

    python3 amfa/aktualizacja-podstawy.py --sprawdz      # tylko raport, nic nie zmienia
    python3 amfa/aktualizacja-podstawy.py --przygotuj    # naklada nasze zmiany, testuje, buduje

Zasady (patrz AMFA-ZMIANY.md):
  - `master` to lustro podstawy i nigdy nie commitujemy tu naszych zmian,
  - `amfa` to nasza linia; nasze commity sa nakladane na nowy znacznik wydania podstawy,
  - konflikt konczy sie raportem z lista plikow — nigdy cichym pozostaniem na starej wersji.

Kody wyjscia:
  0 — brak aktualizacji albo wszystko przeszlo
  2 — jest nowe wydanie, ale naszych zmian nie dalo sie nalozyc (konflikt)
  3 — nasze zmiany nalozone, ale testy albo budowanie padly
  4 — blad wywolania (brak galezi, brak znacznikow)
"""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

KORZEN = pathlib.Path(__file__).resolve().parents[1]
PLIK_PODSTAWY = KORZEN / "amfa" / "PODSTAWA"
NASZA_LINIA = "amfa"
LUSTRO = "master"
ZRODLO = "upstream"

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


def najnowszy_znacznik() -> tuple[str, str]:
    """Zwraca (znacznik, commit) najnowszego wydania podstawy wedlug numeracji wersji."""
    uruchom("git", "fetch", "--tags", "--quiet", ZRODLO)
    wynik = uruchom("git", "tag", "--sort=-v:refname", "--list", "v*")
    for znacznik in wynik.stdout.split():
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
    if argumenty.sprawdz:
        wynik = uruchom("git", "log", "--oneline", f"{podstawa['commit']}..{commit}",
                        sprawdz_kod=False)
        liczba = len([l for l in wynik.stdout.split("\n") if l.strip()])
        print(f"  podstawy zmian do przyswojenia: {liczba}")
        print("  uruchom z --przygotuj, zeby nalozyc nasze zmiany.")
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

    ok, opis = zbuduj()
    print(f"Budowanie: {'OK' if ok else 'PADLO'} — {opis}")
    if not ok:
        return 3

    zapisz_podstawe(commit, znacznik)
    print(f"Podstawa zapisana jako {znacznik}. Nasza linia jest gotowa do wydania.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as blad:
        print(f"BLAD: {blad}", file=sys.stderr)
        sys.exit(4)
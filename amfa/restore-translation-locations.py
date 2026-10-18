#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 AMITRONIC
# SPDX-License-Identifier: proprietary
"""Przywraca w katalogach tlumaczen bloki lokalizacji z podstawy (i pilnuje tego w CI).

Skad problem: automat podstawy (`.github/workflows/webui-i18n-extract.yml`, nocny, upstreamowy) uruchamia
`npm run i18n:extract` i commituje wynik na `chore/i18n-extract`, a jego PR jest scalany do naszej galezi.
Ekstrakcja wypisuje na nowo `<context context-type="linenumber">` dla **kazdej** jednostki, bo czyta nasz
kod — wiec po kazdym takim scaleniu katalogi maja ~1,4 tys. linii roznicy, ktore nie sa tlumaczeniami,
tylko metadanymi. To ten szum puchl nasza delte wobec lustra i gryzl sie przy kazdym podniesieniu podstawy.

Co robi ten program: dla kazdej jednostki, ktora **jest w podstawie**, podmienia bloki lokalizacji na
wersje z podstawy (`--mirror`, domyslnie `master`); jednostki, ktorych w podstawie nie ma (nasze wlasne
napisy), zostaja bez zmian, a `<source>` i `<target>` nie sa dotykane w ogole. Efekt: katalogi roznia sie
od podstawy wylacznie trescia tlumaczen, a po kolejnym nocnym PR-ze wystarczy uruchomic ten program.

Tryby:
  bez argumentow   poprawia pliki w miejscu,
  --check          nic nie zapisuje, tylko mowi, ktore jednostki maja lokalizacje spoza podstawy
                   (kod wyjscia 1) — tego uzywa strażnik `tests/test_amfa_krok11_lokalizacje-w-katalogu.py`.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
import xml.etree.ElementTree as ElementTree

REPO = pathlib.Path(__file__).resolve().parent.parent
LOCALE_DIR = REPO / "privacyidea" / "static" / "src" / "locale"
NAMESPACE = {"x": "urn:oasis:names:tc:xliff:document:1.2"}
UNIT = re.compile(r'[ ]*<trans-unit id="[^"]+"[^>]*>.*?</trans-unit>\n', re.DOTALL)
LOCATIONS = re.compile(r'(?:[ ]*<context-group purpose="location">.*?</context-group>\n)+', re.DOTALL)


def unit_id_of(block: str) -> str:
    found = re.search(r'id="([^"]+)"', block)
    if found is None:
        raise SystemExit("STOP: blok bez identyfikatora jednostki")
    return found.group(1)


def mirror_text(path: pathlib.Path, mirror: str) -> str | None:
    """Tresc pliku z podstawy; probujemy nazwe lokalna, potem zdalna galaz o tej samej nazwie."""
    candidates = [mirror] if mirror != "master" else ["master"]
    candidates += [f"origin/{x}" for x in ([mirror] if mirror != "master" else ["master"])]
    candidates += [f"refs/remotes/origin/{x}" for x in ([mirror] if mirror != "master" else ["master"])]
    for ref in candidates:
        result = subprocess.run(["git", "show", f"{ref}:{path.relative_to(REPO)}"],
                                cwd=REPO, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
    return None


def unit_map(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for block in UNIT.findall(text):
        found[unit_id_of(block)] = block
    return found


def locations_of(block: str) -> str:
    return "".join(LOCATIONS.findall(block))


def content_of(text: str) -> dict[str, tuple[str, str]]:
    """id -> (source, target) — to, co musi przetrwac niezmienione."""
    root = ElementTree.fromstring(text)
    found: dict[str, tuple[str, str]] = {}
    for unit in root.iter("{urn:oasis:names:tc:xliff:document:1.2}trans-unit"):
        source = unit.find("x:source", NAMESPACE)
        target = unit.find("x:target", NAMESPACE)
        found[unit.get("id", "")] = (source.text or "" if source is not None else "",
                                     target.text or "" if target is not None else "")
    return found


def process(path: pathlib.Path, mirror: str, check: bool) -> tuple[int, int, list[str]]:
    ours_text = path.read_text(encoding="utf-8")
    base = mirror_text(path, mirror)
    if base is None:
        return 0, 0, [f"{path.name}: brak pliku w podstawie ({mirror}) — pomijam"]
    mirror_units = unit_map(base)
    offenders: list[str] = []
    fixed = left = 0

    def transform(match: re.Match[str]) -> str:
        nonlocal fixed, left
        block = match.group(0)
        unit_id = unit_id_of(block)
        base_block = mirror_units.get(unit_id)
        if base_block is None:
            left += 1
            return block
        wanted = locations_of(base_block)
        current = locations_of(block)
        if not wanted or current == wanted:
            if current != wanted and wanted:
                offenders.append(f"{path.name}: {unit_id}")
            return block
        offenders.append(f"{path.name}: {unit_id}")
        if check:
            return block
        fixed += 1
        return block.replace(current, wanted, 1) if current else block.replace("      </trans-unit>",
                                                                              wanted + "      </trans-unit>", 1)

    result = UNIT.sub(transform, ours_text)
    if not check and fixed:
        if content_of(result) != content_of(ours_text):
            raise SystemExit(f"STOP: {path.name}: tresc tlumaczen zmienilaby sie, nie zapisuje")
        path.write_text(result, encoding="utf-8")
    return fixed, left, offenders


def main() -> int:
    parser = argparse.ArgumentParser(description="lokalizacje w katalogach tlumaczen z podstawy")
    parser.add_argument("--mirror", default="master", help="galaz podstawy (domyslnie master)")
    parser.add_argument("--check", action="store_true", help="tylko sprawdz, nic nie zapisuj")
    args = parser.parse_args()

    files = sorted(LOCALE_DIR.glob("messages*.xlf"))
    if not files:
        print(f"BLAD: brak katalogow w {LOCALE_DIR}", file=sys.stderr)
        return 2
    rows, offenders, changed = [], [], 0
    for path in files:
        fixed, left, found = process(path, args.mirror, args.check)
        changed += fixed
        offenders.extend(found)
        rows.append(f"{path.name}: poprawione={fixed}, nasze wlasne jednostki bez podstawy={left}")
    print("\n".join(rows))
    for offender in offenders[:20]:
        print(f"  poza podstawa: {offender}")
    if args.check:
        if offenders:
            print(f"NIEGOTOWE: {len(offenders)} jednostek ma lokalizacje spoza podstawy — "
                  f"uruchom `python3 amfa/restore-translation-locations.py`")
            return 1
        print("OK: lokalizacje wszystkich jednostek zgodne z podstawa")
        return 0
    print(f"gotowe: poprawionych jednostek={changed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

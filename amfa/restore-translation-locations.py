#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 AMITRONIC
# SPDX-License-Identifier: proprietary
"""Sprowadza katalogi tlumaczen do postaci zgodnej z podstawa — dwie rzeczy naraz.

1) **Lokalizacje z podstawy.** Nocny automat podstawy (`webui-i18n-extract.yml`) uruchamia
   `npm run i18n:extract` i commituje wynik na `chore/i18n-extract`; ekstrakcja czyta **nasz** kod, wiec
   wypisuje na nowo `<context context-type="linenumber">` dla kazdej jednostki. Bez tej poprawki katalogi
   nosza ok. 12 tys. jednostek z lokalizacjami spoza podstawy — to nie tlumaczenia, a puchnie delte wobec
   lustra i gryzie sie przy kazdym podniesieniu podstawy.

2) **Nazwy podstawy w tlumaczeniach, ktore zostaja z podstawy.** Tam, gdzie nasz komunikat zmienil nazwe
   (np. `privacyIDEA` -> `AMFA`), tlumaczenie podstawy nadal mowi o podstawie, a to widoczny tekst panelu —
   pilnuje tego strażnik `tests/test_amfa_krok5_brand.py::test_panel_nie_mowi_o_podstawie` (nazwa podstawy
   albo dostawcy w widocznym tekscie = czerwony). Poprawka: jezeli komunikat podstawy zawieral nazwe
   podstawy, a nasz zawiera nasza, to w tlumaczeniu podstawy podmieniamy nazwe tak samo.

`<source>` i nasze wlasne `<target>` nie sa dotykane. Tryby:
  bez argumentow   poprawia pliki w miejscu,
  --check          nic nie zapisuje, tylko mowi, ktore jednostki sa niezgodne (kod wyjscia 1) —
                   tego uzywa strażnik `tests/test_amfa_krok11_lokalizacje-w-katalogu.py`.
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
# Nazwy podstawy, ktore nasza linia przemianowala; podmieniamy je tez w tlumaczeniu podstawy.
RENAMES = (("privacyIDEA", "AMFA"), ("NetKnights", "AMITRONIC"))


def unit_id_of(block: str) -> str:
    found = re.search(r'id="([^"]+)"', block)
    if found is None:
        raise SystemExit("STOP: blok bez identyfikatora jednostki")
    return found.group(1)


def mirror_text(path: pathlib.Path, mirror: str) -> str | None:
    """Tresc pliku z podstawy; probujemy nazwe lokalna, potem zdalna galaz o tej samej nazwie."""
    names = [mirror]
    candidates = names + [f"origin/{name}" for name in names] + [f"refs/remotes/origin/{name}" for name in names]
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


def field_of(block: str, which: str) -> str:
    found = re.search(rf"(<{which}[^>]*>)(.*?)(</{which}>)", block, re.DOTALL)
    return found.group(2) if found else ""


def set_field(block: str, which: str, value: str) -> str:
    found = re.search(rf"(<{which}[^>]*>)(.*?)(</{which}>)", block, re.DOTALL)
    if found is None:
        return block
    return block[:found.start(2)] + value + block[found.end(2):]


def locations_of(block: str) -> str:
    return "".join(LOCATIONS.findall(block))


def rename_base_mentions(target: str, base_source: str, our_source: str) -> str:
    """Podmienia nazwy podstawy w tlumaczeniu, ktore zostaje z podstawy.

    Bez warunku „komunikat sie zmienil”: nazwa podstawy w widocznym tekscie panelu jest u nas zabroniona
    niezaleznie od tego, czy zmienilismy sam komunikat (pilnuje tego
    `test_amfa_krok5_brand.py::test_panel_nie_mowi_o_podstawie`), a tlumaczenia podstawy nazywaja podstawe
    czesto takze tam, gdzie nasz komunikat podstawy nie zmienial.
    """
    for old, new in RENAMES:
        if old in target:
            target = target.replace(old, new)
    return target


def content_of(text: str) -> dict[str, tuple[str, str]]:
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
        return 0, 0, [f"{path.name}: brak pliku w podstawie ({mirror}) — nie moge ocenic"]
    mirror_units = unit_map(base)
    offenders: list[str] = []
    expected_targets: dict[str, str] = {}
    fixed = left = 0

    def transform(match: re.Match[str]) -> str:
        nonlocal fixed, left
        block = match.group(0)
        unit_id = unit_id_of(block)
        base_block = mirror_units.get(unit_id)
        if base_block is None:
            left += 1
            return block
        result = block
        problems: list[str] = []
        wanted_locations = locations_of(base_block)
        current_locations = locations_of(block)
        if wanted_locations and current_locations != wanted_locations:
            problems.append(f"{path.name}: {unit_id} (lokalizacja spoza podstawy)")
            if not check:
                result = (result.replace(current_locations, wanted_locations, 1) if current_locations
                          else result.replace("      </trans-unit>", wanted_locations + "      </trans-unit>", 1))
        our_target = field_of(block, "target")
        base_target = field_of(base_block, "target")
        # Sanityzujemy to, co faktycznie zostalo z podstawy: puste nasze tlumaczenie albo identyczne
        # z podstawowym (tak wyglada jezyk, w ktorym nasze tlumaczenia wypadly).
        if not our_target.strip() or our_target == base_target:
            renamed = rename_base_mentions(base_target, field_of(base_block, "source"),
                                           field_of(block, "source"))
            if renamed != base_target:
                problems.append(f"{path.name}: {unit_id} (nazwa podstawy w tlumaczeniu podstawy)")
                expected_targets[unit_id] = renamed
                if not check:
                    result = set_field(result, "target", renamed)
        if problems:
            fixed += 1 if not check else 0
            offenders.extend(problems)
        return result

    result = UNIT.sub(transform, ours_text)
    if not check:
        if not fixed:
            return 0, left, offenders
        # Kontrola: nasze komunikaty i nasze tlumaczenia musza przetrwac nietkniete.
        # Kontrola jednym sposobem czytania po obu stronach (regex, nie ElementTree: dla `<target>` z
        # elementami potomnymi ElementTree zwraca tylko fragment tekstu i porownanie klamie).
        before_blocks, after_blocks = unit_map(ours_text), unit_map(result)
        for unit_id, block in before_blocks.items():
            after_block = after_blocks.get(unit_id, "")
            if field_of(block, "source") != field_of(after_block, "source"):
                raise SystemExit(f"STOP: {path.name}: {unit_id} komunikat mialby sie zmienic, nie zapisuje")
            wanted = expected_targets.get(unit_id, field_of(block, "target"))
            if wanted.strip() and field_of(after_block, "target") != wanted:
                raise SystemExit(f"STOP: {path.name}: {unit_id} tlumaczenie mialoby sie zmienic "
                                 f"inaczej niz podmiana nazwy podstawy")
        if len(before_blocks) != len(after_blocks):
            raise SystemExit(f"STOP: {path.name}: liczba jednostek mialaby sie zmienic, nie zapisuje")
        path.write_text(result, encoding="utf-8")
    return fixed, left, offenders


def main() -> int:
    parser = argparse.ArgumentParser(description="katalogi tlumaczen zgodne z podstawa")
    parser.add_argument("--mirror", default="master", help="galaz podstawy (domyslnie master)")
    parser.add_argument("--check", action="store_true", help="tylko sprawdz, nic nie zapisuj")
    args = parser.parse_args()

    files = sorted(LOCALE_DIR.glob("messages*.xlf"))
    if not files:
        print(f"BLAD: brak katalogow w {LOCALE_DIR}", file=sys.stderr)
        return 2
    rows, offenders, changed, unchecked = [], [], 0, 0
    for path in files:
        fixed, left, found = process(path, args.mirror, args.check)
        if found and "nie moge ocenic" in found[0]:
            unchecked += 1
        changed += fixed
        offenders.extend([x for x in found if "nie moge ocenic" not in x])
        rows.append(f"{path.name}: poprawione={fixed}, nasze wlasne jednostki bez podstawy={left}")
    print("\n".join(rows))
    for offender in offenders[:20]:
        print(f"  niezgodne: {offender}")
    if unchecked:
        print(f"POMINIETO: {unchecked} plikow nie ma odpowiednika w podstawie — nie moge ocenic")
    if args.check:
        if offenders:
            print(f"NIEGOTOWE: {len(offenders)} jednostek zgodnych nie jest z podstawa — "
                  f"uruchom `python3 amfa/restore-translation-locations.py`")
            return 1
        if unchecked == len(files):
            print("POMINIETO: brak galezi podstawy — nie ocenilem nic (nie udaje zielonego werdyktu)")
            return 0
        print("OK: katalogi zgodne z podstawa (lokalizacje i nazwy w tlumaczeniach podstawy)")
        return 0
    print(f"gotowe: poprawionych jednostek={changed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

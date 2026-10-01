"""Straznicy zmian AMFA — krok 4, automat aktualizacji podstawy.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Uruchamianie w drzewie privacyIDEA:
    python -m pytest tests/test_amfa_krok4_automat.py -q
"""
from __future__ import annotations

import ast
import pathlib

KORZEN = pathlib.Path(__file__).resolve().parents[1]


def test_automat_aktualizacji_jest_na_miejscu() -> None:
    """Skrypt automatu, jego workflow i zapis podstawy musza byc w repozytorium."""
    skrypt = KORZEN / "amfa" / "aktualizacja-podstawy.py"
    assert skrypt.is_file(), "brak skryptu automatu wydan"
    ast.parse(skrypt.read_text(encoding="utf-8"))

    workflow = KORZEN / ".github" / "workflows" / "amfa-aktualizacja-podstawy.yml"
    assert workflow.is_file(), "brak workflow automatu wydan"
    tresc = workflow.read_text(encoding="utf-8")
    assert "amfa/aktualizacja-podstawy.py --przygotuj" in tresc, "workflow nie wola skryptu"
    assert "gh issue create" in tresc, "workflow nie zglosza konfliktu"

    podstawa = (KORZEN / "amfa" / "PODSTAWA").read_text(encoding="utf-8")
    assert "commit " in podstawa, "brak zapisu podstawy — automat nie wie, na czym stoi"


def test_automat_buduje_takze_panel() -> None:
    """W panelu sa nasze zmiany brandowe, wiec zepsuty panel musi zatrzymac wydanie.

    Bez tego wydanie przeszloby z panelem, ktory sie nie buduje.
    """
    skrypt = (KORZEN / "amfa" / "aktualizacja-podstawy.py").read_text(encoding="utf-8")
    assert "def zbuduj_panel(" in skrypt, "automat nie buduje panelu"
    assert '"npm", "run", "build"' in skrypt, "automat nie uruchamia buildu panelu"
    assert 'zbuduj_panel()' in skrypt, "build panelu nie jest dolaczony do przebiegu"

    workflow = (KORZEN / ".github" / "workflows" / "amfa-aktualizacja-podstawy.yml").read_text(encoding="utf-8")
    assert "setup-node" in workflow, "workflow nie przygotowuje srodowiska Node"


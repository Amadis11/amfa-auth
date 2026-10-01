"""Straznicy zmian AMFA — krok 1, wycinka telefonu do domu.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Uruchamianie w drzewie privacyIDEA:
    python -m pytest tests/test_amfa_krok1_telemetria.py -q
"""
from __future__ import annotations

import pathlib

KORZEN = pathlib.Path(__file__).resolve().parents[1]

def test_zadanie_statystyk_nie_jest_zarejestrowane() -> None:
    """Telefon do domu (krok 1): zadanie statystyk usuniete i nie zarejestrowane."""
    assert not (KORZEN / "privacyidea" / "lib" / "task" / "simplestats.py").is_file(), (
        "wrocil modul statystyk wysylajacych dane na zewnatrz"
    )
    tresc = (KORZEN / "privacyidea" / "lib" / "periodictask.py").read_text(encoding="utf-8")
    assert "simplestats" not in tresc.lower()
    assert "SimpleStats" not in tresc


def test_lista_zadan_nadal_istnieje() -> None:
    """Wyjecie wpisu nie moze zdjac definicji listy zadan: to byl realny blad przy kroku 1."""
    import ast as _ast

    zrodlo = (KORZEN / "privacyidea" / "lib" / "periodictask.py").read_text(encoding="utf-8")
    zdefiniowane = {n.targets[0].id for n in _ast.walk(_ast.parse(zrodlo))
                    if isinstance(n, _ast.Assign) and isinstance(n.targets[0], _ast.Name)}
    assert "TASK_CLASSES" in zdefiniowane, "brak definicji TASK_CLASSES — wyjecie wpisu zdjelo liste"
    assert "TASK_MODULES" in zdefiniowane, "brak definicji TASK_MODULES"

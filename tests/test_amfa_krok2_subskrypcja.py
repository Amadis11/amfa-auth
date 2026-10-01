"""Straznicy zmian AMFA — krok 2, wycinka subskrypcji i licznika.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Uruchamianie w drzewie privacyIDEA:
    python -m pytest tests/test_amfa_krok2_subskrypcja.py -q
"""
from __future__ import annotations

import pathlib

KORZEN = pathlib.Path(__file__).resolve().parents[1]

def test_moduly_subskrypcji_nie_istnieja() -> None:
    """Licznik i licencja (krok 2): moduly usuniete."""
    for wzgledna in ("privacyidea/lib/subscriptions.py", "privacyidea/api/subscriptions.py"):
        assert not (KORZEN / wzgledna).is_file(), f"wrocil modul {wzgledna}"


def test_subskrypcja_nie_jest_sprawdzana_na_sciezkach_logowania() -> None:
    """Sprawdzenie licencji nie moze wrocic do walidacji ani do wydawania tokenu."""
    for wzgledna in ("privacyidea/api/validate.py", "privacyidea/api/token.py"):
        tresc = (KORZEN / wzgledna).read_text(encoding="utf-8")
        assert "CheckSubscription" not in tresc, f"wrocilo sprawdzanie subskrypcji w {wzgledna}"


def test_blueprint_subskrypcji_nie_jest_wpiety() -> None:
    """Blueprint subskrypcji nie moze byc wpisany do aplikacji."""
    for wzgledna in ("privacyidea/app.py", "privacyidea/api/before_after.py"):
        tresc = (KORZEN / wzgledna).read_text(encoding="utf-8")
        assert "subscriptions_blueprint" not in tresc, f"wrocil blueprint subskrypcji w {wzgledna}"


def test_ustawienia_panelu_nadal_dzialaja_bez_subskrypcji() -> None:
    """Funkcja ustawien panelu musi zostac: usuwamy z niej tylko subskrypcje, nie logike panelu."""
    tresc = (KORZEN / "privacyidea" / "api" / "lib" / "postpolicy.py").read_text(encoding="utf-8")
    assert "def get_webui_settings(" in tresc
    assert "get_subscription" not in tresc
    assert "BODY_TEMPLATE" not in tresc

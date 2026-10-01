"""Testy-strazniki zmian AMFA w tym forku.

Kazdy krok wycinki i kazda nasza zmiana dostaje tu kontrolę, ktora przy nalozeniu na nowa wersje
podstawy powie wprost, jesli cos wrocilo. To jest wlasnie "testy ze szczegolnym naciskiem na nasze
czesci" z automatu wydan (zgloszenie #199).

Uruchamianie w drzewie privacyIDEA:
    python -m pytest tests/test_amfa_zmiany.py -q
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


def test_lista_zadan_nadal_istnieje() -> None:
    """Wyjecie wpisu nie moze zdjac definicji listy zadan: to byl realny blad przy kroku 1."""
    import ast as _ast

    zrodlo = (KORZEN / "privacyidea" / "lib" / "periodictask.py").read_text(encoding="utf-8")
    zdefiniowane = {n.targets[0].id for n in _ast.walk(_ast.parse(zrodlo))
                    if isinstance(n, _ast.Assign) and isinstance(n.targets[0], _ast.Name)}
    assert "TASK_CLASSES" in zdefiniowane, "brak definicji TASK_CLASSES — wyjecie wpisu zdjelo liste"
    assert "TASK_MODULES" in zdefiniowane, "brak definicji TASK_MODULES"


def test_stan_konta_z_katalogu_jest_rozpoznawany() -> None:
    """Krok 3: kody Active Directory musza byc rozpoznane, a nie zlane w jeden blad poswiadczen."""
    import sys
    sys.path.insert(0, str(KORZEN))
    from privacyidea.lib.resolvers.LDAPIdResolver import stan_hasla_z_odpowiedzi_katalogu

    ad = lambda kod: {"message": f"80090308: LdapErr: DSID-0C0904DC, comment: "
                                 f"AcceptSecurityContext error, data {kod}, v3839"}
    assert stan_hasla_z_odpowiedzi_katalogu(ad("773")) == "password_change_required"
    assert stan_hasla_z_odpowiedzi_katalogu(ad("532")) == "password_expired"
    assert stan_hasla_z_odpowiedzi_katalogu(ad("775")) == "account_locked"
    assert stan_hasla_z_odpowiedzi_katalogu(ad("52e")) == "invalid_credentials"
    assert stan_hasla_z_odpowiedzi_katalogu({"description": "invalidCredentials"}) is None
    assert stan_hasla_z_odpowiedzi_katalogu({}) is None


def test_stan_konta_nie_jest_polykany_po_drodze() -> None:
    """Sygnal musi byc przepuszczony przez warstwe uzytkownika i przekazany do odpowiedzi."""
    uzytkownik = (KORZEN / "privacyidea" / "lib" / "user.py").read_text(encoding="utf-8")
    assert "except DirectoryPasswordState:" in uzytkownik, "user.py polyka stan konta z katalogu"
    dekoratory = (KORZEN / "privacyidea" / "lib" / "policydecorators.py").read_text(encoding="utf-8")
    assert 'token.auth_details["password_change_required"] = True' in dekoratory
    odpowiedz = (KORZEN / "privacyidea" / "lib" / "token" / "auth.py").read_text(encoding="utf-8")
    assert 'reply_dict["password_change_required"] = True' in odpowiedz

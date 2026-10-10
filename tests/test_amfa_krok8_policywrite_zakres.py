"""Straznicy zmian AMFA — krok 8, zapis polityki zawezony do zakresu docelowego.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Po co te strazniki: granica „konto z watskim prawem nie zapisze polityki administracyjnej" ma
lezec w silniku, a nie w kodzie klienta. Nowa podstawa moze po cichu wrocic do jednego
`policywrite` na wszystkie zakresy — wtedy ten plik ma zapalic sie w CI, a nie dopiero wtedy, gdy
ktos z klienta nadas sobie prawa.

Uruchamianie w drzewie privacyIDEA:
    .venv/bin/python tests/test_amfa_krok8_policywrite_zakres.py      # bez pytest, kod 0/1
    .venv/bin/python -m pytest tests/test_amfa_krok8_policywrite_zakres.py -q
"""
from __future__ import annotations

import pathlib

KORZEN = pathlib.Path(__file__).resolve().parents[1]
API_POLICY = KORZEN / "privacyidea" / "api" / "policy.py"
PREPOLICY = KORZEN / "privacyidea" / "api" / "lib" / "prepolicy.py"
AKCJE = KORZEN / "privacyidea" / "lib" / "policies" / "actions.py"

#: Zakresy, ktore maja prawo zawezone. Zakresu `admin` tu nie ma i nie wolno go dopisac.
ZAKRESY = ("authentication", "authorization", "audit", "user", "enrollment",
           "webui", "register", "container", "token", "hardening", "conditional_access")


def test_nazwy_zawezone_bez_admina() -> None:
    """Tabela praw zawezonych nie zawiera zakresu `admin` — inaczej granica zniknela."""
    from privacyidea.lib.policies.actions import PolicyAction, policy_write_action

    assert tuple(PolicyAction.POLICY_WRITE_SCOPES) == ZAKRESY, "zmienil sie zestaw zakresow zaweazonych"
    assert "admin" not in PolicyAction.POLICY_WRITE_SCOPES, "zakres admin trafil na liste zawezona"
    for zakres in ZAKRESY:
        assert policy_write_action(zakres) == f"policywrite_{zakres}"
        assert policy_write_action(zakres, delete=True) == f"policydelete_{zakres}"
    # Zakres bez prawa zawezonego (w tym `admin`) nie ma nazwy — i to jest cala granica.
    for zakres in ("admin", "nie-znany-zakres", ""):
        assert policy_write_action(zakres) is None, f"powstala nazwa dla zakresu {zakres!r}"
        assert policy_write_action(zakres, delete=True) is None, f"powstala nazwa usuwania dla {zakres!r}"


def test_nowe_nazwy_trafiaja_do_definicji_admina() -> None:
    """Definicje `GET /policy/defs/admin` powstaja z tabeli praw zawezonych (bez bazy w strazniku).

    Sprawdzenie na zrodle, nie na wywolaniu: `get_static_policy_definitions` potrzebuje aplikacji
    i bazy, a straznik ma dzialac w automacie wydania bez ciezkich zaleznosci. Kontrakt z zywego
    API (`GET /policy/defs/admin`) pilnuje osobny test w `tests/test_api_policy_scoped_write.py`.
    """
    zrodlo = (KORZEN / "privacyidea" / "lib" / "policy.py").read_text(encoding="utf-8")
    assert "policy_write_action(scope, delete)" in zrodlo, "definicje nie korzystaja z tabeli praw zawezonych"
    assert "for scope in PolicyAction.POLICY_WRITE_SCOPES" in zrodlo, "znikla petla po zakresach zaweazonych"
    assert "for delete in (False, True)" in zrodlo, "znikla polowa prawa usuwania"
    for zakres in ("admin",):
        assert f'"policywrite_{zakres}"' not in zrodlo, "w zrodle powstalo policywrite_admin"
        assert f'"policydelete_{zakres}"' not in zrodlo, "w zrodle powstalo policydelete_admin"
    # Pelne prawa musza zostac (zgodnosc wstecz dla klientow sprzed tej zmiany).
    assert "PolicyAction.POLICYWRITE: {'type': 'bool'" in zrodlo, "zniknely pelne prawa zapisu"


def test_endpointy_uzywaja_sprawdzenia_zawezonego() -> None:
    """Zapis polityki idzie przez nasze sprawdzenie — na wszystkich czterech sciezkach."""
    zrodlo = API_POLICY.read_text(encoding="utf-8")
    for funkcja in ("enable_policy_api", "disable_policy_api", "patch_policy_name_api", "set_policy_api"):
        blok = zrodlo.split(f"def {funkcja}(", 1)[0].rsplit("@policy_blueprint.route", 1)[-1]
        assert "check_scoped_policy_write" in blok, f"{funkcja}: brak sprawdzenia zawezonego"
    blok_usuwania = zrodlo.split("def delete_policy_api(", 1)[0].rsplit("@policy_blueprint.route", 1)[-1]
    assert "check_scoped_policy_delete" in blok_usuwania, "usuwanie nie uzywa sprawdzenia zawezonego"
    # Import przenosi polityki dowolnych zakresow, wiec zostaje na pelnym prawie — tego nie zwieramy.
    blok_importu = zrodlo.split("def import_policy_api(", 1)[0].rsplit("@policy_blueprint.route", 1)[-1]
    assert "check_base_action" in blok_importu, "import polityk zgubil pelne sprawdzenie"
    assert "check_scoped_policy_write" not in blok_importu, "import polityk zawezony — to otwiera obejscie granicy"


def test_sprawdzenie_zwraca_odmowe_a_nie_tylko_brak_wyjatku() -> None:
    """Kod sprawdzenia musi konczyc sie odmowa: bez tego `None` przeszloby jako zgoda."""
    zrodlo = PREPOLICY.read_text(encoding="utf-8")
    blok = zrodlo.split("def check_scoped_policy_write(", 1)[1].split("\ndef ", 1)[0]
    assert "raise PolicyError(" in blok, "brak odmowy w sprawdzeniu zapisu polityki"
    assert "policy_write_action(" in blok, "sprawdzenie nie korzysta z tabeli praw zawezonych"
    assert "def check_scoped_policy_delete(" in zrodlo, "brak watku usuwania dla dekoratora prepolicy"


def test_zmiana_zakresu_istniejacej_polityki_wymaga_pelnego_prawa() -> None:
    """Zakres bierzemy z bazy, a zadanie o inny zakres nie przechodzi prawem zawezonym."""
    zrodlo = PREPOLICY.read_text(encoding="utf-8")
    blok = zrodlo.split("def _policy_target_scope(", 1)[1].split("\ndef ", 1)[0]
    assert "list_policies(name=name)" in blok, "zakres nie jest czytany z bazy"
    assert "return None" in blok, "brak sciezki 'wymagane pelne prawo'"
    assert "requested_scope != stored_scope" in blok, "zmiana zakresu nie jest blokowana"


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

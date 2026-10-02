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


def test_automat_zachowuje_zbudowany_panel() -> None:
    """Wdrozenie ma brac gotowy plik: pakiet privacyIDEA zawiera tylko zbudowany panel,
    a zrodla wyrzuca, wiec bez zachowania wyniku nasze zmiany bylyby niewidoczne."""
    skrypt = (KORZEN / "amfa" / "aktualizacja-podstawy.py").read_text(encoding="utf-8")
    assert "def spakuj_panel(" in skrypt, "automat nie pakuje zbudowanego panelu"
    assert "amfa-panel-" in skrypt, "brak nazwy pliku z panelem"

    workflow = (KORZEN / ".github" / "workflows" / "amfa-aktualizacja-podstawy.yml").read_text(encoding="utf-8")
    assert "dist-amfa" in workflow, "workflow nie zalacza zbudowanego panelu jako wyniku"


def _automat():
    """Modul automatu zaladowany z pliku (nazwa z myslnikiem nie jest importowalna zwykle)."""
    import importlib.util

    sciezka = KORZEN / "amfa" / "aktualizacja-podstawy.py"
    spec = importlib.util.spec_from_file_location("automat_amfa", sciezka)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


def test_automat_wie_ktore_znaczniki_sa_wydaniem() -> None:
    """Podstawa wybierana jest z wydan, nie z wersji rozwojowych — inaczej na lab szloby `v3.14dev4`."""
    automat = _automat()
    assert automat.czy_wydanie("v3.14") is True
    assert automat.czy_wydanie("3.14.1") is True
    assert automat.czy_wydanie("v3.14dev4") is False
    assert automat.czy_wydanie("v3.9dev1") is False
    assert automat.czy_wydanie("—") is False
    assert automat.czy_wydanie(None) is False


def test_automat_nie_wymaga_decyzji_o_liscie_wydan() -> None:
    """Zgodnosc z nowa linia potwierdzaja testy, a nie numer wydania dopisany w kodzie bramy.

    Ten straznik zapisuje decyzje: powrot listy linii (albo kodu wyjscia dla recznej decyzji) oznaczalby,
    ze nowe wydanie podstawy znowu trzeba obwarowac recznym krokiem.
    """
    skrypt = (KORZEN / "amfa" / "aktualizacja-podstawy.py").read_text(encoding="utf-8")
    assert "brama-linie.json" not in skrypt, "wrocila lista linii bramy wymagajaca recznej decyzji"
    assert "5 —" not in skrypt, "wrocil kod wyjscia dla recznej decyzji"
    assert "SANE_RELEASE_LINES" not in skrypt, "automat wrocil do pytania o liste wydan w bramie"

    automat = _automat()
    assert not hasattr(automat, "zgodnosc_bramy"), "wrocila bramka zgodnosci z lista wydan"

    lista = automat.LISTA_KONTROLNA_WYDANIA
    assert any("regresja bramy" in punkt for punkt in lista), "lista kontrolna bez calej regresji bramy"
    assert any("test:flow" in punkt for punkt in lista), "lista kontrolna bez przebiegu na zywym labie"
    assert any("pi-manage db upgrade" in punkt for punkt in lista), "lista kontrolna bez migracji schematu"
    assert any("requirements.txt" in punkt for punkt in lista), "lista kontrolna bez aktualizacji zaleznosci"


def test_lista_kontrolna_mowi_o_testach_a_nie_o_decyzji() -> None:
    """Dokument i workflow mowia to samo, co automat: wydajemy po testach."""
    lista = (KORZEN / "amfa" / "lista-kontrolna-wydania.md").read_text(encoding="utf-8")
    assert "tests/web/gateway" in lista, "lista kontrolna nie wskazuje regresji bramy"
    assert "test:flow" in lista, "lista kontrolna nie wskazuje przebiegu na labie"
    assert "SANE_RELEASE_LINES" not in lista, "lista kontrolna wciaz mowi o liscie wydan w kodzie"
    assert "brama-linie.json" not in lista, "lista kontrolna wciaz mowi o pliku z lista wydan"

    workflow = (KORZEN / ".github" / "workflows" / "amfa-aktualizacja-podstawy.yml").read_text(encoding="utf-8")
    assert "kod == '5'" not in workflow, "workflow wciaz rozpoznaje kod recznej decyzji"
    assert "wymaga decyzji o zgodnosci z brama" not in workflow, "workflow wciaz zglasza decyzje o liscie wydan"
    assert "PIPESTATUS[0]" in workflow, "kod wyjscia musi byc brany ze skryptu, nie z tee"


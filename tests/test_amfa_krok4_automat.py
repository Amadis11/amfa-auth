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


def test_automat_czyta_linie_przyjmowane_przez_brame() -> None:
    """Aktualizacja jest caloscia: automat musi wiedziec, ktore linie wydan przyjmuje brama."""
    automat = _automat()
    linie, gdzie, jak = automat.przyjmowane_linie()
    assert "3.14" in linie, f"brama ma przyjmowac linie, na ktorej stoimy: {linie}"
    assert "privacyidea.py" in gdzie, "brak wskazania, gdzie w bramie zyje lista linii"
    assert jak, "brak instrukcji, co zrobic, gdy trzeba dopisac linie"

    plik = KORZEN / "amfa" / "brama-linie.json"
    assert plik.is_file(), "brak zadeklarowanej listy linii bramy (amfa/brama-linie.json)"


def test_automat_wie_ktora_linia_ma_wydanie() -> None:
    """Linia wydania z znacznika — bez tego automat nie ma czego porownac z lista bramy."""
    automat = _automat()
    assert automat.linia_wydania("v3.14.1") == "3.14"
    assert automat.linia_wydania("v3.15") == "3.15"
    assert automat.linia_wydania("3.13.4") == "3.13"
    assert automat.linia_wydania("v3.9dev3") is None, "wersja rozwojowa nie jest wydaniem podstawy"
    assert automat.linia_wydania("—") is None
    assert automat.linia_wydania(None) is None

    # Wybor podstawy tez musi pomijac wersje rozwojowe (inaczej automat bierze `v3.14dev4` za wydanie
    # i nie ma czego porownac z lista bramy).
    assert automat.czy_wydanie("v3.14") is True
    assert automat.czy_wydanie("3.14.1") is True
    assert automat.czy_wydanie("v3.14dev4") is False
    assert automat.czy_wydanie("v3.9dev1") is False


def test_automat_przyjmuje_linie_z_listy_bramy() -> None:
    """Linia z listy: zgodnosc potwierdzona, opis mowi wprost o przyjmowaniu."""
    automat = _automat()
    zgodne, opis = automat.zgodnosc_bramy("v3.14")
    assert zgodne is True
    assert "przyjmuje" in opis and "3.14" in opis


def test_automat_wstrzymuje_wydanie_linii_spoza_listy_bramy() -> None:
    """Linia spoza listy to decyzja, nie awaria: brak zgody, wskazanie miejsca i lista kontrolna.

    Ten test pilnuje tez, ze automat nie przemilcza rozjazdu: bez tego wydanie przeszloby, a logowanie
    przez brame zatrzymaloby sie dopiero na labie.
    """
    automat = _automat()
    zgodne, opis = automat.zgodnosc_bramy("v3.15")
    assert zgodne is False, "linia spoza listy bramy nie moze przejsc jako wydanie"
    assert "NIE PRZYJMUJE" in opis
    assert "privacyidea.py" in opis, "brak wskazania, gdzie dopisac linie"
    assert "Lista kontrolna wydania" in opis
    assert "pi-manage db upgrade" in opis, "lista kontrolna bez kroku migracji schematu"
    assert len(automat.LISTA_KONTROLNA_WYDANIA) >= 6, "lista kontrolna wydania jest niekompletna"


def test_workflow_zglasza_decyzje_o_zgodnosci_osobno_od_konfliktu() -> None:
    """Zgloszenie o zgodnosci z brama nie moze wygladac jak konflikt przy nakladaniu zmian."""
    workflow = (KORZEN / ".github" / "workflows" / "amfa-aktualizacja-podstawy.yml").read_text(encoding="utf-8")
    assert "kod == '5'" in workflow, "workflow nie rozpoznaje kodu 5"
    assert "wymaga decyzji o zgodnosci z brama" in workflow, "brak osobnego tytulu zgloszenia"
    assert "PIPESTATUS[0]" in workflow, "kod wyjscia musi byc brany ze skryptu, nie z tee"
    assert "steps.nalozenie.outputs.kod != '5'" in workflow, "konflikt nie odsiewa kodu 5"

    skrypt = (KORZEN / "amfa" / "aktualizacja-podstawy.py").read_text(encoding="utf-8")
    assert "5 — nowa linia wydania" in skrypt, "kod wyjscia 5 nie jest udokumentowany"

    lista = KORZEN / "amfa" / "lista-kontrolna-wydania.md"
    assert lista.is_file(), "brak listy kontrolnej wydania"
    tresc = lista.read_text(encoding="utf-8")
    assert "SANE_RELEASE_LINES" in tresc, "lista kontrolna nie wskazuje listy linii w bramie"


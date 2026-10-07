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


def test_automat_wydaje_tylko_gdy_podstawa_sie_zmienila() -> None:
    """Bez nowego wydania skrypt nie rusza `amfa/PODSTAWA`, a krok wydania nie powstaje.

    `--przygotuj` konczy sie kodem 0 zarowno wtedy, gdy nalozyl nowe wydanie, jak i wtedy, gdy nie bylo
    czego nakladac. Bez rozroznienia workflow robilby galaz i pull request przy kazdym przebiegu
    (a `gh pr create` bez roznicy commitow konczylby sie czerwonym zadaniem) — dlatego workflow
    rozpoznaje wydanie po **zmianie pliku podstawy**, a nie po samym kodzie wyjscia.
    """
    ogon = (KORZEN / "amfa" / "aktualizacja-podstawy.py").read_text(encoding="utf-8").split("def main(")[1]
    przed_zapisem = ogon.split("zapisz_podstawe(")[0]
    assert przed_zapisem.count("return 0") >= 2, \
        "brak aktualizacji nie konczy przebiegu przed zapisem podstawy — workflow nie ma czego porownywac"

    workflow = (KORZEN / ".github" / "workflows" / "amfa-aktualizacja-podstawy.yml").read_text(encoding="utf-8")
    assert "PODSTAWA_PRZED" in workflow and "PODSTAWA_PO" in workflow, \
        "workflow nie porownuje podstawy przed i po nalozeniu"
    assert "zmiana=nie" in workflow and "zmiana=tak" in workflow, "workflow nie zapisuje znacznika zmiany"
    assert "steps.nalozenie.outputs.zmiana == 'tak'" in workflow, \
        "krok wydania nie jest bramkowany zmiana podstawy"


def test_automat_uruchamia_sie_z_galezi_domyslnej() -> None:
    """`schedule` i `workflow_dispatch` dzialaja tylko z galezi domyslnej repozytorium.

    Galaz domyslna `amfa-auth` jest `amfa` (nasza linia), a `master` to lustro podstawy. Przy domyslnej
    `master` plik workflow lezy w repozytorium, ale automat nie uruchamia sie nigdy — a straznik tego
    nie widzi, bo patrzy na plik, nie na ustawienie repozytorium.
    """
    tresc = (KORZEN / ".github" / "workflows" / "amfa-aktualizacja-podstawy.yml").read_text(encoding="utf-8")
    assert "schedule:" in tresc, "automat nie ma wyzwalacza czasowego"
    assert "workflow_dispatch:" in tresc, "automatu nie da sie uruchomic recznie"
    assert "galezi domyslnej" in tresc, "workflow nie zapisuje wymogu galezi domyslnej"

    lista = (KORZEN / "amfa" / "lista-kontrolna-wydania.md").read_text(encoding="utf-8")
    assert "workflow_dispatch" in lista, "lista kontrolna nie mowi o uruchamialnosci automatu"
    assert "gałąź domyślna" in lista, "lista kontrolna nie wskazuje galezi domyslnej"


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


def test_automat_uruchamia_wszystkie_nasze_strazniki() -> None:
    """Bramka wydania uruchamia wszystkie nasze strazniki, a nie liste wpisana raz na zawsze.

    Straznik brandu (krok 5) powstal po kroku 4 i przy liscie wpisanej po nazwie pliku zostal poza
    bramka — wydanie moglo przejsc z nazwa podstawy w widocznej warstwie konsoli.
    """
    automat = _automat()
    straznicy = automat.nasze_strazniki()
    assert "tests/test_amfa_krok4_automat.py" in straznicy, "bramka nie uruchamia straznika kroku 4"
    assert "tests/test_amfa_krok5_brand.py" in straznicy, "bramka nie uruchamia straznika brandu"

    try:
        automat.nasze_strazniki("tests/test_amfa_nie-ma-takich*.py")
    except RuntimeError:
        pass
    else:
        raise AssertionError("brak naszych straznikow nie zatrzymuje wydania")

    skrypt = (KORZEN / "amfa" / "aktualizacja-podstawy.py").read_text(encoding="utf-8")
    assert "NASZE_STRAZNICY_WZORZEC" in skrypt, "bramka wrocila do wpisanej po nazwie listy testow"


def test_automat_buduje_panel_przed_pakietem() -> None:
    """Panel musi powstac przed pakietem, a stare drzewo pakowania zniknac.

    Pakiet zawiera tylko wynik buildu panelu (zrodla panelu sa z niego wyrzucane), wiec odwrotna
    kolejnosc dawala pakiet z panelem sprzed zmiany; drzewo `build/` setuptoolsa wnosilo dodatkowo
    bundle z poprzednich buildow (widoczna nazwa podstawy w srodku pakietu).
    """
    skrypt = (KORZEN / "amfa" / "aktualizacja-podstawy.py").read_text(encoding="utf-8")
    assert "def wyczysc_smieci_pakowania(" in skrypt, "automat nie czysci drzewa pakowania"
    czesc_pakowania = skrypt.split("def zbuduj(")[1]
    assert "wyczysc_smieci_pakowania()" in czesc_pakowania, "czyszczenie nie jest wolane przy pakowaniu"

    ogon = skrypt.split("def main(")[1]
    assert ogon.index("zbuduj_panel()") < ogon.index("zbuduj()"), "pakiet buduje sie przed panelem"


def test_automat_sprawdza_testy_podstawy_dotkniete_naszymi_krokami() -> None:
    """Powierzchnie, ktore zmieniamy w podstawie, maja swoje testy podstawy w bramce.

    Chodzi o widoczna warstwe konsoli (tytul strony, logo) i zadania okresowe po usunieciu statystyk —
    bez nich nasza zmiana wychodzi dopiero na czerwonym CI, gdzie latwo ja wziac za cudzy blad.
    """
    automat = _automat()
    podstawa = set(automat.TESTY_PODSTAWY)
    assert "tests/test_ui_login.py" in podstawa, "bramka nie sprawdza testu podstawy o widocznej warstwie"
    assert "tests/cli/test_cli_cron.py" in podstawa, "bramka nie sprawdza testu podstawy o zadaniach okresowych"


def test_automat_uruchamia_testy_pythonem_z_zaleznosciami() -> None:
    """Straznicy potrzebuja zaleznosci podstawy (np. flask), wiec testy ida przez venv z repozytorium.

    Bez tego automat na golej maszynie meldowalby FAIL na wlasnym braku `flask`/`pytest` zamiast
    sprawdzic zmiany.
    """
    import sys as _sys

    automat = _automat()
    venv = automat.KORZEN / ".venv" / "bin" / "python"
    wybrany = automat.python_z_testami()
    if venv.is_file():
        assert wybrany == str(venv), "automat nie uzywa venv z repozytorium, choc ten jest"
    else:
        assert wybrany == _sys.executable, "automat nie cofa sie do interpretera, ktory go uruchomil"


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



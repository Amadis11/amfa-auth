"""Straznicy zmian AMFA — krok 5, brand widocznej warstwy.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Uruchamianie w drzewie privacyIDEA:
    python -m pytest tests/test_amfa_krok5_brand.py -q
"""
from __future__ import annotations

import hashlib
import pathlib

KORZEN = pathlib.Path(__file__).resolve().parents[1]
PANEL = KORZEN / "privacyidea" / "static"

# Co WOLNO zostawic z nazwa podstawy w widocznej warstwie i dlaczego:
#  - `privacyIDEA Authenticator` to cudza aplikacja mobilna; przemianowanie jej kazaloby szukac
#    czegos, czego nie ma,
#  - `privacyIDEA1.png` to nazwa pliku zasobu podstawy,
#  - naglowki licencyjne (AGPL) zostaja nietkniete.
DOPUSZCZALNE_FRAGMENTY = (
    "privacyIDEA Authenticator",   # nazwa cudzej aplikacji mobilnej
    "privacyIDEA1.png",            # nazwa pliku zasobu podstawy
    # Klucze protokolow (identyfikatory klientow w naglowku User-Agent) — niewidoczne dla czlowieka,
    # a musza zostac takie, jakie naprawde wysylaja klienci; inaczej mapa nazw przestaje dzialac.
    "privacyIDEA-App", "privacyIDEA-Shibboleth", "privacyIDEA-LDAP-Proxy",
)
DOPUSZCZALNE_LINIE = (
    "(c) NetKnights", "SPDX-License", "This code is free software", "GNU AFFERO GENERAL PUBLIC LICENSE",
    "version 3 of the License", "WITHOUT ANY WARRANTY", "You should have received",
    "Free Software Foundation", "distributed in the hope", "along with this program",
)
# Odnosniki do dostawcy podstawy: w widocznej warstwie nie ma prawa ich byc.
ODNOSNIKI_DOSTAWCY = (
    "netknights.it", "github.com/privacyidea", "privacyidea.readthedocs.io",
    "hosted.weblate.org/projects/privacyidea",
)
PLIKI_WIDOCZNE = ("*.html", "*.ts", "*.xlf")


def _pliki_widocznej_warstwy():
    """Pliki, ktore trafiaja do zbudowanego panelu albo tlumacza jego teksty.

    Pliki `*.spec.ts` sa pomijane: to testy, nie warstwa widoczna, i moga cytowac dane podstawy.
    """
    for katalog in (PANEL / "src" / "app", PANEL / "src" / "locale"):
        for wzorzec in PLIKI_WIDOCZNE:
            for plik in katalog.rglob(wzorzec):
                if plik.name.endswith(".spec.ts") or "node_modules" in plik.parts:
                    continue
                yield plik
    yield PANEL / "src" / "index.html"


def _naruszajace(warunek) -> list[str]:
    znalezione = []
    for plik in _pliki_widocznej_warstwy():
        for numer, linia in enumerate(plik.read_text(encoding="utf-8").splitlines(), start=1):
            if any(fragment in linia for fragment in DOPUSZCZALNE_LINIE):
                continue
            linia_bez_dozwolonych = linia
            for fragment in DOPUSZCZALNE_FRAGMENTY:
                linia_bez_dozwolonych = linia_bez_dozwolonych.replace(fragment, "")
            if warunek(linia_bez_dozwolonych):
                znalezione.append(f"{plik.relative_to(KORZEN)}:{numer}: {linia.strip()[:120]}")
    return znalezione


def test_brand_widocznej_warstwy() -> None:
    """Tytul strony jest nasz, a produkt nie odsyla do stron ani sklepu podstawy."""
    login = (KORZEN / "privacyidea" / "webui" / "login.py").read_text(encoding="utf-8")
    assert 'PI_PAGE_TITLE", "AMFA"' in login, "tytul strony nie jest nasz"
    assert 'PI_EXTERNAL_LINKS", False' in login, "odnosniki zewnetrzne sa domyslnie wlaczone"
    # Wewnetrzna nazwa klucza dla interfejsu zostaje: zbudowany panel jej oczekuje.
    assert "'privacyideaVersionNumber'" in login, "usunieto klucz, ktorego oczekuje panel"


def test_logo_jest_nasz() -> None:
    """W konsoli ma byc nasz znak, a plik ma lezec w zasobach."""
    login = (KORZEN / "privacyidea" / "webui" / "login.py").read_text(encoding="utf-8")
    assert 'PI_LOGO", "amfa.svg"' in login, "domyslne logo nie jest nasze"
    assert (KORZEN / "privacyidea" / "static" / "public" / "assets" / "amfa.svg").is_file(), \
        "brak pliku naszego logo w zasobach konsoli"


def test_wystawca_kodow_otp_jest_nasz() -> None:
    """W aplikacji do kodow (Google Authenticator i inne) ma byc AMFA, nie nazwa podstawy.

    Klient moze to nadpisac polityka tokenissuer — chodzi o wartosc domyslna.
    """
    hotp = (KORZEN / "privacyidea" / "lib" / "tokens" / "hotptoken.py").read_text(encoding="utf-8")
    assert 'params.get("tokenissuer", "AMFA")' in hotp, "domyslny wystawca OTP nie jest nasz"
    assert "issuer=tokenissuer" in hotp, "wystawca nie jest przekazywany do aplikacji"


def test_okna_licencyjne_nie_wrocily() -> None:
    """Okna powitalne i wygasniecia subskrypcji usuniete — nie moga wrocic z nowa podstawa.

    Uwaga: usluga subskrypcji (subscription.service) zostaje — korzysta z niej pulpit konsoli
    i panel uzytkownika. Usuniete sa okna, nie cala obsluga subskrypcji; szerokie usuniecie
    katalogu uslug wysypalo build panelu.
    """
    for wzgledna in ("privacyidea/static/src/app/components/shared/welcome-dialog",
                     "privacyidea/static/src/app/components/shared/subscription-expiry-dialog",
                     "privacyidea/static/src/app/services/welcome"):
        assert not (KORZEN / wzgledna).exists(), f"wrocilo {wzgledna}"
    # Definicje uslug moga zostac w katalogu services/subscription (korzysta z nich pulpit),
    # ale zaden inny plik nie moze ich wolac.
    for plik in (KORZEN / "privacyidea" / "static" / "src" / "app").rglob("*.ts"):
        if "services/subscription" in str(plik) or "services/welcome" in str(plik):
            continue
        tresc = plik.read_text(encoding="utf-8")
        assert "WelcomeDialogService" not in tresc, f"wrocilo odwolanie w {plik}"
        assert "SubscriptionExpiryService" not in tresc, f"wrocilo odwolanie w {plik}"


def test_testy_podstawy_o_brandzie_sa_zgodne_z_naszymi() -> None:
    """Testy podstawy o widocznej warstwie musza potwierdzac nasze wartosci domyslne.

    Domyslne `PI_PAGE_TITLE` i `PI_LOGO` sa nasze, wiec test podstawy, ktory oczekuje starych wartosci
    (`privacyIDEA Authentication System`, puste logo), swieci na czerwono bez powodu — a poprawka lubi
    sie zgubic przy nakladaniu naszych zmian na nowe wydanie.
    """
    plik = KORZEN / "tests" / "test_ui_login.py"
    if not plik.is_file():
        return
    tresc = plik.read_text(encoding="utf-8")
    assert '"privacyIDEA Authentication System"' not in tresc, "test podstawy oczekuje starego tytulu strony"
    assert '"AMFA"' in tresc, "test podstawy nie potwierdza naszego tytulu strony"

    # Logo idzie inna droga niz tytul: endpoint konfiguracji dla panelu nie wstrzykuje znaku
    # (`PI_LOGO` domyslnie pusty), a panel podstawia nasz zasob `assets/amfa.svg`. Sprawdzamy oba konce,
    # bo podmiana jednego z nich cofa brand albo wstrzykuje znak podstawy do konfiguracji.
    login = (KORZEN / "privacyidea" / "webui" / "login.py").read_text(encoding="utf-8")
    assert 'PI_LOGO", ""' in login, "endpoint konfiguracji panelu wstrzykuje logo z konfiguracji"
    panel_login = (PANEL / "src" / "app" / "components" / "login" / "login.component.html").read_text(encoding="utf-8")
    assert "assets/amfa.svg" in panel_login, "ekran logowania panelu nie uzywa naszego znaku"


def test_panel_nie_mowi_o_podstawie() -> None:
    """Zadna widoczna tekstowka panelu nie nazywa podstawy ani jej dostawcy.

    Nowa podstawa moze wniesc nowe teksty — wtedy ten straznik ma zapalic sie w CI, a nie
    dopiero w oku czlowieka patrzacego na konsole.
    """
    naruszajace = _naruszajace(lambda linia: "privacyIDEA" in linia or "NetKnights" in linia)
    assert not naruszajace, "widoczne teksty nazywaja podstawe:\n" + "\n".join(naruszajace)


def test_panel_nie_odsyla_do_dostawcy_podstawy() -> None:
    """W widocznej warstwie panelu nie ma odnosnikow do stron dostawcy podstawy.

    Odnosnik, ktory prowadzi do sklepu/instrukcji dostawcy, to ta sama reklama co jego nazwa.
    """
    naruszajace = _naruszajace(lambda linia: any(o in linia for o in ODNOSNIKI_DOSTAWCY))
    assert not naruszajace, "widoczne odnosniki do dostawcy:\n" + "\n".join(naruszajace)


def test_panel_uzywa_naszego_znaku_i_stopki() -> None:
    """Nawigacja pokazuje nasz znak, a stopka mowi o AMFA/AMITRONIC.

    Sprawdzamy zarowno tekst zrodlowy (`messages.xlf`), jak i tlumaczenie polskie, bo konsola
    w labie chodzi po polsku.
    """
    nawigacja = (PANEL / "src" / "app" / "components" / "layout" / "navigation"
                 / "navigation.component.html").read_text(encoding="utf-8")
    assert "assets/amfa.svg" in nawigacja, "nawigacja nie uzywa naszego znaku"
    assert "privacyIDEA1.png" not in nawigacja and "logo-text.png" not in nawigacja, \
        "nawigacja wrocila do znakow podstawy"

    for plik, oczekiwane in ((PANEL / "src" / "locale" / "messages.xlf", "AMFA"),
                             (PANEL / "src" / "locale" / "messages.pl.xlf", "system uwierzytelniania AMITRONIC")):
        tresc = plik.read_text(encoding="utf-8") if plik.is_file() else ""
        blok = tresc.split('id="nav.openSourceProject"', 1)
        assert len(blok) == 2, f"{plik.name}: brak wpisu stopki"
        assert oczekiwane in blok[1][:400], f"{plik.name}: stopka nie mowi o AMFA"


def test_ikona_karty_jest_nasza() -> None:
    """Ikona karty przegladarki to nasz znak, nie ikona podstawy.

    Nowa podstawa przynosi wlasna ikone (niebieskie kolko); straznik pilnuje, ze podmiana
    w naszym drzewie nie zniknela i ze plik nie zostal podmieniony na cudzy.
    """
    ikona = PANEL / "public" / "assets" / "favicon.ico"
    assert ikona.is_file(), "brak ikony karty w zasobach panelu"
    skrot = hashlib.sha256(ikona.read_bytes()).hexdigest()
    assert skrot == "c6873772fa2775445676bfc9503200edff4f9d1ceef80f2473bd4b8170043320", \
        "ikona karty nie jest nasza (podstawa przyniosla wlasna?)"


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


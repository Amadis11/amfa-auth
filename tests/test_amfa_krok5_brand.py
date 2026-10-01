"""Straznicy zmian AMFA — krok 5, brand widocznej warstwy.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Uruchamianie w drzewie privacyIDEA:
    python -m pytest tests/test_amfa_krok5_brand.py -q
"""
from __future__ import annotations

import pathlib

KORZEN = pathlib.Path(__file__).resolve().parents[1]


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
    """Okna powitalne i wygasniecia subskrypcji usuniete — nie moga wrocic z nowa podstawa."""
    for wzgledna in ("privacyidea/static/src/app/components/shared/welcome-dialog",
                     "privacyidea/static/src/app/components/shared/subscription-expiry-dialog",
                     "privacyidea/static/src/app/services/subscription"):
        assert not (KORZEN / wzgledna).exists(), f"wrocilo {wzgledna}"
    zrodla = (KORZEN / "privacyidea" / "static" / "src" / "app").rglob("*.ts")
    for plik in zrodla:
        tresc = plik.read_text(encoding="utf-8")
        assert "WelcomeDialogService" not in tresc, f"wrocilo odwolanie w {plik}"
        assert "SubscriptionExpiryService" not in tresc, f"wrocilo odwolanie w {plik}"

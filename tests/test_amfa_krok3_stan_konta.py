"""Straznicy zmian AMFA — krok 3, stan konta z katalogu.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Uruchamianie w drzewie privacyIDEA:
    python -m pytest tests/test_amfa_krok3_stan_konta.py -q
"""
from __future__ import annotations

import pathlib

KORZEN = pathlib.Path(__file__).resolve().parents[1]

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
    resolver = (KORZEN / "privacyidea" / "lib" / "resolvers" / "LDAPIdResolver.py").read_text(encoding="utf-8")
    # Resolver podnosi stan, ale ponizszy `except Exception` zjadal go jako zwykla pomylke i zwracal False
    # (log 475 sasiadujacy z 484) - dlatego stan musi byc przepuszczony wyzej (zgloszenie #222).
    assert "except DirectoryPasswordState:" in resolver, "resolver polyka stan konta z katalogu"
    stan_kod = resolver.index("except DirectoryPasswordState:")
    zwykly_kod = resolver.index('Failed to check password for {uid!r}/{bind_user!r}')
    assert stan_kod < zwykly_kod, "przepuszczenie stanu musi stac przed obsluga zwyklej pomylki"
    uzytkownik = (KORZEN / "privacyidea" / "lib" / "user.py").read_text(encoding="utf-8")
    assert "except DirectoryPasswordState as stan:" in uzytkownik, "user.py polyka stan konta z katalogu"
    # Zapis na czas zadania: adnotacja na tokenie nie dochodzi do odpowiedzi, bo odpowiedz budowana jest
    # na swiezo pobieranych obiektach tokenow (zgloszenie #222).
    assert "zapamietaj_stan_katalogu(stan.state, self.login)" in uzytkownik
    dekoratory = (KORZEN / "privacyidea" / "lib" / "policydecorators.py").read_text(encoding="utf-8")
    assert 'token.auth_details["password_change_required"] = True' in dekoratory
    odpowiedz = (KORZEN / "privacyidea" / "lib" / "token" / "auth.py").read_text(encoding="utf-8")
    assert 'reply_dict["password_change_required"] = True' in odpowiedz
    assert "stany_katalogu_z_zadania()" in odpowiedz, "odpowiedz nie czyta stanu zapisanego na czas zadania"


def test_stan_konta_zyje_tyle_co_zadanie() -> None:
    """Stan rozpoznany przez katalog musi przetrwac do budowania odpowiedzi w tym samym zadaniu."""
    import sys
    sys.path.insert(0, str(KORZEN))
    from flask import Flask

    from privacyidea.lib.amfa_stan_katalogu import (stany_katalogu_z_zadania,
                                                     zapamietaj_stan_katalogu)

    # Poza zadaniem nie ma gdzie tego trzymac - i nie moze wybuchnac.
    assert stany_katalogu_z_zadania() == []

    aplikacja = Flask(__name__)
    with aplikacja.test_request_context("/validate/check"):
        zapamietaj_stan_katalogu("password_change_required", "amfa-test-zmiana")
        zapamietaj_stan_katalogu("password_change_required", "amfa-test-zmiana")
        zapamietaj_stan_katalogu("account_disabled", "amfa-test-wylaczone")
        assert stany_katalogu_z_zadania() == ["password_change_required", "account_disabled"]

    # Nastepne zadanie nie widzi stanu poprzedniego.
    with aplikacja.test_request_context("/validate/check"):
        assert stany_katalogu_z_zadania() == []

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


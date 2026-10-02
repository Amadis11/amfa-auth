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
    uzytkownik = (KORZEN / "privacyidea" / "lib" / "user.py").read_text(encoding="utf-8")
    assert "except DirectoryPasswordState:" in uzytkownik, "user.py polyka stan konta z katalogu"
    dekoratory = (KORZEN / "privacyidea" / "lib" / "policydecorators.py").read_text(encoding="utf-8")
    assert 'token.auth_details["password_change_required"] = True' in dekoratory
    odpowiedz = (KORZEN / "privacyidea" / "lib" / "token" / "auth.py").read_text(encoding="utf-8")
    assert 'reply_dict["password_change_required"] = True' in odpowiedz

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


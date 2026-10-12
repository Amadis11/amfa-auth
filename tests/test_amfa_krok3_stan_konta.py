"""Straznicy zmian AMFA — krok 3, stan konta z katalogu.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Uruchamianie w drzewie privacyIDEA (cwd = korzen podrepozytorium — atrapa LDAP trzyma katalog
względem katalogu roboczego):
    python -m pytest tests/test_amfa_krok3_stan_konta.py -q
    python tests/test_amfa_krok3_stan_konta.py            # bez pytest, wlasny runner nizej
"""
from __future__ import annotations

import os
import pathlib

KORZEN = pathlib.Path(__file__).resolve().parents[1]


# Konta katalogu AD w ksztalcie, jaki realnie zwraca Active Directory: bez `userPassword`
# (AD go nie oddaje), za to z atrybutami, po ktorych AD orzeka stan konta. `accountExpires`,
# `pwdLastSet` i `lockoutTime` to FILETIME (int64, 100-ns od 1.1.1601); `accountExpires` rowne
# 0 znaczy "nigdy nie wygasa", a `userAccountControl` ma bit ACCOUNTDISABLE (0x2).
AD_STANY = [
    {"dn": "cn=amfa-test-zmiana,ou=example,o=test",
     "attributes": {"cn": "amfa-test-zmiana", "sAMAccountName": "amfa-test-zmiana",
                    "userAccountControl": 512,          # NORMAL_ACCOUNT
                    "lockoutTime": 0,
                    "pwdLastSet": 133700000000000000,
                    "accountExpires": 9223372036854775807,   # nigdy
                    "msDS-UserPasswordExpiryTimeComputed": 133700000000000000}},
    {"dn": "cn=amfa-test-wylaczone,ou=example,o=test",
     "attributes": {"cn": "amfa-test-wylaczone", "sAMAccountName": "amfa-test-wylaczone",
                    "userAccountControl": 514,          # NORMAL_ACCOUNT | ACCOUNTDISABLE (0x2)
                    "lockoutTime": 0,
                    "pwdLastSet": 133700000000000000,
                    "accountExpires": 0}},
    {"dn": "cn=amfa-test-blokada,ou=example,o=test",
     "attributes": {"cn": "amfa-test-blokada", "sAMAccountName": "amfa-test-blokada",
                    "userAccountControl": 512,
                    "lockoutTime": 133600000000000000,  # niezerowy = zablokowane
                    "pwdLastSet": 133700000000000000,
                    "accountExpires": 0}},
    {"dn": "cn=amfa-test-konto-wyg,ou=example,o=test",
     "attributes": {"cn": "amfa-test-konto-wyg", "sAMAccountName": "amfa-test-konto-wyg",
                    "userAccountControl": 512,
                    "lockoutTime": 0,
                    "pwdLastSet": 133700000000000000,
                    "accountExpires": 131024988000000000}},   # FILETIME w przeszlosci
]

# Konfiguracja resolvera do pomiaru drogi katalog -> stan. UIDTYPE=DN pozwala podac DN wprost,
# wiec bind idzie od razu na konto, a nie najpierw na konto serwisowe.
KONFIG_AD = {
    "LDAPURI": "ldap://localhost",
    "LDAPBASE": "ou=example,o=test",
    "BINDDN": "cn=manager,ou=example,o=test",
    "BINDPW": "nie-uzywane",
    "LOGINNAMEATTRIBUTE": "sAMAccountName",
    "LDAPSEARCHFILTER": "(sAMAccountName=*)",
    "USERINFO": '{"username": "sAMAccountName", "surname": "sn", "givenname": "givenName"}',
    "UIDTYPE": "DN",
}


def _kod_ad(kod: str) -> dict:
    """Komunikat katalogu z kodem AD tak, jak go zwraca Active Directory."""
    return {"message": f"80090308: LdapErr: DSID-0C0904DC, comment: "
                       f"AcceptSecurityContext error, data {kod}, v3839"}


def test_stan_konta_z_katalogu_jest_rozpoznawany() -> None:
    """Krok 3: kody Active Directory musza byc rozpoznane, a nie zlane w jeden blad poswiadczen."""
    import sys
    sys.path.insert(0, str(KORZEN))
    from privacyidea.lib.resolvers.LDAPIdResolver import (AD_KODY_STANU_HASLA,
                                                          stan_hasla_z_odpowiedzi_katalogu)

    ad = _kod_ad
    # Pelna, obslugiwana mapa kodow — jeden przypadek na kazdy kod, na ktory resolver ma stan.
    # Rozjazd (usuniety albo przestawiony kod) ma wyjsc tu, a nie dopiero na labie.
    oczekiwane = {
        "525": "user_not_found",
        "52e": "invalid_credentials",
        "530": "logon_time_restriction",
        "531": "logon_restriction",
        "532": "password_expired",
        "533": "account_disabled",
        "701": "account_expired",
        "773": "password_change_required",
        "775": "account_locked",
    }
    assert AD_KODY_STANU_HASLA == oczekiwane, AD_KODY_STANU_HASLA
    for kod, stan in oczekiwane.items():
        assert stan_hasla_z_odpowiedzi_katalogu(ad(kod)) == stan, kod

    # Wariant komunikatu w innym ksztalcie: inny DSID (inne wersje/locale AD), wielkie litery
    # kodu, brak ogona "v...", konczacy srednik. Parser szuka znacznika "data <kod>", wiec tekst
    # wokol kodu nie moze zepsuc rozpoznania.
    warianty = [
        ("80090308: LdapErr: DSID-03190F84, comment: AcceptSecurityContext error, data 775, v4563",
         "account_locked"),
        ("80090308: LdapErr: DSID-0C0906E8, comment: AcceptSecurityContext error, data 52E",
         "invalid_credentials"),
        ("LdapErr: DSID-0C0904DC, comment: AcceptSecurityContext error, data 773;",
         "password_change_required"),
    ]
    for tekst, stan in warianty:
        assert stan_hasla_z_odpowiedzi_katalogu({"message": tekst}) == stan, tekst

    # Kody nieobslugiwane (m.in. 1792 — nie jest kodem stanu konta AD) nie moga dawac stanu.
    for kod in ("534", "1792", "0"):
        assert stan_hasla_z_odpowiedzi_katalogu(ad(kod)) is None, kod

    assert stan_hasla_z_odpowiedzi_katalogu({"description": "invalidCredentials"}) is None
    assert stan_hasla_z_odpowiedzi_katalogu({}) is None


def test_stany_kont_ad_dochodza_do_stanu() -> None:
    """Kazdy obslugiwany kod AD z katalogu ma dac stan konta — po jednym przypadku na kod.

    Droga jest pelna: atrapa LDAP zwraca komunikat katalogu (bind z kodem AD), resolver go
    rozpoznaje i podnosi `DirectoryPasswordState`. Kod `52e` (zwykle zle poswiadczenia) stanem
    nie jest — resolver ma wtedy zwrocic `False`, a nie zgadywac stan.
    """
    import sys
    sys.path.insert(0, str(KORZEN))
    katalog_roboczy = os.getcwd()
    os.chdir(KORZEN)  # atrapa LDAP trzyma katalog wzgledem katalogu roboczego
    try:
        from flask import Flask

        from tests import ldap3mock
        from privacyidea.lib.resolvers.LDAPIdResolver import (AD_KODY_STANU_HASLA,
                                                              DirectoryPasswordState,
                                                              IdResolver as LDAPResolver)

        dn = "cn=amfa-test-zmiana,ou=example,o=test"
        aplikacja = Flask(__name__)
        with aplikacja.app_context():
            for kod, oczekiwany in sorted(AD_KODY_STANU_HASLA.items()):
                with ldap3mock.mock:
                    ldap3mock.setLDAPDirectory(AD_STANY)
                    ldap3mock.set_bind_result(code=kod)
                    resolver = LDAPResolver()
                    resolver.loadConfig(KONFIG_AD)
                    try:
                        resolver.checkPass(dn, "niepoprawne-haslo")
                        stan = None
                    except DirectoryPasswordState as blad:
                        stan = blad.state
                    if oczekiwany == "invalid_credentials":
                        assert stan is None, f"kod {kod} nie moze byc stanem konta"
                    else:
                        assert stan == oczekiwany, f"kod {kod}: {stan!r} != {oczekiwany!r}"
    finally:
        os.chdir(katalog_roboczy)


def test_atrapa_ldap_zwraca_bledy_i_strony() -> None:
    """Atrapa LDAP musi umiec zwrocic blad katalogu, paginowac i odrzucic TLS.

    Bez tego kazdy test na atrapie zaklada sukces: bind/search zawsze wygrywaja, a regresja
    w obsludze kodow LDAP/AD, stron i TLS przechodzi niezauwazona.
    """
    import sys
    sys.path.insert(0, str(KORZEN))
    katalog_roboczy = os.getcwd()
    os.chdir(KORZEN)
    try:
        import ldap3
        from ldap3.core.exceptions import LDAPOperationResult, LDAPSocketOpenError

        from tests import ldap3mock

        def polacz(use_ssl: bool = False):
            serwer = ldap3.Server("localhost", port=636 if use_ssl else 389,
                                  use_ssl=use_ssl, connect_timeout=5)
            polaczenie = ldap3.Connection(serwer, user="cn=manager,ou=example,o=test",
                                          password="x", authentication=ldap3.SIMPLE,
                                          auto_bind=False)
            polaczenie.open()
            polaczenie.bind()
            return polaczenie

        # (a) bind zwraca kod LDAP 49 z podkodem AD w komunikacie
        with ldap3mock.mock:
            ldap3mock.setLDAPDirectory(AD_STANY)
            ldap3mock.set_bind_result(code="775")
            c = polacz()
            assert c.bind() is False
            assert c.result["result"] == 49, c.result
            assert "data 775" in c.result["message"], c.result

        # (b) search: pusty wynik (result 0) rozny od bledu katalogu
        with ldap3mock.mock:
            ldap3mock.setLDAPDirectory(AD_STANY)
            c = polacz()
            c.search(search_base="o=test", search_filter="(&(cn=*))", search_scope=ldap3.SUBTREE,
                     attributes=ldap3.ALL_ATTRIBUTES)
            assert c.result["result"] == 0 and c.result["description"] == "success", c.result
            assert len(c.response) == len(AD_STANY)
            for kod, opis in ((4, "sizeLimitExceeded"), (32, "noSuchObject"),
                              (50, "insufficientAccess")):
                ldap3mock.set_search_result(result=kod, description=opis)
                c = polacz()
                c.search(search_base="o=test", search_filter="(&(cn=*))",
                         search_scope=ldap3.SUBTREE, attributes=ldap3.ALL_ATTRIBUTES)
                assert c.result["result"] == kod, c.result
                assert c.result["description"] == opis, c.result
                if kod != 4:
                    assert c.response == [], c.response
            # pusty wynik bez bledu
            ldap3mock.set_search_result(result=0, description="success")
            c = polacz()
            c.search(search_base="o=test", search_filter="(&(cn=nie-ma-takiego))",
                     search_scope=ldap3.SUBTREE, attributes=ldap3.ALL_ATTRIBUTES)
            assert c.result["result"] == 0 and c.response == [], (c.result, c.response)

        # (c) paged_search respektuje rozmiar strony i cookie — nic nie ginie
        with ldap3mock.mock:
            ldap3mock.setLDAPDirectory(AD_STANY)
            c = polacz()
            zebrane, cookie, stron = [], None, 0
            for _ in range(len(AD_STANY) + 2):
                strona = c.extend.standard.paged_search(
                    search_base="o=test", search_filter="(&(cn=*))", search_scope=ldap3.SUBTREE,
                    attributes=ldap3.ALL_ATTRIBUTES, paged_size=1, paged_cookie=cookie)
                stron += 1
                assert len(strona) <= 1, strona
                zebrane += [wpis["dn"] for wpis in strona]
                cookie = c.result["controls"]["1.2.840.113556.1.4.319"]["value"]["cookie"]
                if not cookie:
                    break
            assert stron == len(AD_STANY), stron
            assert len(zebrane) == len(AD_STANY), zebrane
            assert len(set(zebrane)) == len(AD_STANY), zebrane
            # generator=True przechodzi wszystkie strony tak samo
            generator = c.extend.standard.paged_search(
                search_base="o=test", search_filter="(&(cn=*))", search_scope=ldap3.SUBTREE,
                attributes=ldap3.ALL_ATTRIBUTES, paged_size=2, generator=True)
            wszystkie = [wpis["dn"] for wpis in generator]
            assert len(wszystkie) == len(AD_STANY), wszystkie

        # (d) set_exception rzuca podklase ldap3 z kodem, nie goly Exception
        with ldap3mock.mock:
            ldap3mock.setLDAPDirectory(AD_STANY)
            ldap3mock.set_exception()
            try:
                polacz()
                assert False, "set_exception nie podnioslo wyjatku"
            except LDAPSocketOpenError:
                pass
            finally:
                ldap3mock.set_exception(False)
            ldap3mock.set_exception(LDAPOperationResult(result=4, description="sizeLimitExceeded"))
            try:
                polacz()
                assert False, "set_exception(instancja) nie podnioslo wyjatku"
            except LDAPOperationResult as blad:
                assert blad.result == 4, blad
            finally:
                ldap3mock.set_exception(False)

        # (e) TLS odrzucony: polaczenie z TLS nie wstaje, a serwer widzi, o co pytalismy
        with ldap3mock.mock:
            ldap3mock.setLDAPDirectory(AD_STANY)
            ldap3mock.set_tls_rejected()
            try:
                polacz(use_ssl=True)
                assert False, "odrzucony TLS nie przerwal polaczenia"
            except LDAPSocketOpenError:
                pass
            assert any(opcja["use_ssl"] for opcja in ldap3mock.mock.server_options), \
                ldap3mock.mock.server_options
    finally:
        os.chdir(katalog_roboczy)


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

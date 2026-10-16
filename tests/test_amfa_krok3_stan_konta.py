"""Straznicy zmian AMFA — krok 3, stan konta z katalogu.

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Uruchamianie w drzewie privacyIDEA (cwd = korzen podrepozytorium — atrapa LDAP trzyma katalog
względem katalogu roboczego):
    python -m pytest tests/test_amfa_krok3_stan_konta.py -q
    python tests/test_amfa_krok3_stan_konta.py            # bez pytest, wlasny runner nizej

Zgloszone do podstawy jako privacyidea/privacyidea#6127 (16.10.2026): jesli upstream zacznie
odroznian stan konta w katalogu, nasz patch (odwzorowanie kodow danych AD + sciezka zaufanego
klienta) wypada razem z tym straznikiem — sprawdz zgloszenie przy kolejnym nalorzeniu wydania.
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
    # Warstwa polityk nie musi juz znac stanu na tokenie: konwersja na zwykla odmowe jest w
    # `User.check_password`, a stan jedzie do odpowiedzi i rejestru przez `lib/amfa_stan_katalogu.py`
    # (zgloszenie #32).
    assert 'token.auth_details["password_change_required"] = True' not in dekoratory
    odpowiedz = (KORZEN / "privacyidea" / "lib" / "token" / "auth.py").read_text(encoding="utf-8")
    assert "stany_katalogu_z_zadania()" in odpowiedz, "odpowiedz nie czyta stanu zapisanego na czas zadania"
    # Stan konta nie moze juz trafiac do odpowiedzi bezwarunkowo: pola dokłada wspolna bramka
    # `directory_reply_keys`, ktora przepuszcza je tylko zaufana sciezka (zgloszenie #31).
    assert 'reply_dict["password_change_required"] = True' not in odpowiedz, \
        "stan konta trafia do odpowiedzi bez bramki zaufanej sciezki"
    assert "reply_dict.update(directory_reply_keys(stany_katalogu))" in odpowiedz
    assert "record_directory_states(stany_katalogu)" in odpowiedz, \
        "klasyfikacja musi trafiac do rejestru rowniez wtedy, gdy nie idzie do odpowiedzi"


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


def test_katalog_niedostepny_to_nie_zle_poswiadczenia() -> None:
    """Katalog nieosiagalny (LDAP/DC down) musi byc odrozniony od zlych poswiadczen.

    Atrapa umie rzucic blad gniazda (`set_exception`). Resolver ma wtedy podniesc
    `DirectoryUnavailable`, a NIE zwrocic `False`: bez tego kazdy przypadek niedostepnego katalogu
    wyglada jak zwykla pomylka poswiadczen ("wrong otp pin"), uzytkownik powtarza proby i wpada
    w blokade AD. Zle haslo i konto usuniete nadal zwracaja `False`, bez zadnego stanu konta.
    """
    import sys
    sys.path.insert(0, str(KORZEN))
    katalog_roboczy = os.getcwd()
    os.chdir(KORZEN)
    try:
        from flask import Flask

        from tests import ldap3mock
        from privacyidea.lib.resolvers.LDAPIdResolver import (DirectoryPasswordState,
                                                              DirectoryUnavailable,
                                                              IdResolver as LDAPResolver)

        dn = "cn=amfa-test-zmiana,ou=example,o=test"
        aplikacja = Flask(__name__)
        with aplikacja.app_context():
            # (a) blad gniazda = katalog nieosiagalny -> wlasny wyjatek, nie False
            with ldap3mock.mock:
                ldap3mock.setLDAPDirectory(AD_STANY)
                ldap3mock.set_exception()
                resolver = LDAPResolver()
                resolver.loadConfig(KONFIG_AD)
                try:
                    wynik = resolver.checkPass(dn, "jakiekolwiek-haslo")
                    assert False, f"katalog nieosiagalny zwrocil {wynik!r} zamiast podniesc blad"
                except DirectoryPasswordState as blad:
                    assert False, f"katalog nieosiagalny zgloszony jako stan konta: {blad.state!r}"
                except DirectoryUnavailable:
                    pass
                finally:
                    ldap3mock.set_exception(False)

            # (b) zle haslo to nadal zwykla odmowa (False), bez stanu konta
            with ldap3mock.mock:
                ldap3mock.setLDAPDirectory(AD_STANY)
                resolver = LDAPResolver()
                resolver.loadConfig(KONFIG_AD)
                assert resolver.checkPass(dn, "zle-haslo") is False
                # (c) konto usuniete (DN poza katalogiem) to tez zwykla odmowa, bez stanu
                assert resolver.checkPass("cn=amfa-usuniete,ou=example,o=test", "x") is False
    finally:
        os.chdir(katalog_roboczy)

    # Straznik drogi: resolver musi podniesc wlasny typ przy bledzie gniazda/puli (nie zwrocic False),
    # a lib/user.py musi go zlapac i zapamietac stan `directory_unavailable` na czas zadania - inaczej
    # odpowiedz /validate/check nie niesie go maszynowo i dostawca nie ma z czego zbudowac komunikatu.
    resolver_zrodlo = (KORZEN / "privacyidea" / "lib" / "resolvers" / "LDAPIdResolver.py").read_text(encoding="utf-8")
    assert "except (LDAPSocketOpenError, LDAPServerPoolExhaustedError) as e:" in resolver_zrodlo
    assert "raise DirectoryUnavailable(" in resolver_zrodlo
    uzytkownik = (KORZEN / "privacyidea" / "lib" / "user.py").read_text(encoding="utf-8")
    assert "except DirectoryUnavailable:" in uzytkownik, "user.py nie lapie DirectoryUnavailable"
    assert 'zapamietaj_stan_katalogu("directory_unavailable", self.login)' in uzytkownik


def test_konto_usuniete_904_rozne_od_zlego_hasla() -> None:
    """Konto usuniete w trakcie sesji (904) musi byc odroznione od zlego hasla.

    Brak uzytkownika w katalogu to kod bledu `904` (`Error.USER`) - maszynowo rozroznialny i inny
    niz odmowa poswiadczenia (`AUTHENTICATE_WRONG_CREDENTIALS`). Resolver przy usunietym koncie nie
    zglasza zadnego stanu konta (patrz test wyzej), wiec 904 nie moze zostac zlane ze zlym haslem
    ani z bledem OTP. Ksztalt odpowiedzi 904 na `/validate/check` pilnuje `tests/test_api_validate.py`.
    """
    import sys
    sys.path.insert(0, str(KORZEN))
    from privacyidea.lib.error import Error

    assert Error.USER == 904, Error.USER
    assert Error.USER != Error.AUTHENTICATE_WRONG_CREDENTIALS

    # Straznik zrodla: nieznany uzytkownik konczy sie `UserError` (904), a nie `AuthError` zlych
    # poswiadczen - te dwie drogi musza zostac rozdzielone.
    dekoratory = (KORZEN / "privacyidea" / "lib" / "policydecorators.py").read_text(encoding="utf-8")
    assert 'raise UserError(f"User {user_object} does not exist.")' in dekoratory
    assert 'raise AuthError("", id=Error.AUTHENTICATE_WRONG_CREDENTIALS)' in dekoratory


def test_kanal_stanu_konta_tylko_zaufana_sciezka() -> None:
    """Stan konta wychodzi z silnika wylacznie zaufana sciezka (zgloszenie #31).

    Stany `password_expired` i `password_change_required` wystepuja tylko po poprawnym hasle, wiec
    w ogolnej odpowiedzi `/validate/check` byly oracle poprawnosci hasla. Teraz pola doklada
    `directory_reply_keys`, ktore przepuszcza je tylko wtedy, gdy zadanie przyszlo z sekretem
    zaufanego klienta; bez skonfigurowanego sekretu nie ma sygnalu nigdzie (fail-closed).
    """
    import sys
    sys.path.insert(0, str(KORZEN))
    from flask import Flask

    from privacyidea.lib import amfa_stan_katalogu as modul
    from privacyidea.lib.amfa_stan_katalogu import (REVEALED_STATES, TRUST_MARKER_HEADER,
                                                    directory_reply_keys, is_trusted_client_request,
                                                    states_to_reveal)
    from privacyidea.lib.config import SYSCONF

    # Klucz ustawienia jest kontraktem z wdrozeniem (ustawienia.cfg na wezle).
    assert SYSCONF.TRUSTED_CLIENT_SECRET == "TrustedClientSecret"

    # Decyzja wlasciciela (13.10.2026): po poprawnym hasle pokazujemy wymagana zmiane, wygasle haslo,
    # konto zablokowane i wylaczone; nieistniejace i wygasle konto zostaja bez sygnalu.
    assert REVEALED_STATES == {"password_change_required", "password_expired",
                               "account_locked", "account_disabled"}
    assert states_to_reveal(["account_locked", "user_not_found", "password_expired"]) == \
        ["account_locked", "password_expired"]
    assert states_to_reveal(["user_not_found", "account_expired"]) == []

    # Zrodlem sekretu jest konfiguracja silnika, ktora w tym strazniku podstawiamy: poza aplikacja
    # privacyIDEA czytanie konfiguracji idzie do bazy, a straznik nie stawia bazy.
    oryginalne_czytanie = modul.get_from_config
    konfiguracja: dict[str, str] = {}
    modul.get_from_config = lambda klucz, domyslne=None, **_k: konfiguracja.get(klucz, domyslne)
    try:
        aplikacja = Flask(__name__)
        # Bez sekretu w konfiguracji nie ma zaufanej sciezki — takze dla poprawnego hasla na wygaslym koncie.
        with aplikacja.test_request_context("/validate/check"):
            assert is_trusted_client_request() is False
            assert directory_reply_keys({"password_expired"}) == {}
            assert directory_reply_keys({"account_locked"}) == {}

        konfiguracja["TrustedClientSecret"] = "sekret-labu"
        # Zly naglowek i brak naglowka nie wystarczaja.
        with aplikacja.test_request_context("/validate/check",
                                            headers={TRUST_MARKER_HEADER: "nie-ten"}):
            assert is_trusted_client_request() is False
            assert directory_reply_keys({"account_locked"}) == {}
        with aplikacja.test_request_context("/validate/check"):
            assert directory_reply_keys({"account_locked"}) == {}

        # Zaufany klient dostaje tylko to, co wolno: nieistniejace konto nie jest zdradzane.
        with aplikacja.test_request_context("/validate/check",
                                            headers={TRUST_MARKER_HEADER: "sekret-labu"}):
            assert is_trusted_client_request() is True
            assert directory_reply_keys({"account_locked", "user_not_found"}) == {
                "password_change_required": True,
                "directory_password_state": ["account_locked"]}
            assert directory_reply_keys({"user_not_found"}) == {}
    finally:
        modul.get_from_config = oryginalne_czytanie


def test_klasyfikacja_stanu_konta_trafia_do_rejestru() -> None:
    """Stany trafiaja do rejestru zadania niezaleznie od tego, czy wolno je pokazac.

    Gdy sygnal nie idzie do odpowiedzi, rejestr jest jedynym miejscem, w ktorym widac, ze konto
    bylo wygasle, a nie ze haslo bylo zle.
    """
    import sys
    sys.path.insert(0, str(KORZEN))
    from flask import Flask, g

    from privacyidea.lib.amfa_stan_katalogu import record_directory_states

    class Rejestr:
        def __init__(self):
            self.wpisy = []

        def add_to_log(self, wpis, add_with_comma=False):
            self.wpisy.append((dict(wpis), add_with_comma))

    aplikacja = Flask(__name__)
    with aplikacja.test_request_context("/validate/check"):
        rejestr = Rejestr()
        g.audit_object = rejestr
        record_directory_states({"user_not_found", "account_locked", "account_locked"})
        assert rejestr.wpisy == [({"action_detail":
                                   "directory_password_state: account_locked, user_not_found"}, True)], \
            rejestr.wpisy

    # Bez rejestru i poza zadaniem nic sie nie dzieje i nic nie wybucha.
    with aplikacja.test_request_context("/validate/check"):
        record_directory_states({"account_locked"})
    record_directory_states({"account_locked"})


def test_stan_konta_nie_ucieka_jako_wyjatek() -> None:
    """Stan konta konczy sie zwykla odmowa, a nie wyjatkiem na sciezce logowania (zgloszenie #32).

    `DirectoryPasswordState` dziedziczy po `ResolverError`, a sciezki logowania lapia tylko
    `UserError`/`AuthError` - wyjatek wychodzil wiec jako odpowiedz bledu serwera, a przerwany
    przeplyw pomijal inkrementacje licznika nieudanych prob (czyli oslabial blokade konta).
    Konwersja jest w jednym miejscu: `User.check_password` zapamietuje stan na czas zadania i zwraca
    `None`, wiec kazdy wolajacy widzi zwykla odmowe.
    """
    uzytkownik = (KORZEN / "privacyidea" / "lib" / "user.py").read_text(encoding="utf-8")
    poczatek = uzytkownik.index("except DirectoryPasswordState as stan:")
    galez = uzytkownik[poczatek:].split("except DirectoryUnavailable")[0]
    assert "zapamietaj_stan_katalogu(stan.state, self.login)" in galez
    assert "return None" in galez, "user.py nie konczy zwykla odmowa"
    assert "raise" not in galez, "user.py przepuszcza stan konta jako wyjatek na sciezke logowania"

    # Jedno miejsce konwersji: poza resolverem (ktory podnosi wyjatek wewnatrz siebie, zeby nie zjadl go
    # jego wlasny `except Exception`) nikt go nie lapie - ani warstwa polityk, ani API.
    zlapania = {}
    for plik in sorted((KORZEN / "privacyidea").rglob("*.py")):
        ile = plik.read_text(encoding="utf-8").count("except DirectoryPasswordState")
        if ile:
            zlapania[str(plik.relative_to(KORZEN))] = ile
    assert zlapania == {"privacyidea/lib/resolvers/LDAPIdResolver.py": 1,
                        "privacyidea/lib/user.py": 1}, zlapania

    # Warstwa polityk (otppin=userstore) nie stempluje PASSWORD_FAIL, gdy katalog rozpoznal stan konta:
    # haslo bylo wtedy poprawne, a PASSWORD_FAIL liczy sie w politykach progu nieudanych prob.
    dekoratory = (KORZEN / "privacyidea" / "lib" / "policydecorators.py").read_text(encoding="utf-8")
    assert "stany_katalogu_z_zadania()" in dekoratory
    assert "except DirectoryPasswordState" not in dekoratory


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

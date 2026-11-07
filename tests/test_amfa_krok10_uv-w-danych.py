"""Straznicy zmian AMFA — krok 10, polityka UV jedzie z danymi offline (#427).

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Po co te strazniki: decyzja wlasciciela jest taka, ze o tym, czego wymagac offline, decyduje
serwer, a klient tylko wykonuje polityke. Ladunek offline nie mial dotad zadnego pola o user
verification, wiec klient nie mial skad wziac tej polityki. Nowa podstawa moze po cichu wrocic do
ladunku bez tego pola (np. przy przepisywaniu `get_authentication_item`) — wtedy ten plik ma
zapalic sie w bramie wydania, a nie dopiero wtedy, gdy ktos policzy „sam klucz" jako drugi
skladnik bez wymuszonego UV.

Uruchamianie w drzewie privacyIDEA (potrzebne sa zaleznosci podstawy, m.in. `flask`):
    .venv/bin/python tests/test_amfa_krok10_uv-w-danych.py      # bez pytest, kod 0/1
    .venv/bin/python -m pytest tests/test_amfa_krok10_uv-w-danych.py -q
"""
from __future__ import annotations

import pathlib
import sys

KORZEN = pathlib.Path(__file__).resolve().parents[1]
OFFLINE = KORZEN / "privacyidea" / "lib" / "applications" / "offline.py"
PREPOLICY = KORZEN / "privacyidea" / "api" / "lib" / "prepolicy.py"
POSTPOLICY = KORZEN / "privacyidea" / "api" / "lib" / "postpolicy.py"
VALIDATE = KORZEN / "privacyidea" / "api" / "validate.py"

#: Nazwa pola, ktore czyta klient (`CppClient/JsonParser.cpp`). Zmiana nazwy to zerwanie kontraktu.
POLE_UV = "userVerification"

#: Wartosci, ktore pole moze przyjac (poziom user verification z FIDO2).
WARTOSCI_UV = ("required", "preferred", "discouraged")

#: Nazwa klienta, ktora wysyla nasz dostawca poswiadczen — bez nazwy maszyny nie ma ladunku FIDO2.
UA_DOSTAWCY = "amfa-cp/1.0.0 Windows/PC-LAB"


class _AtrapaTokenu:
    """Token atrapa: tylko to, czego `offline.py` siega przy skladaniu ladunku. Bez bazy."""

    def __init__(self, typ: str):
        self.type = typ
        self.user = None
        self._klucz = b"a-credential-id"
        self.token = self

    def get_tokeninfo(self, klucz: str):
        return {"pubKey": "a5b1d7", "public_key": "a5b1d7", "relying_party_id": "netknights.it"}.get(klucz)

    def decrypt_otpkey(self) -> str:
        return self._klucz.decode("utf-8")

    def get_otpkey(self):
        return _AtrapaKlucza(self._klucz)


class _AtrapaKlucza:
    def __init__(self, wartosc: bytes):
        self._wartosc = wartosc

    def getKey(self) -> bytes:
        return self._wartosc


def _ladunek_offline(typ: str, user_verification, challenge=None):
    """Ladunek offline tak, jak go sklada silnik — z atrapa tokenu i bez bazy danych."""
    from unittest import mock

    sys.path.insert(0, str(KORZEN))
    from privacyidea.lib.applications import offline as modul

    # Krok 13 (#audyt plaster 04, Z4) czyta zapisany refilltoken ZANIM go zalozy: nazwa maszyny
    # liczy sie z `get_computer_name_from_user_agent`, ktore siega konfiguracji aplikacji. Harness
    # jest celowo bez kontekstu aplikacji i bez bazy, wiec nazwe maszyny podstawiamy tak samo jak
    # `generate_new_refilltoken` nizej — inaczej krok 10 padalby na cudzej zmianie.
    with mock.patch.object(modul, "get_one_token", return_value=_AtrapaTokenu(typ)), \
            mock.patch.object(modul, "get_computer_name_from_user_agent", return_value="PC-LAB"), \
            mock.patch.object(modul.MachineApplication, "generate_new_refilltoken",
                              return_value="a" * 2 * modul.REFILLTOKEN_LENGTH), \
            mock.patch.object(modul.MachineApplication, "get_offline_otps", return_value={"1": "hash"}):
        return modul.MachineApplication.get_authentication_item(typ, "AMFA0001", challenge=challenge,
                                                                user_agent=UA_DOSTAWCY,
                                                                user_verification=user_verification)


def test_webauthn_i_passkey_wioza_polityke_uv() -> None:
    """Ladunek offline klucza niesie wartosc polityki UV, a pola wpisu zostaja te same."""
    for typ in ("webauthn", "passkey"):
        for wartosc in WARTOSCI_UV:
            ladunek = _ladunek_offline(typ, wartosc)
            odp = ladunek.get("response")
            assert odp.get(POLE_UV) == wartosc, f"{typ}: pole {POLE_UV} nie jedzie z danymi ({odp!r})"
            # Pola, po ktorych klient rozpoznaje typ wpisu i weryfikuje asercje, zostaja nietkniete.
            for pole in ("pubKey", "credentialId", "rpId"):
                assert pole in odp, f"{typ}: zniknelo pole {pole}"
            assert set(odp) == {"pubKey", "credentialId", "rpId", POLE_UV}, \
                f"{typ}: zmienil sie zestaw pol odpowiedzi: {sorted(odp)}"
            assert ladunek.get("refilltoken")


def test_hotp_nie_dostaje_pola_uv() -> None:
    """Kod offline (HOTP) to mapa licznikow — pole UV nie ma tam czego szukac."""
    ladunek = _ladunek_offline("hotp", "required")
    assert POLE_UV not in ladunek.get("response"), "pole UV trafilo do ladunku HOTP"
    # I nie ma go takze w zrodle na sciezce HOTP: pomocnik jest wolany tylko w galeziach FIDO2.
    zrodlo = OFFLINE.read_text(encoding="utf-8")
    assert zrodlo.count("_add_user_verification(ret[\"response\"]") == 2, \
        "pomocnik UV nie jest wolany dokladnie dwa razy (webauthn, passkey)"
    assert f'"{POLE_UV}"' in zrodlo, f"zrodlo nie zna nazwy pola {POLE_UV}"


def test_brak_wartosci_nie_dodaje_pola() -> None:
    """Wolajacy bez kontekstu polityki (np. API `/machine/authitem`) nie dostaje pola z `null`."""
    for typ in ("webauthn", "passkey"):
        assert POLE_UV not in _ladunek_offline(typ, None).get("response"), typ


def test_pomocnik_polityki_uv_ma_bezpieczna_domyslna_wartosc() -> None:
    """Rozstrzygniecie polityki ma domyslna wartosc i nie wywraca odpowiedzi przy zlej konfiguracji."""
    zrodlo = PREPOLICY.read_text(encoding="utf-8")
    blok = zrodlo.split("def get_user_verification_requirement(", 1)[1].split("\ndef ", 1)[0]
    assert "Match.user(" in blok, "polityka UV nie jest rozstrzygana przez Match.user"
    assert "DEFAULT_USER_VERIFICATION_REQUIREMENT" in blok, "brak domyslnej wartosci polityki UV"
    assert "USER_VERIFICATION_LEVELS" in blok, "brak sprawdzenia dopuszczalnych wartosci"
    assert "write_to_audit_log=False" in blok, "rozstrzygniecie polityki UV zapisuje sie do audytu"
    # Domyslna wartosc musi byc ta sama, ktora widzi klient online.
    from privacyidea.lib.tokens.webauthntoken import DEFAULT_USER_VERIFICATION_REQUIREMENT
    assert DEFAULT_USER_VERIFICATION_REQUIREMENT in WARTOSCI_UV


def test_konflikt_uv_zwraca_domyslna_wartosc_i_nie_usuwa_offline() -> None:
    """Konflikt dwoch polityk UV nie odbiera HOTP/FIDO2 partii ani nie rzuca wyjatku (#72)."""
    from unittest import mock
    from privacyidea.api.lib import prepolicy as modul
    from privacyidea.lib.error import PolicyError
    from privacyidea.lib.policy import SCOPE
    from privacyidea.lib.tokens.webauthntoken import DEFAULT_USER_VERIFICATION_REQUIREMENT as domyslna

    with mock.patch.object(modul.Match, "user") as dopasowanie, \
            mock.patch.object(modul.log, "warning") as ostrzezenie:
        dopasowanie.return_value.action_values.side_effect = PolicyError(
            "Conflicting webauthn_user_verification_requirement values"
        )
        wartosc = modul.get_user_verification_requirement(SCOPE.AUTH)
        assert wartosc == domyslna, "konflikt polityk musi bezpiecznie uzyc domyslnego UV"
        assert dopasowanie.return_value.action_values.call_args.kwargs["unique"] is True
        ostrzezenie.assert_called_once()
    for typ in ("webauthn", "passkey"):
        ladunek = _ladunek_offline(typ, wartosc)
        assert ladunek["response"][POLE_UV] == domyslna
        assert ladunek.get("refilltoken"), "konflikt UV nie moze usunac tokenu uzupelniania"


def test_polityka_uv_zgodna_pusta_i_nieprawidlowa() -> None:
    """Zwykla polityka, jej brak i zla wartosc zachowuja dotychczasowy kontrakt."""
    from unittest import mock
    from privacyidea.api.lib import prepolicy as modul
    from privacyidea.lib.policy import SCOPE
    from privacyidea.lib.tokens.webauthntoken import DEFAULT_USER_VERIFICATION_REQUIREMENT as domyslna

    for wartosci, oczekiwana, ostrzezenia in (
        (["required"], "required", 0),
        (["discouraged"], "discouraged", 0),
        ([], domyslna, 0),
        (["invalid-uv"], domyslna, 1),
    ):
        with mock.patch.object(modul.Match, "user") as dopasowanie, \
                mock.patch.object(modul.log, "warning") as warning:
            dopasowanie.return_value.action_values.return_value = wartosci
            wynik = modul.get_user_verification_requirement(SCOPE.AUTH)
            assert wynik == oczekiwana, (wartosci, wynik, oczekiwana)
            assert warning.call_count == ostrzezenia, (wartosci, warning.call_count)


def test_konflikt_uv_nie_usuwa_podpisanego_ladunku_postpolicy() -> None:
    """Cala sciezka offline_info nadal publikuje ladunek przy konflikcie UV (#72)."""
    import json
    from types import SimpleNamespace
    from unittest import mock
    from flask import Flask, g
    from privacyidea.api.lib import prepolicy as modul, postpolicy
    from privacyidea.lib.error import PolicyError
    from privacyidea.lib.tokens.webauthntoken import DEFAULT_USER_VERIFICATION_REQUIREMENT as domyslna

    class Odpowiedz:
        def __init__(self):
            self.json = {"result": {"value": True}, "detail": {"serial": "AMFA-TEST-UV"}}
            self.data = None

        def set_data(self, value):
            self.data = value

    app = Flask(__name__)
    with app.test_request_context("/validate/check"):
        g.client_ip = "127.0.0.1"
        request = SimpleNamespace(
            all_data={"pass": "test-otp-pin"},
            user_agent=SimpleNamespace(string=UA_DOSTAWCY),
            User=None,
        )
        response = Odpowiedz()
        with mock.patch.object(modul.Match, "user") as dopasowanie, \
                mock.patch.object(postpolicy, "get_auth_items", return_value={
                    "offline": [{"serial": "AMFA-TEST-UV", "response": {"userVerification": domyslna}}]
                }) as get_items, \
                mock.patch("privacyidea.lib.amfa_offline_signatures.signed_auth_items",
                           side_effect=lambda items: items), \
                mock.patch.object(postpolicy, "db") as db:
            dopasowanie.return_value.action_values.side_effect = PolicyError("UV conflict")
            assert postpolicy.offline_info(request, response) is response
            assert response.data is not None, "konflikt UV nie moze wylaczyc signed offline payload"
            ladunek = json.loads(response.data)
            assert len(ladunek["auth_items"]["offline"]) == 1
            assert get_items.call_args.kwargs["user_verification"] == domyslna
            db.session.commit.assert_called_once()
            db.session.rollback.assert_not_called()


def test_obie_sciezki_offline_przekazuja_wartosc_polityki() -> None:
    """Wartosc liczy sie tam, gdzie jest kontekst polityki, i jest przekazana do ladunku offline."""
    postpolicy = POSTPOLICY.read_text(encoding="utf-8")
    blok = postpolicy.split("def offline_info(", 1)[1].split("\ndef ", 1)[0]
    assert "get_user_verification_requirement(" in blok, "offline_info nie rozstrzyga polityki UV"
    assert "user_verification=user_verification" in blok, "offline_info nie przekazuje polityki UV"

    validate = VALIDATE.read_text(encoding="utf-8")
    blok = validate.split("def _handle_fido2_auth(", 1)[1].split("\ndef ", 1)[0]
    assert "ENROLL_VIA_MULTICHALLENGE_PASSKEY_OFFLINE" in blok, "zmienil sie warunek ladunku przy enrollu"
    assert "get_user_verification_requirement(" in blok, "enroll po multichallenge nie rozstrzyga polityki UV"
    assert "user_verification=user_verification" in blok, "enroll nie przekazuje polityki UV"

    # Pole jest czescia odpowiedzi, a nie dodatkiem na najwyzszym poziomie wpisu.
    assert 'response["userVerification"]' in OFFLINE.read_text(encoding="utf-8")


def test_sciezka_online_bez_zmian() -> None:
    """Zadne istniejace pole ladunku nie zniknelo, a sciezka online nie zalezy od nowego pola."""
    zrodlo = OFFLINE.read_text(encoding="utf-8")
    for pole in ('"pubKey"', '"credentialId"', '"rpId"', '"refilltoken"', '"userId"'):
        assert pole in zrodlo, f"zniknelo istniejace pole ladunku: {pole}"


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

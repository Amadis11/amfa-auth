"""Straznicy zmian AMFA — krok 13, stan konta bez znacznika klienta zaufanego (#1030, wariant D).

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Decyzja wlasciciela (wariant D): silnik ujawnia stan katalogu **sam** — bez znacznika od klienta
i bez nowego sekretu wdrozeniowego — pod regula neutralnosci. Ten plik pilnuje trzech rzeczy:

1. **Nie ma odbiorcy znacznika**: w kodzie silnika nie zostalo nic, co czyta naglowek
   `X-AMFA-Trusted-Client`, sekret `TrustedClientSecret` ani jakiekolwiek ustawienie bramkujace
   ujawnienie. Brak odbiorcy jest tu funkcja, nie brakiem: dopoki znacznik istnial, droga stacji
   wymagala wdrozenia nowego sekretu na kazdej stacji (a odbiorcy w produkcie nigdy nie bylo, wiec
   stan nie opuszczal silnika).
2. **Regula neutralnosci ma zeby**: te same pola dla kazdego wolajacego (naglowek nic nie zmienia),
   zadnej zmiany komunikatu ani kodu odpowiedzi, zadnego nieistniejacego ani wygaslego konta
   (enumeracja), i nadal tylko stany z listy `REVEALED_STATES` (decyzja z 13.10.2026).
3. **Powierzchnie zostaja tam, gdzie byly**: brama odpowiada ogolna odmowa i zapisuje stan w dzienniku
   (#428/#563), a stacja ma wlasne, neutralne komunikaty (#131). Silnik dokłada wylacznie dane.

Uruchamianie w drzewie privacyIDEA (cwd = korzen podrepozytorium):
    python -m pytest tests/test_amfa_krok13_stan-konta-bez-znacznika.py -q
    python tests/test_amfa_krok13_stan-konta-bez-znacznika.py       # bez pytest, wlasny runner nizej
"""
from __future__ import annotations

import pathlib
import sys

KORZEN = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KORZEN))

from privacyidea.lib.amfa_stan_katalogu import (DIRECTORY_REPLY_KEYS, REVEALED_STATES,  # noqa: E402
                                                directory_reply_keys, states_to_reveal)
from privacyidea.lib.config import SYSCONF  # noqa: E402

#: Nazwy, ktorych nie moze juz byc w silniku: znacznik klienta zaufanego i sekret, ktorym byl bramkowany.
USUNIETE_NAZWY = ("X-AMFA-Trusted-Client", "TrustedClientSecret", "TRUST_MARKER_HEADER",
                  "is_trusted_client_request", "TRUSTED_CLIENT_SECRET")


def _zrodlo_modulu() -> str:
    return (KORZEN / "privacyidea" / "lib" / "amfa_stan_katalogu.py").read_text(encoding="utf-8")


def test_silnik_ujawnia_stan_kazdemu_wolajacemu() -> None:
    """Ten sam stan dla kazdego wolajacego: naglowek (takze podrobiony) niczego nie zmienia."""
    from flask import Flask

    aplikacja = Flask(__name__)
    stan = {"password_change_required"}
    with aplikacja.test_request_context("/validate/check"):
        bez_naglowka = directory_reply_keys(stan)
    with aplikacja.test_request_context("/validate/check",
                                        headers={"X-AMFA-Trusted-Client": "sekret-labu"}):
        z_podrobionym = directory_reply_keys(stan)
    with aplikacja.test_request_context("/validate/check",
                                        headers={"Authorization": "cokolwiek", "X-Forwarded-For": "10.0.0.1",
                                                 "X-AMFA-Trusted-Client": ""}):
        z_obcymi = directory_reply_keys(stan)
    assert bez_naglowka == z_podrobionym == z_obcymi == {
        "password_change_required": True,
        "directory_password_state": ["password_change_required"]}, bez_naglowka

    # Poza zadaniem nie ma komu pokazac stanu — funkcja nic nie robi i nie wybucha.
    assert directory_reply_keys(stan) == {}


def test_regula_neutralnosci_ksztaltu_odpowiedzi() -> None:
    """Ujawniamy dane, nie komunikat: dokladnie te dwa pola, tylko potwierdzone stany, bez enumeracji."""
    from flask import Flask

    aplikacja = Flask(__name__)
    with aplikacja.test_request_context("/validate/check"):
        # Dokladnie pola z listy: zadnego komunikatu, kodu ani niczego, czego stacja nie zna.
        assert set(directory_reply_keys({"account_locked"})) == set(DIRECTORY_REPLY_KEYS)
        assert DIRECTORY_REPLY_KEYS == ("password_change_required", "directory_password_state")
        # Kazdy ujawniony stan niesie flage zmiany hasla — kontrakt, ktory czyta stacja.
        for stan in REVEALED_STATES:
            assert directory_reply_keys({stan}) == {"password_change_required": True,
                                                    "directory_password_state": [stan]}
        # Nieistniejace i wygasle konto: bez sygnalu (inaczej to enumeracja kont), tak samo jak smieci.
        for stan in ("user_not_found", "account_expired", "invalid_credentials", "logon_restriction", "", None):
            assert directory_reply_keys({stan}) == {}, stan
        assert directory_reply_keys(set()) == {}
        assert states_to_reveal({"account_locked", "user_not_found"}) == ["account_locked"]

    # Decyzja z 13.10.2026 (zgloszenie #31) jest ta sama: cztery stany, ani jeden wiecej.
    assert REVEALED_STATES == {"password_change_required", "password_expired", "account_locked",
                               "account_disabled"}, REVEALED_STATES


def test_odbiorca_znacznika_usuniety_z_kodu() -> None:
    """W silniku nie zostalo nic, co czyta znacznik klienta zaufanego ani sekret wdrozeniowy."""
    # Ustawienie zniknelo razem z odbiorca: nikt go juz nie czyta, wiec wdrozenie nie ma czego ustawiac.
    assert "TRUSTED_CLIENT_SECRET" not in vars(SYSCONF), vars(SYSCONF)
    assert not any("TrustedClientSecret" in str(wartosc) for wartosc in vars(SYSCONF).values())

    zrodlo = _zrodlo_modulu()
    # Naglowek i sekret zostaja wylacznie w opisie, dlaczego ich nie ma.
    assert "request.headers" not in zrodlo, "silnik nadal czyta naglowki zadania"
    assert "import hmac" not in zrodlo, "zostalo porownywanie sekretu z naglowkiem"
    assert "get_from_config" not in zrodlo, "ujawnienie stanu nadal zalezy od ustawienia"
    assert "def is_trusted_client_request" not in zrodlo and "TRUST_MARKER_HEADER" not in zrodlo

    # Cala linia silnika: zadnego innego czytelnika znacznika (moglby zostac w module, ktory go podnosi).
    czytelnicy = {}
    for plik in sorted((KORZEN / "privacyidea").rglob("*.py")):
        tresc = plik.read_text(encoding="utf-8")
        znalezione = [nazwa for nazwa in USUNIETE_NAZWY if nazwa in tresc]
        if znalezione:
            czytelnicy[str(plik.relative_to(KORZEN))] = znalezione
    assert czytelnicy == {"privacyidea/lib/amfa_stan_katalogu.py": ["X-AMFA-Trusted-Client",
                                                                   "TrustedClientSecret"]}, czytelnicy


def test_odpowiedz_nadal_buduje_wspolna_bramka() -> None:
    """Ujawnienie idzie jedna droga (bramka + rejestr), a nie przez rozgalezienie po wolajacym."""
    odpowiedz = (KORZEN / "privacyidea" / "lib" / "token" / "auth.py").read_text(encoding="utf-8")
    assert "reply_dict.update(directory_reply_keys(stany_katalogu))" in odpowiedz
    assert "record_directory_states(stany_katalogu)" in odpowiedz, \
        "klasyfikacja musi trafiac do rejestru takze wtedy, gdy pola nie ida do odpowiedzi"


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

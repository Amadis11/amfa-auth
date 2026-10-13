"""Stan konta rozpoznany przez katalog w bieżącym żądaniu (AMFA).

Katalog potrafi rozpoznać, że poświadczenie jest poprawne, ale konto wymaga zmiany hasła, jest
wyłączone albo wygasłe (patrz `resolvers/LDAPIdResolver.py`, `DirectoryPasswordState`). Wtedy samo
„błędne poświadczenia" jest nieprawdą i użytkownik ma dostać zadanie zmiany poświadczeń.

Stan trzeba zapamiętać **na czas żądania**, a nie na obiekcie tokena: kontrola poświadczenia i budowanie
odpowiedzi w `lib/token/auth.py` pracują na świeżo pobieranych obiektach tokenów, więc adnotacja na
jednym z nich nie dochodzi do odpowiedzi (zgłoszenie #222). Trzymamy więc wpisy w `flask.g`, które żyje
dokładnie tyle, co żądanie `/validate/check`.

Zapis robi `lib/user.py` (jedno miejsce, w którym stan z katalogu jest podnoszony, niezależnie od tego,
kto sprawdza hasło), a odczytuje `lib/token/auth.py` przy budowaniu odpowiedzi.
"""

from __future__ import annotations

import hmac

from flask import g, has_request_context, request

from privacyidea.lib.config import SYSCONF, get_from_config

KLUCZ_W_ZADANIU = "amfa_stany_katalogu"

# Naglowek, ktorym zaufany klient (nasza brama) znaczy swoje wlasne wywolanie silnika. Nazwa jest
# wspolna z brama - ona go dokłada, a OpenResty usuwa wejsciowe `X-AMFA-*` od klienta, wiec nikt
# z zewnatrz nie moze go podrobic.
TRUST_MARKER_HEADER = "X-AMFA-Trusted-Client"

# Stany, ktore wolno pokazac uzytkownikowi: te, ktore wystepuja tylko po poprawnym hasle i mowia, ze
# konto wymaga dzialania (zmiana hasla, wygasle haslo), oraz zablokowane i wylaczone (decyzja
# wlasciciela 2026-10-13, zgloszenie #31). `user_not_found` i `account_expired` nie sa ujawniane:
# pierwszy jest enumeracja kont, drugi nie rozni sie dla uzytkownika od zwyklego niepowodzenia.
REVEALED_STATES = frozenset({
    "password_change_required",
    "password_expired",
    "account_locked",
    "account_disabled",
})


def is_trusted_client_request() -> bool:
    """Czy zadanie przyszlo zaufana sciezka (nasza brama z sekretem w naglowku)?

    Bez skonfigurowanego sekretu odpowiedz brzmi "nie" - domyslnie stan konta nie opuszcza silnika
    (fail-closed), a nie odwrotnie.
    """
    if not has_request_context():
        return False
    sekret = get_from_config(SYSCONF.TRUSTED_CLIENT_SECRET, "")
    if not sekret:
        return False
    przedstawiony = request.headers.get(TRUST_MARKER_HEADER, "")
    return bool(przedstawiony) and hmac.compare_digest(str(przedstawiony), str(sekret))


def states_to_reveal(states) -> list[str]:
    """Stany konta, ktore moga trafic do odpowiedzi - czesc wspolna z REVEALED_STATES."""
    return sorted({stan for stan in states if stan in REVEALED_STATES})


def directory_reply_keys(states) -> dict:
    """Pola odpowiedzi o stanie konta albo nic.

    Stan konta jest nasza funkcja, ale nie moze byc oracle poprawnosci hasla: `password_expired`
    i `password_change_required` wystepuja tylko po poprawnym hasle, wiec w ogolnej odpowiedzi
    `/validate/check` zdradzalyby, ze zgadniete haslo bylo dobre (zgloszenie #31). Dlatego pola
    dokladamy wylacznie wtedy, gdy zadanie przyszlo zaufana sciezka.
    """
    if not is_trusted_client_request():
        return {}
    do_ujawnienia = states_to_reveal(states)
    if not do_ujawnienia:
        return {}
    return {"password_change_required": True, "directory_password_state": do_ujawnienia}


def record_directory_states(states) -> None:
    """Zapisuje rozpoznane stany do rejestru zadania - niezaleznie od tego, czy je ujawniamy.

    Klasyfikacja ma zostac w rejestrze (audyt `validate/check`), bo to ona tlumaczy, dlaczego
    logowanie sie nie powiodlo. Do odpowiedzi idzie tylko wtedy, gdy wolno (patrz
    `directory_reply_keys`).
    """
    stany = sorted({stan for stan in states if stan})
    if not stany or not has_request_context():
        return
    obiekt_audytu = getattr(g, "audit_object", None)
    if obiekt_audytu is None:
        return
    obiekt_audytu.add_to_log({"action_detail": "directory_password_state: " + ", ".join(stany)},
                             add_with_comma=True)


def zapamietaj_stan_katalogu(stan: str, uzytkownik: str | None = None) -> None:
    """Dopisuje stan konta rozpoznany przez katalog do bieżącego żądania.

    Poza żądaniem (np. w skrypcie administracyjnym) nie ma gdzie tego trzymać i nie ma komu pokazać —
    wtedy nic nie robimy, żeby nie tworzyć stanu, który nigdy nie zostanie odczytany.
    """
    if not has_request_context():
        return
    wpisy = getattr(g, KLUCZ_W_ZADANIU, None)
    if wpisy is None:
        wpisy = []
        setattr(g, KLUCZ_W_ZADANIU, wpisy)
    wpisy.append({"stan": stan, "uzytkownik": uzytkownik})


def stany_katalogu_z_zadania() -> list[str]:
    """Zwraca stany katalogu rozpoznane w bieżącym żądaniu (bez powtórzeń, w kolejności rozpoznania)."""
    if not has_request_context():
        return []
    stany: list[str] = []
    for wpis in getattr(g, KLUCZ_W_ZADANIU, []) or []:
        stan = wpis.get("stan")
        if stan and stan not in stany:
            stany.append(stan)
    return stany

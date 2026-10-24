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

**Reguła neutralności (zgłoszenie #1030, wariant D).** Silnik ujawnia stan katalogu **sam**: bez
znacznika od klienta i bez nowego sekretu wdrożeniowego. Do 25.10.2026 pola przechodziły tylko wtedy, gdy
żądanie przyszło zaufaną ścieżką (nagłówek `X-AMFA-Trusted-Client` z sekretem `TrustedClientSecret`,
zgłoszenie #31) — tyle że **odbiorcy tego znacznika nigdy nie było w produkcie**: brama go nie dokłada,
żaden węzeł nie ustawiał sekretu, więc stan nie opuszczał silnika, a naprawa po stronie stacji
wymagałaby wdrożenia nowego sekretu na każdej z nich. Neutralność zostaje tam, gdzie była i gdzie
należy: brama odpowiada na powierzchni publicznej ogólną odmową i zapisuje stan w dzienniku (#428,
kryterium 4; #563), a stacja ma własne, neutralne komunikaty (#131/#428) i pokazuje stan konta tylko
wtedy, gdy potwierdził go katalog. Sam silnik nie zmienia przy tym niczego poza **danymi** w `detail`:
komunikat i kod odpowiedzi zostają takie same jak przy zwykłej odmowie, a nieistniejące i wygasłe konto
nadal nie mają żadnego sygnału (to byłaby enumeracja kont).
"""

from __future__ import annotations

from flask import g, has_request_context

KLUCZ_W_ZADANIU = "amfa_stany_katalogu"

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

#: Pola, ktore silnik dokłada do odpowiedzi, gdy katalog potwierdzil stan konta. Wypisane jako lista,
#: a nie dwa literaly w kodzie, zeby regula neutralnosci miala jeden punkt do trzymania: ujawniamy
#: **dane**, nigdy komunikat, kod odpowiedzi ani cokolwiek, co zalezy od poprawnosci hasla.
DIRECTORY_REPLY_KEYS = ("password_change_required", "directory_password_state")


def states_to_reveal(states) -> list[str]:
    """Stany konta, ktore moga trafic do odpowiedzi - czesc wspolna z REVEALED_STATES."""
    return sorted({stan for stan in states if stan in REVEALED_STATES})


def directory_reply_keys(states) -> dict:
    """Pola odpowiedzi o stanie konta albo nic - regula neutralnosci (zgloszenie #1030, wariant D).

    Stan konta jest nasza funkcja, ale nie moze byc oracle poprawnosci hasla: `password_expired`
    i `password_change_required` wystepuja tylko po poprawnym hasle, wiec w ogolnej odpowiedzi
    `/validate/check` zdradzalyby, ze zgadniete haslo bylo dobre (zgloszenie #31). Rozwiazaniem jest
    neutralnosc powierzchni, a nie znakowanie wolajacego:

      * pola dokladamy **zawsze i kazdemu** - ten sam stan wychodzi tak samo do bramy, do stacji
        i do kazdego innego wolajacego (brak rozgalezienia po naglowku jest tu regula, nie przypadkiem),
      * dokladamy **wylacznie dane** (`DIRECTORY_REPLY_KEYS`): komunikat ostrzezenia i kod odpowiedzi
        zostaja takie, jakie bylyby bez stanu konta,
      * ujawniamy wylacznie stan **potwierdzony przez katalog** i tylko z listy `REVEALED_STATES`
        (nieistniejace i wygasle konto zostaja bez sygnalu - to bylaby enumeracja kont),
      * o tym, co z tym zrobic, decyduje powierzchnia: brama zwraca ogolna odmowe i zapisuje stan
        w dzienniku (#428/#563), a stacja rozstrzyga ekran wlasnymi regulami (#131).

    Poza zadaniem nie ma komu pokazac stanu, wiec funkcja nic nie robi.
    """
    if not has_request_context():
        return {}
    do_ujawnienia = states_to_reveal(states)
    if not do_ujawnienia:
        return {}
    odpowiedz = {"password_change_required": True, "directory_password_state": do_ujawnienia}
    return {klucz: odpowiedz[klucz] for klucz in DIRECTORY_REPLY_KEYS}


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

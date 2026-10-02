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

from flask import g, has_request_context

KLUCZ_W_ZADANIU = "amfa_stany_katalogu"


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

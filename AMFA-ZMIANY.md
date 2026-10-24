# AMFA Auth — nasze zmiany wobec privacyIDEA

To jest **samodzielne repozytorium naszego produktu**, nie fork. Cala historia podstawy jest
w srodku, a oryginal sluzy wylacznie jako zrodlo nowych wydan, podpiety jako zdalne `upstream`.
Dzieki temu mamy wlasne zgloszenia, wlasne wydania i wlasna automatyzacje, ktorych fork nie daje.

Ten plik opisuje, jak oznaczamy i opisujemy nasze zmiany, zeby automat wydan (#199 w repozytorium
amitronic-amfa) mogl je rozpoznac i nalozyc na nowe wydanie privacyIDEA.

## Model galezi

- `master` — **lustro podstawy** (zdalne `upstream` = oryginal). Nigdy nie commitujemy tu naszych zmian; sluzy tylko do pobierania
  nowych wydan i jako baza dla nakladania.
- `amfa` — **nasza linia**. Tu wchodza wszystkie nasze zmiany, kazda przez osobny PR.
- `amfa-<krok>` — galaz jednego kroku; po scaleniu usuwana. Uwaga: nie mozna uzywac nazw z ukosnikiem
  (`amfa/cos`), bo git nie pozwala miec jednoczesnie galezi `amfa` i `amfa/cos`.

## Skad biora sie nowe wydania

`upstream` wskazuje na `https://github.com/privacyidea/privacyidea.git`. Automat wydan pobiera
najnowszy znacznik wydania, naklada nasze commity z linii `amfa` na nowa podstawe, uruchamia testy
(ze szczegolnym naciskiem na nasze) i zglasza, ze jest aktualizacja — albo zglasza konflikt, jesli
nasze zmiany zderzyly sie z nowa wersja.

## Aktualizacja jest caloscia

Wydanie nowej linii podstawy nie konczy sie na tym repozytorium: trzeba miec **zielona cala regresje
bramy** i **przebieg na zywym labie**, a nie numer wydania dopisany w kodzie bramy. Brama nie trzyma
listy obslugiwanych wydan — sprawdza ksztalt i spojnosc odpowiedzi privacyIDEA, a zgodnosc kontraktu
potwierdzaja testy. Pelny lancuch weryfikacji (kod, brama, brama na labie, zaleznosci, schemat, panel,
wzorce, wdrozenie) jest w `amfa/lista-kontrolna-wydania.md`, a automat dokłada go do raportu wydania.

## Konwencja commitow

Kazdy commit zaczyna sie od `AMFA: `. Po temacie idzie blok opisowy w stalej kolejnosci:

    AMFA: <co i ktory krok> (krok N z #199)

    CO: <co dokladnie zmienione, plikami>
    DLACZEGO: <powod zmiany>
    JAK: <sposob wykonania, zeby dalo sie odtworzyc>
    RYZYKO: <co moze sie zderzyc z nowa wersja podstawy i gdzie>
    WERYFIKACJA: <czym sprawdzone>
    AUTOMAT: <co ma zrobic automat wydan przy nakladaniu>

Uzasadnienie: przy nakladaniu na nowe wydanie najwazniejsze jest `RYZYKO` (gdzie spodziewac sie
konfliktu) i `AUTOMAT` (co uruchomic, zeby potwierdzic, ze zmiana nadal dziala). Bez tego kazda
aktualizacja bylaby czytaniem calego diffu od nowa.

## Zasady

- Nasze zmiany **nigdy** nie sa wymieszane z kodem podstawy w tym samym commicie. To jedyna
  twarda regula i wynika z nakladania na nowe wydania: w mieszanym commicie nie widac, czyja
  zmiana zderzyla sie z nowa podstawa. Liczba commitow na krok jest dowolna, byle kazdy byl
  nasz, maly i samodzielny.
- Kazda zmiana, ktora da sie sprawdzic statycznie, dostaje straznika w **wlasnym** pliku kroku:
  `tests/test_amfa_krok<N>_<nazwa>.py` (np. `test_amfa_krok5_brand.py`). Plik nalezy do jednego kroku —
  dzieki temu nakladanie na nowe wydanie nie konfliktuje o wspolny plik testow. Bramka wydania uruchamia
  **wszystkie** pliki z wzorca `tests/test_amfa_krok*.py` (`NASZE_STRAZNICY_WZORZEC` w automacie), a brak
  ktoregokolwiek z nich zatrzymuje wydanie. Wspolny plik `tests/test_amfa_zmiany.py` nie istnieje — nazwa
  zostala po pierwszym zalozeniu i nie wolno do niej wracac.
- Straznicy sa szybcy i nie wymagaja bazy danych — maja dzialac w automacie bez ciezkich zaleznosci.
  Kazdy plik da sie uruchomic bez pytest: `python3 tests/test_amfa_krok<N>_<nazwa>.py` (kod wyjscia 0/1).
  Kilku straznikom potrzebne sa zaleznosci podstawy (np. krokowi 3 — `flask`): wtedy uruchamiac je
  pythonem z `.venv` w repozytorium (`python3 -m venv .venv && .venv/bin/pip install -e ".[test]"`),
  ktory bierze tez automat (`python_z_testami()`). Bez zaleznosci straznik zglasza sie jako FAIL,
  a nie pomija.
- Wewnetrznej nazwy pakietu `privacyidea` nie zmieniamy: jest niewidoczna, a jej zmiana zerwalaby
  mozliwosc nakladania naszych zmian na nowe wydania.

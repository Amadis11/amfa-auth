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

Wydanie nowej linii podstawy nie konczy sie na tym repozytorium: brama AMFA ma **zamknieta liste linii
wydan**, ktore przyjmuje (`SANE_RELEASE_LINES` w `amitronic-amfa`, kopia w `amfa/brama-linie.json`).
Dlatego automat, widzac wydanie z linii spoza tej listy, **nie naklada naszych zmian** i konczy sie
kodem `5` z zgloszeniem „wymaga decyzji o zgodnosci z brama” — to decyzja, a nie awaria. Pelny lancuch
wydania (kod, brama, zaleznosci, schemat, panel, wzorce, wdrozenie) jest w
`amfa/lista-kontrolna-wydania.md`.

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
- Kazda zmiana, ktora da sie sprawdzic statycznie, dostaje straznika w `tests/test_amfa_zmiany.py`.
- Straznicy sa szybcy i nie wymagaja bazy danych — maja dzialac w automacie bez ciezkich zaleznosci.
- Wewnetrznej nazwy pakietu `privacyidea` nie zmieniamy: jest niewidoczna, a jej zmiana zerwalaby
  mozliwosc nakladania naszych zmian na nowe wydania.

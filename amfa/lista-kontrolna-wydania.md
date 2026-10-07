# Lista kontrolna wydania — aktualizacja podstawy to całość

Nowa linia wydania privacyIDEA nie jest „podmianą kodu w jednym komponencie”. Wydanie jest gotowe
dopiero wtedy, gdy **wszystkie** punkty niżej są zielone — i to jest **weryfikacja, nie decyzja**:
brama nie trzyma listy obsługiwanych wydań, więc nowa linia przechodzi dlatego, że ją przetestowano,
a nie dlatego, że ktoś dopisał numer.

| krok | co musi być zielone | gdzie to żyje | czym się sprawdza |
|---|---|---|---|
| 0. Uruchamialność | gałąź domyślna repozytorium to `amfa` (nasza linia), a `master` zostaje lustrem podstawy — `schedule` i `workflow_dispatch` uruchamiają workflow **tylko z gałęzi domyślnej**, więc przy domyślnej `master` automat nie rusza nigdy, choć plik leży w repozytorium | to repozytorium, `.github/workflows/amfa-aktualizacja-podstawy.yml`, ustawienie repozytorium na GitHubie | przebieg automatu z `workflow_dispatch` kończy się zielono |
| 1. Kod | nasze commity nałożone na nową podstawę, nasze strażnicy i testy podstawy zielone; bramka uruchamia **wszystkie** `tests/test_amfa_krok*.py` (w tym strażnik brandu), a brak któregokolwiek strażnika zatrzymuje wydanie | to repozytorium, `amfa/aktualizacja-podstawy.py` | kod wyjścia `0` automatu |
| 2. Brama | **cała regresja bramy** (przyjmowanie odpowiedzi privacyIDEA, MFA, sesje, powiadomienia, szablony, syslog, telemetria, ruch, certyfikaty) | `amitronic-amfa`: `tests/web/gateway/`, CI `.github/workflows/testy-bramy.yml` | `python3 -m unittest discover -s tests/web/gateway -p "test_*.py"` |
| 3. Brama na labie | przebieg na żywym środowisku: logowanie przez bramę i wszystkie ekrany panelu | `components/amfa-ui`: `pnpm test:flow` | 16/16, prawdziwy Chromium |
| 4. Zależności | piny z `requirements.txt` nowej linii zainstalowane na każdym węźle | `/opt/privacyidea` na 140 i 141 | `/opt/privacyidea/bin/pip show privacyidea`, start usługi |
| 5. Schemat | migracja wykonana **przy zatrzymanej usłudze na wszystkich węzłach** (nowa wersja przenosi dane) | `pi-manage db upgrade` na węźle | wersja rewizji w bazie przed i po |
| 6. Panel | panel zbudowany **przed** pakietem, stare drzewo `build/` wyczyszczone (inaczej pakiet niesie bundle z poprzednich buildów, razem z nazwami dostawcy) | `privacyidea/static/dist/privacyidea-webui/browser/` w zbudowanym pakiecie | rozmiar pakietu ~96 MB, brak dawnych `main-*.js`, w paczce tytuł `AMFA`, nasz `amfa.svg` i nasza ikona karty |
| 7. Wzorce | realm, resolver i polityki na węzłach zgodne z `components/privacyidea/`; nowe polityki wchodzą skryptem | `amitronic-amfa`: `components/privacyidea/`, `infra/ha/privacyidea/amfa-policies.py` | odczyt polityk z API, `amfa-policies.py --dry-run` |
| 8. Wdrożenie | kopie wstecz, stop, podmiana, start, weryfikacja i wpis w `docs/status.md` | `amitronic-amfa`: `docs/status.md`, `docs/architecture/change_log.md` | logowanie administratora, logowanie przez bramę, telemetria |

## Co robi automat, a czego nie

Automat (`amfa/aktualizacja-podstawy.py`, workflow `amfa-aktualizacja-podstawy.yml`) budzi się raz na
dobę i po ręcznym uruchomieniu. Gdy nasza linia stoi na najnowszym wydaniu, kończy się kodem `0`
i **nie rusza pliku `amfa/PODSTAWA`** — workflow rozpoznaje to po niezmienionym pliku i nie robi ani
gałęzi, ani pull requesta. Wydanie (gałąź + PR do `amfa`) powstaje tylko wtedy, gdy plik podstawy
faktycznie się zmienił, a testy i budowa panelu przeszły. Konflikt albo padnięte testy kończą się
zgłoszeniem z raportem, bez wydania.

## Dlaczego bez ręcznej decyzji

Numer wydania wpisany w kod bramy byłby obietnicą zamiast sprawdzenia: dopisanie „3.15” niczego nie
dowodzi, a jego brak zatrzymuje ruch dopiero na labie (objaw: `503` na logowaniu,
`amfa_challenge_start_failure`, `phase=privacyidea.outcome`). Brama sprawdza więc **kształt i spójność**
koperty odpowiedzi (JSON-RPC, obiekt `result`, wersja w formacie privacyIDEA, a gdy obecne jest też
`versionnumber` — ta sama linia co w `version`), a zgodność kontraktu potwierdza cała regresja
(punkt 2) i przebieg na żywym labie (punkt 3). Jeśli nowa linia zmieni coś w kontrakcie, widać to jako
czerwony test **przed** wdrożeniem, a nie jako numer do dopisania w kodzie.

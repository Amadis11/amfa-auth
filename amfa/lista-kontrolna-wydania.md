# Lista kontrolna wydania — aktualizacja podstawy to całość

Nowa linia wydania privacyIDEA nie jest „podmianą kodu w jednym komponencie”. Wydanie jest gotowe
dopiero wtedy, gdy **wszystkie** punkty niżej są zielone — i to jest **weryfikacja, nie decyzja**:
brama nie trzyma listy obsługiwanych wydań, więc nowa linia przechodzi dlatego, że ją przetestowano,
a nie dlatego, że ktoś dopisał numer.

| krok | co musi być zielone | gdzie to żyje | czym się sprawdza |
|---|---|---|---|
| 1. Kod | nasze commity nałożone na nową podstawę, nasze strażnicy i testy podstawy zielone | to repozytorium, `amfa/aktualizacja-podstawy.py` | kod wyjścia `0` automatu |
| 2. Brama | **cała regresja bramy** (przyjmowanie odpowiedzi privacyIDEA, MFA, sesje, powiadomienia, szablony, syslog, telemetria, ruch, certyfikaty) | `amitronic-amfa`: `tests/web/gateway/`, CI `.github/workflows/testy-bramy.yml` | `python3 -m unittest discover -s tests/web/gateway -p "test_*.py"` |
| 3. Brama na labie | przebieg na żywym środowisku: logowanie przez bramę i wszystkie ekrany panelu | `components/amfa-ui`: `pnpm test:flow` | 16/16, prawdziwy Chromium |
| 4. Zależności | piny z `requirements.txt` nowej linii zainstalowane na każdym węźle | `/opt/privacyidea` na 140 i 141 | `/opt/privacyidea/bin/pip show privacyidea`, start usługi |
| 5. Schemat | migracja wykonana **przy zatrzymanej usłudze na wszystkich węzłach** (nowa wersja przenosi dane) | `pi-manage db upgrade` na węźle | wersja rewizji w bazie przed i po |
| 6. Panel | panel zbudowany z tego pakietu (nasze zmiany brandowe) | `privacyidea/static/dist/privacyidea-webui/browser/` w zbudowanym pakiecie | HTTP na konsoli, nasze `amfa.svg` |
| 7. Wzorce | realm, resolver i polityki na węzłach zgodne z `components/privacyidea/`; nowe polityki wchodzą skryptem | `amitronic-amfa`: `components/privacyidea/`, `infra/ha/privacyidea/amfa-policies.py` | odczyt polityk z API, `amfa-policies.py --dry-run` |
| 8. Wdrożenie | kopie wstecz, stop, podmiana, start, weryfikacja i wpis w `docs/status.md` | `amitronic-amfa`: `docs/status.md`, `docs/architecture/change_log.md` | logowanie administratora, logowanie przez bramę, telemetria |

## Dlaczego bez ręcznej decyzji

Numer wydania wpisany w kod bramy byłby obietnicą zamiast sprawdzenia: dopisanie „3.15” niczego nie
dowodzi, a jego brak zatrzymuje ruch dopiero na labie (objaw: `503` na logowaniu,
`amfa_challenge_start_failure`, `phase=privacyidea.outcome`). Brama sprawdza więc **kształt i spójność**
koperty odpowiedzi (JSON-RPC, obiekt `result`, wersja w formacie privacyIDEA, a gdy obecne jest też
`versionnumber` — ta sama linia co w `version`), a zgodność kontraktu potwierdza cała regresja
(punkt 2) i przebieg na żywym labie (punkt 3). Jeśli nowa linia zmieni coś w kontrakcie, widać to jako
czerwony test **przed** wdrożeniem, a nie jako numer do dopisania w kodzie.

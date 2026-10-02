# Lista kontrolna wydania — aktualizacja podstawy to całość

Nowa linia wydania privacyIDEA nie jest „podmianą kodu w jednym komponencie”. Wydanie jest gotowe
dopiero wtedy, gdy **wszystkie** punkty niżej są załatwione — dlatego automat wydań
(`amfa/aktualizacja-podstawy.py`) przy nowej linii najpierw pyta o zgodność z bramą i **nie nakłada
naszych zmian**, dopóki linia nie jest przyjęta (`amfa/brama-linie.json`). To jest decyzja, nie awaria:
automat kończy się wtedy kodem `5` i zgłoszeniem, a nie czerwonym „nie udało się nałożyć”.

| krok | co musi być prawdą | gdzie to żyje | czym się sprawdza |
|---|---|---|---|
| 1. Kod | nasze commity nałożone na nową podstawę, wszystkie testy zielone (nasze strażnicy pierwsi) | to repozytorium, `amfa/aktualizacja-podstawy.py` | kod wyjścia `0` automatu |
| 2. Brama | linia wydania jest na liście przyjmowanych linii | `amitronic-amfa`: `components/gateway/core/amfa_gateway/privacyidea.py` (`SANE_RELEASE_LINES`) + kopia w `amfa/brama-linie.json` | kod wyjścia `5` automatu, test `test_zgodnosc_linii_bramy.py` w repozytorium bramy |
| 3. Zależności | piny z `requirements.txt` nowej linii zainstalowane na każdym węźle | `/opt/privacyidea` na 140 i 141 | `/opt/privacyidea/bin/pip show privacyidea`, start usługi |
| 4. Schemat | migracja wykonana **przy zatrzymanej usłudze na wszystkich węzłach** (nowa wersja przenosi dane) | `pi-manage db upgrade` na węźle | wersja rewizji w bazie przed i po |
| 5. Panel | panel zbudowany z tego pakietu (nasze zmiany brandowe) | `privacyidea/static/dist/privacyidea-webui/browser/` w zbudowanym pakiecie | HTTP na konsoli, nasze `amfa.svg` |
| 6. Wzorce | realm, resolver i polityki na węzłach zgodne z `components/privacyidea/`; nowe polityki wchodzą skryptem | `amitronic-amfa`: `components/privacyidea/`, `infra/ha/privacyidea/amfa-policies.py` | odczyt polityk z API, `amfa-policies.py --dry-run` |
| 7. Wdrożenie | kopie wstecz, stop, podmiana, start, weryfikacja i wpis w `docs/status.md` | `amitronic-amfa`: `docs/status.md`, `docs/architecture/change_log.md` | logowanie administratora, logowanie przez bramę, telemetria |

## Gdy punkt 2 nie jest załatwiony

1. PR w `amitronic-amfa`: linia dopisana do `SANE_RELEASE_LINES` (+ test koperty odpowiedzi dla nowej wersji).
2. Dopisanie linii w `amfa/brama-linie.json` (ten plik jest zadeklarowaną kopią listy z bramy).
3. Wdrożenie obrazu bramy na węzły (`scripts/deploy/deploy-gateway.sh <host> <sha> <nr>`).
4. Ponowne uruchomienie automatu — dopiero teraz wydanie nowej linii jest dozwolone.

Powód, dla którego lista w bramie jest zamknięta: nieznane wydanie ma **zatrzymać ruch**, a nie przejść
niezauważone. Koszt jest znany i policzony: bez punktu 2 logowanie przez bramę kończy się `503`
(`amfa_challenge_start_failure`, `phase=privacyidea.outcome`), a nie cichym „prawie działa”.

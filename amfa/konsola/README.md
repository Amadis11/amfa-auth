# Nakladka na konsole podstawy (`amfa/konsola/**`)

Po co: klasa `console-brand` w inwentarzu linii ma byc dostarczana jako **nasza nakladka**, a nie jako
zmiana w plikach podstawy. Granica wlasciciela (18.10.2026): konsola nie moze sie gryzc z silnikiem, wiec
konsola **zawsze powstaje z tego samego commita co silnik** — buduje ja `deploy/docker/Dockerfile`
(stage `node-builder`: `COPY privacyidea/static/ ./` -> `npm run build`). Nie robimy z niej osobnego
artefaktu ani nie serwujemy jej z vhosta.

Stan na teraz (krok 1): nakladka **przygotowana i zmanifestowana**, ale **nie wpięta do budowy obrazu** —
pliki podstawy sa nadal naszymi wersjami, wiec obraz buduje sie jak dotad. Kroki dalej:
1. `deploy/docker/Dockerfile`: przed `npm run build` naloz nakladke
   (`COPY amfa/konsola/privacyidea/static/src/ ./privacyidea/static/src/` w stage `node-builder`)
   i usun pliki z sekcji `D` manifestu (`RUN rm -f ...`).
2. Wycofaj w linii pliki z sekcji `M`/`A` do podstawy (`git checkout master -- ...`, dla `A` — `git rm`).
3. Strażnicy: `tests/test_amfa_krok5_brand.py` i warstwa `konsola-tlumaczenia` musza oceniac **podstawe
   plus nakladke**, a nie samo drzewo — inaczej po wycofaniu czerwienią sie bez powodu (a rozjazd nakladki
   z nowa konsola podstawy ma byc widoczny w budowie obrazu i w przebiegu dymnym, nie na produkcji).

Co zawiera: `manifest.txt` (generowany z gita, sekcje `M`/`A`/`D`) oraz pliki w tej samej sciezce, w jakiej
lezaly w drzewie podstawy — `amfa/konsola/privacyidea/static/...`.

Zmierzone (18.10.2026) wobec lustra `master` = `31db0ecd8`, linia `amfa` = `4005cbd6d`: **112 plikow** —
`M` 86 (podmieniamy), `A` 2 (`public/assets/amfa.svg`, `favicon.svg` — nasze znaki), `D` 24 (powierzchnia
subskrypcji i okno powitalne, ktore nasza linia usunela z konsoli). Punkt odniesienia dla zawartosci:
build konsoli z linii → 17 jezykow, 562 pliki / 279 MB, `pl/index.html` 24 395 B,
`sha256 5a6ca22fbf6d8419d9430233…`; po nalożeniu nakladki ta suma musi wyjsc ta sama.

Uwaga: sekcji `D` **nie da sie** wyrazic nakladka (`COPY` nie usuwa plikow) — dlatego jest w manifescie
i trafia do budowy obrazu jako jawna lista usuniec.

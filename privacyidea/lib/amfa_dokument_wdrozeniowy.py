"""Podpisany dokument wdrozeniowy silnika: weryfikacja i bramka toru offline HOTP (zgloszenie #425, wariant B).

Dokument jest **ten sam**, ktory czyta dostawca poswiadczen Windows: koperta ``document`` + ``signature``
(``rsa-sha256`` nad kanonicznym JSON-em dokumentu), podpisana kluczem produktu ``amfa-licence-2026``
(``forks/credential-provider/doc/flagi-wdrozeniowe.md``, narzedzie ``scripts/flagi-wdrozeniowe/wystaw.py``).

Silnik czyta go **inna droga niz wtyczka**: stacja czyta plik z wlasnego dysku
(``C:\\ProgramData\\AMITRONIC\\AMFAdeployment-flags.json``, raz przy zaladowaniu LogonUI), a silnik czyta
plik wskazany ustawieniem ``AMFADeploymentFlagsFile`` (domyslnie ``/etc/amfa/konfiguracja-stacji.json``
w kontenerze) i weryfikuje go przy kazdym pytaniu o dane offline. Kanalu pobrania z bramy (#370, punkt 3)
silnik nie uzywa: dokument jest podpisany, wiec droga, ktora przyszedl, nie zmienia jego tresci.

Po co ta bramka (#425 wariant B): dno toru offline HOTP bylo dotad tylko po stronie klienta (stacja odmawia
uzycia danych offline). Teraz to samo robi silnik: kontu, ktore nie jest w zadnej grupie AD z listy
``offline_hotp_groups``, **nie wydajemy danych offline HOTP** - ani pierwszej partii, ani dopelnienia.
Kazda droga odmowy konczy sie zamknieciem toru, nigdy jego otwarciem.

Czego ta bramka **nie** robi: nie dotyka toru z kluczem sprzetowym (``offline_fido2_groups``) - ten nalezy
do kroku per grupa dla FIDO2 (#1070). Pola ``method_order``, ``offline_data_binding`` i
``offline_refill_interval_seconds`` sa przyjmowane i ignorowane, bo tyle samo znacza po stronie stacji
(runda 1 z #1042).

Zrodla prawdy o dokumencie sa po stronie produktu, nie tutaj: granice pol, kanoniczna postac i powod
odrzucenia opisuje ``forks/credential-provider/doc/flagi-wdrozeniowe.md``, a narzedzie, ktorym dokument
sie wystawia, to ``scripts/flagi-wdrozeniowe/wystaw.py``. Ten modul jest **strona odbiorcy** - musi
przyjac dokument wystawiony narzedziem i musi odmowic wszystkiemu innemu.
"""
from __future__ import annotations

import base64
import datetime as _datetime
import hashlib
import json
import logging
import pathlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from privacyidea.lib.config import SYSCONF, get_from_config

log = logging.getLogger(__name__)

#: Wersja formatu dokumentu. Ta sama co u narzedzia i u stacji; nieznana wersja to odrzucenie, nie zgadywanie.
FORMAT_VERSION = 1

#: Typ dokumentu.
TYPE = "deployment-flags"

#: Algorytm podpisu. Jeden, zeby nie bylo wyboru do pomylenia.
ALGORITHM = "rsa-sha256"

#: Identyfikator klucza produktu: ten sam wpis co na liscie kluczy stacji (`PinnedFlagKeys`) i co klucz
#: licencji produktu (`PUBLIC_KEY_PEM` w `components/gateway/core/amfa_gateway/licencja.py`). Klucz spoza
#: tej listy to odrzucenie dokumentu - nigdy "sprobujmy innym kluczem".
KEY_ID = "amfa-licence-2026"

#: Odcisk SHA-256 surowego modulu klucza (384 B). Ta sama regula co `sha256Modulus` w `PinnedFlagKeys` po
#: stronie stacji i `key_entry()` w `scripts/flagi-wdrozeniowe/flagi.py`; wartosc jest **przypiety** w kodzie,
#: wiec klucz wklejony przez pomylke (inny niz zadeklarowany) nie przejdzie weryfikacji zadnego dokumentu.
ODCISK_KLUCZA = "ba892c74f6156bb568aa4d07e447c7d8457bc8ebb4b9d7ec79b04ac6420a18e1"

#: Klucz publiczny produktu, wkompilowany w kod (#378). Para prywatna jest w Vaultwardenie i nigdy nie
#: wchodzi do repozytorium; dokumenty wystawia sie wylacznie nia.
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAusvxuYhEBkQwCFNix2lL
eZOObhdxxT3pRhgQoXNhxJ2/OspwFSaHrb38J5AzxfGxdWl3mvzaWZyc4DN3f1B+
dzeJUB7sani8LLnGExMjrsDZqmrj8cF3I1zThT+exTjVrUc2qtIasvK7BEaBRDeF
BjF5Pl7N2ISLQUnxVvBxprWrOwnQoOBfRgwidUlhBK1dBTF7F1AIZrJzBckXI+9p
RtBSPfB+gTkgn+bwzBCom01HjCCBfZ7OSd4WOsobjSKypPpMo30ZzX6exWvOqCqK
cNDptjFj2PZmYhommRjr0Nh6XNT1S3vssisXbcqCFEYTuqmG9ldfp4SQa41KTLCc
nQGgAAQcX7x4uKzvFvpPRZGODDewiWsjC91t0qv6X0OYoP7kf0KaHllPOuCfB7X5
KSnnbiwsNT4khPc064chh3QIWvEmuL1kDtFrXBvHF20JKRdStOI0iuYBc3AAGcmK
2S2zqqhWxcUlqB2vNiloEOM+gzD5GxyuwRYEjUwlP1TVAgMBAAE=
-----END PUBLIC KEY-----"""

#: Sciezka dokumentu, gdy wdrozenie nie podalo innej (`AMFADeploymentFlagsFile`).
SCIEZKA_DOMYSLNA = "/etc/amfa/konfiguracja-stacji.json"

#: Gorny limit rozmiaru pliku (ten sam co po stronie stacji): wiekszy plik jest odrzucany, nie skracany.
MAKS_ROZMIAR_BAJTOW = 64 * 1024

#: Pole dokumentu otwierajace tor offline HOTP. Bez niego tor zostaje zamkniety, nawet gdy lista grup jest
#: niepusta - tak samo rozumie to stacja (`MayUseHotpOffline`).
POLE_HOTP = "offline_hotp_allowed"

#: Lista grup AD dopuszczonych do toru offline HOTP. Pusta lista znaczy **nikt** (fail-closed).
POLE_GRUP_HOTP = "offline_hotp_groups"

#: Lista grup AD dopuszczonych do toru z kluczem sprzetowym. Czytana, zeby dokument z nia byl znany,
#: ale nie decyduje tu o niczym (#1070).
POLE_GRUP_FIDO2 = "offline_fido2_groups"

#: Pola przyjmowane i ignorowane: tyle samo znacza po stronie stacji od rundy 1 (#1042), a dokument, ktory
#: je niesie, jest rownowazny dnu - nie odrzucamy go, bo uniewazniloby to istniejace wdrozenia.
POLA_BEZ_KONSUMENTA = ("method_order", "offline_data_binding", "offline_refill_interval_seconds")

#: Pola, ktore dokument moze niesc w `flags`. Pole spoza tej listy odrzuca **caly** dokument (ta sama regula
#: co u stacji): inaczej starszy odbiorca po cichu ignorowalby nowa regule, a wdrozenie wygladaloby na przyjete.
POLA_ZNANE = (POLE_HOTP, POLE_GRUP_HOTP, POLE_GRUP_FIDO2, *POLA_BEZ_KONSUMENTA)

#: Granice listy grup - te same co na stacji (dokument, ktorego stacja nie przyjmie, nie ma tu znaczyc wiecej).
GRUPY_LIMIT = 32
GRUPA_DLUGOSC_LIMIT = 255

#: Klucz, pod ktorym resolver oddaje grupy konta. Ustala go wdrozenie (`USERINFO` z `groups <- memberOf`,
#: `infra/ha/privacyidea/amfa-resolver-atrybuty.py`); ten sam klucz zna `lib/user.py` jako atrybut drogi.
KLUCZ_GRUP = "groups"


class DokumentNieprzyjety(Exception):
    """Dokument odrzucony. Wyjatek jest wewnetrzny: na zewnatrz kazdy powod konczy sie zamknietym torem."""


def canoniczne_bajty(dokument: dict) -> bytes:
    """Kanoniczna postac dokumentu - dokladnie to, co jest podpisywane.

    ``sort_keys`` i separatory bez spacji, znaki spoza ASCII bez escapowania: ta sama regula co
    ``canonical_bytes`` w module licencji produktu i ``document.dump(-1, ' ', false)`` po stronie stacji.
    Bez tego zgodnosc podpisu zalezalaby od tego, jak serializacja ulozyla klucze.
    """
    return json.dumps(dokument, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def klucz_publiczny() -> rsa.RSAPublicKey:
    """Klucz publiczny produktu z PEM wkompilowanego w kod."""
    klucz = load_pem_public_key(PUBLIC_KEY_PEM.encode("utf-8"))
    if not isinstance(klucz, rsa.RSAPublicKey):  # pragma: no cover - klucz jest RSA, pilnuje tego straznik
        raise DokumentNieprzyjety("the pinned product key is not an RSA key")
    return klucz


def odcisk_klucza() -> str:
    """Odcisk SHA-256 modulu klucza - ta sama regula co `sha256Modulus` w liscie kluczy stacji."""
    modul = klucz_publiczny().public_numbers().n
    return hashlib.sha256(modul.to_bytes((modul.bit_length() + 7) // 8, "big")).hexdigest()


def _sprawdz_klucz() -> None:
    """Klucz w kodzie musi byc tym kluczem, ktory deklaruje odcisk.

    To ta sama kontrola co po stronie stacji (odcisk przed importem klucza): lapie najczestszy blad
    rotacji - wklejony klucz inny niz zadeklarowany. Niezgodnosc znaczy "nie ma czym weryfikowac",
    czyli tor zamkniety, a nie "przejdzmy dalej".
    """
    odcisk = odcisk_klucza()
    if odcisk != ODCISK_KLUCZA:
        raise DokumentNieprzyjety(f"the pinned key does not match its declared fingerprint ({odcisk})")


def _data(tekst: object) -> _datetime.date:
    """Data ISO (`YYYY-MM-DD`) albo wyjatek - dokument z data nie-ISO jest odrzucany, nie zgadywany."""
    if not isinstance(tekst, str):
        raise DokumentNieprzyjety("a document date is not a string")
    try:
        return _datetime.date.fromisoformat(tekst)
    except ValueError:
        raise DokumentNieprzyjety(f"a document date is not ISO (YYYY-MM-DD): {tekst!r}") from None


def _podpis_ok(dokument: dict, podpis_base64: object) -> None:
    """Weryfikacja podpisu albo wyjatek. Podpis jest pierwsza kontrola, a nie ostatnia.

    Kolejnosc ma znaczenie: bez podpisu termin nie znaczy nic (kazdy go wpisze), wiec odmowa podpisu nie
    moze czekac na walidacje wartosci.
    """
    if not isinstance(podpis_base64, str) or not podpis_base64:
        raise DokumentNieprzyjety("signature without a value")
    try:
        podpis = base64.b64decode(podpis_base64, validate=True)
    except Exception:
        raise DokumentNieprzyjety("the signature is not valid base64") from None
    try:
        klucz_publiczny().verify(podpis, canoniczne_bajty(dokument), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise DokumentNieprzyjety("signature does not match the document") from None


def waliduj_grupy(wartosc: object) -> list[str]:
    """Lista nazw grup z dokumentu albo wyjatek: granice te same co na stacji.

    Pusta lista **nie jest** bledem dokumentu - jest regula "nikt" i tak wlasnie jest czytana dalej.
    """
    if wartosc is None:
        return []
    if not isinstance(wartosc, list):
        raise DokumentNieprzyjety("a group list is not a list")
    nazwy: list[str] = []
    for pozycja in wartosc:
        if not isinstance(pozycja, str):
            raise DokumentNieprzyjety("a group name is not a string")
        nazwa = pozycja.strip()
        if not nazwa:
            raise DokumentNieprzyjety("a group name is empty")
        if len(nazwa) > GRUPA_DLUGOSC_LIMIT:
            raise DokumentNieprzyjety(f"a group name is longer than {GRUPA_DLUGOSC_LIMIT} characters")
        if nazwa.lower() in [znana.lower() for znana in nazwy]:
            raise DokumentNieprzyjety(f"a group name repeats (case-insensitively): {nazwa!r}")
        nazwy.append(nazwa)
    if len(nazwy) > GRUPY_LIMIT:
        raise DokumentNieprzyjety(f"a group list has more entries than {GRUPY_LIMIT}")
    return nazwy


def waliduj_dokument(dokument: object, dzis: _datetime.date | None = None) -> dict:
    """Zwraca `flags` przyjetego dokumentu albo podnosi `DokumentNieprzyjety`.

    Kolejnosc jak u stacji: wersja, typ, termin, wartosci. Termin jest wymagany, bo swiezosc jest tym,
    czym zmiana sie rozchodzi; dokument bez terminu jest odrzucany tak samo jak termin miniony.
    """
    if not isinstance(dokument, dict):
        raise DokumentNieprzyjety("the document is not an object")
    if dokument.get("format_version") != FORMAT_VERSION:
        raise DokumentNieprzyjety(f"unknown format version {dokument.get('format_version')!r}")
    if dokument.get("type") != TYPE:
        raise DokumentNieprzyjety(f"unknown document type {dokument.get('type')!r}")
    nieznane = sorted(set(dokument) - {"format_version", "type", "flags", "issued_at", "valid_until"})
    if nieznane:
        raise DokumentNieprzyjety(f"unknown field(s) in the document: {', '.join(nieznane)}")
    termin = dokument.get("valid_until")
    if not termin:
        raise DokumentNieprzyjety("document without valid_until (freshness is how a change propagates)")
    if (dzis or _datetime.date.today()) > _data(termin):
        raise DokumentNieprzyjety(f"document expired on {termin}")
    if dokument.get("issued_at") is not None:
        _data(dokument["issued_at"])
    flagi = dokument.get("flags") or {}
    if not isinstance(flagi, dict):
        raise DokumentNieprzyjety("flags is not an object")
    nieznane = sorted(set(flagi) - set(POLA_ZNANE))
    if nieznane:
        raise DokumentNieprzyjety(f"unknown field(s) in flags: {', '.join(nieznane)}")
    if flagi.get(POLE_HOTP) is not None and not isinstance(flagi.get(POLE_HOTP), bool):
        raise DokumentNieprzyjety(f"{POLE_HOTP} is not a boolean")
    for pole in (POLE_GRUP_HOTP, POLE_GRUP_FIDO2):
        waliduj_grupy(flagi.get(pole))
    return flagi


def wczytaj_dokument(sciezka: str | pathlib.Path | None = None, dzis: _datetime.date | None = None) -> dict:
    """Wczytuje i weryfikuje dokument; zwraca `flags`, a kazda droga odmowy podnosi `DokumentNieprzyjety`.

    Sciezka: ustawienie `AMFADeploymentFlagsFile`, a bez niego `SCIEZKA_DOMYSLNA`. Plik nieczytelny,
    pusty, za duzy, nie-JSON, bez koperty, ze zlym podpisem, z nieznanym kluczem albo po terminie
    znacza dokladnie to samo: tor zamkniety.
    """
    if sciezka is None:
        sciezka = get_from_config(SYSCONF.AMFA_DEPLOYMENT_FLAGS_FILE, SCIEZKA_DOMYSLNA) or SCIEZKA_DOMYSLNA
    plik = pathlib.Path(str(sciezka))
    # Brak pliku, sciezka do katalogu i katalog bez prawa przejscia to ta sama odpowiedz: nie ma czego
    # czytac. `is_file()` nie podnosi wyjatku na brakujacej sciezce, wiec kazdy taki przypadek konczy sie
    # tym samym powodem.
    if not plik.is_file():
        raise DokumentNieprzyjety(f"file missing or unreadable at {plik}")
    try:
        rozmiar = plik.stat().st_size
    except OSError as blad:
        raise DokumentNieprzyjety(f"file missing or unreadable at {plik} ({blad.strerror})") from None
    if rozmiar > MAKS_ROZMIAR_BAJTOW:
        raise DokumentNieprzyjety(f"file is larger than {MAKS_ROZMIAR_BAJTOW} bytes at {plik}")
    try:
        tresc = plik.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as blad:
        raise DokumentNieprzyjety(f"file unreadable or not UTF-8 at {plik} ({blad})") from None
    try:
        koperta = json.loads(tresc)
    except json.JSONDecodeError as blad:
        raise DokumentNieprzyjety(f"document is not valid JSON ({blad.msg})") from None
    if not isinstance(koperta, dict) or "document" not in koperta or "signature" not in koperta:
        raise DokumentNieprzyjety("missing 'document' or 'signature' part")
    podpis = koperta["signature"]
    if not isinstance(podpis, dict):
        raise DokumentNieprzyjety("the signature is not an object")
    if podpis.get("algorithm") != ALGORITHM:
        raise DokumentNieprzyjety(f"unknown signature algorithm {podpis.get('algorithm')!r}")
    if podpis.get("key_id") != KEY_ID:
        raise DokumentNieprzyjety(f"unknown signing key {podpis.get('key_id')!r} (not on the pinned list)")
    _sprawdz_klucz()
    _podpis_ok(koperta["document"], podpis.get("value"))
    return waliduj_dokument(koperta["document"], dzis)


def flagi() -> dict:
    """`flags` przyjetego dokumentu albo `{}`. Jedno miejsce, w ktorym odmowa staje sie pustka."""
    try:
        return wczytaj_dokument()
    except DokumentNieprzyjety as blad:
        log.info(f"SECURITY EVENT deployment-flags: refused ({blad}) - offline HOTP data stay closed")
    except Exception as blad:  # pragma: no cover - kazdy niespodziewany blad zamyka tor, nigdy otwiera
        log.error(f"SECURITY EVENT deployment-flags: cannot read the document ({blad!r}) - offline HOTP "
                  f"data stay closed")
    return {}


def nazwy_grup(wartosc: object) -> list[str]:
    """Nazwy grup z dokumentu bez wyjatku: dokument przyjety znaczy juz sprawdzone granice."""
    try:
        return waliduj_grupy(wartosc)
    except DokumentNieprzyjety as blad:  # pragma: no cover - nieosiagalne po `flagi()`
        log.info(f"SECURITY EVENT deployment-flags: bad group list ({blad}) - offline HOTP data stay closed")
        return []


def nazwa_do_porownania(wartosc: object) -> str:
    """Nazwa grupy sprowadzona do porownania: bez przedrostka domeny, bez DN, malymi literami.

    Trzy postacie tej samej grupy musza byc ta sama nazwa, bo document i katalog mowia o tej samej grupie
    na dwa sposoby:
      * dokument: `AMFA-offline-hotp` albo `AMITRONIC\\AMFA-offline-hotp` (przedrostek opcjonalny),
      * katalog: `AMFA-offline-hotp` albo DN z `memberOf`: `CN=AMFA-offline-hotp,CN=Users,DC=...`.
    """
    nazwa = str(wartosc or "").strip()
    if not nazwa:
        return ""
    if "=" in nazwa:
        for czlon in nazwa.split(","):
            if czlon.strip().upper().startswith("CN="):
                nazwa = czlon.strip()[3:]
                break
    if "\\" in nazwa:
        nazwa = nazwa.rsplit("\\", 1)[1]
    return nazwa.strip().lower()


def dopuszczony(grupy_konta: object, grupy_z_dokumentu: object) -> bool:
    """Czy konto jest w jakiejkolwiek grupie dopuszczonej dokumentem (dopasowanie dokladne nazwy)."""
    z_konta = {nazwa_do_porownania(grupa) for grupa in _na_liste(grupy_konta)}
    z_dokumentu = {nazwa_do_porownania(grupa) for grupa in _na_liste(grupy_z_dokumentu)}
    z_konta.discard("")
    z_dokumentu.discard("")
    return bool(z_konta & z_dokumentu)


def _na_liste(wartosc: object) -> list[str]:
    """Wartosc atrybutu konta jako lista napisow. Jeden napis jest tak samo poprawny jak lista."""
    if wartosc is None:
        return []
    if isinstance(wartosc, (list, tuple, set)):
        return [str(pozycja) for pozycja in wartosc]
    return [str(wartosc)]


def grupy_konta(uzytkownik: object) -> list[str]:
    """Grupy konta z resolvera; brak konta albo brak grup to pusta lista.

    Klucz ustala wdrozenie (`USERINFO` z `groups <- memberOf`), a rezolver bez niego grup nie oddaje -
    wtedy konta nie da sie dopuscic i tor zostaje zamkniety. Tak ma byc: brak wiedzy nie jest zgoda.
    """
    if uzytkownik is None:
        return []
    try:
        if getattr(uzytkownik, "is_empty", None) and uzytkownik.is_empty():
            return []
        informacje = uzytkownik.get_specific_info([KLUCZ_GRUP]) or {}
    except Exception as blad:
        log.warning(f"Cannot read the account groups: {blad!r} - offline HOTP data stay closed")
        return []
    return [nazwa for nazwa in _na_liste(informacje.get(KLUCZ_GRUP)) if nazwa and nazwa.strip()]


def offline_hotp_allowed_for_user(uzytkownik: object) -> bool:
    """Czy temu kontu wolno wydac dane offline HOTP (wariant B zgloszenia #425).

    Otwarte wylacznie wtedy, gdy **wszystkie** warunki sa spelnione: dokument jest przyjety (plik,
    podpis, klucz, termin, znane pola), dokument otwiera tor (`offline_hotp_allowed`), lista
    `offline_hotp_groups` jest niepusta, a konto jest w ktorejs z tych grup. Kazdy brak wiedzy,
    kazdy blad i kazda pustka znacza "nie wydajemy".
    """
    nazwa_konta = getattr(uzytkownik, "login", None)
    try:
        przyjete_flagi = flagi()
        if not przyjete_flagi:
            log.info("Offline HOTP data closed: no accepted deployment document")
            return False
        if not przyjete_flagi.get(POLE_HOTP, False):
            log.info(f"Offline HOTP data closed: the deployment document does not open the path ({POLE_HOTP})")
            return False
        grupy_z_dokumentu = nazwy_grup(przyjete_flagi.get(POLE_GRUP_HOTP))
        if not grupy_z_dokumentu:
            log.info(f"Offline HOTP data closed: {POLE_GRUP_HOTP} is empty - nobody is admitted")
            return False
        grupy = grupy_konta(uzytkownik)
        if not grupy:
            log.info(f"Offline HOTP data closed: no directory groups for the account {nazwa_konta!r}")
            return False
        if not dopuszczony(grupy, grupy_z_dokumentu):
            log.info(f"Offline HOTP data closed: the account {nazwa_konta!r} is not in any admitted group "
                     f"({len(grupy_z_dokumentu)} group(s) in {POLE_GRUP_HOTP})")
            return False
        return True
    except Exception as blad:  # pragma: no cover - niespodziewany blad nie moze otworzyc toru
        log.error(f"Offline HOTP data closed: cannot decide ({blad!r})")
        return False


def offline_hotp_allowed_for_token(token: object) -> bool:
    """To samo co `offline_hotp_allowed_for_user`, ale od strony tokena.

    Obie drogi wydania danych offline (pierwsza partia i dopelnienie) maja pod reka token, a nie konto,
    wiec bramka bierze je z tokena - jedno miejsce, ktore wie, ze konto to `token.user`.
    """
    return offline_hotp_allowed_for_user(getattr(token, "user", None))

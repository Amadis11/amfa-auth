"""Straznicy zmian AMFA — krok 12, dane offline HOTP tylko z podpisanego dokumentu wdrozeniowego (#425, wariant B).

Plik nalezy do jednego kroku i zaden inny krok go nie dotyka: dzieki temu nakladanie naszych
zmian na nowe wydanie podstawy nie konfliktuje o wspolny plik testow. Patrz AMFA-ZMIANY.md.

Co pilnuje (bez bazy danych i bez labu — wszystko na atrapach i na zrodle):

1. **Klucz w kodzie jest kluczem produktu**: odcisk SHA-256 modulu rowny wpisowi `sha256Modulus`
   z listy kluczy stacji (`PinnedFlagKeys`, wpis `amfa-licence-2026`). Rozjazd znaczylby, ze silnik
   i stacja nie mowia o tym samym kluczu, a dokument podpisany kluczem produktu bylby przyjety
   po jednej stronie i odrzucony po drugiej.
2. **Dokument jest weryfikowany w calosci**: podpis przed terminem, a kazda droga odmowy (brak pliku,
   nie-JSON, brak koperty, zly algorytm, klucz spoza listy, zly podpis, pole nieznane, termin miniony,
   zly ksztalt listy grup) konczy sie odrzuceniem calego dokumentu.
3. **Kanoniczna postac** jest ta sama, ktora podpisuje narzedzie (`scripts/flagi-wdrozeniowe/wystaw.py`):
   klucze posortowane, separatory bez spacji, znaki spoza ASCII bez escapowania.
4. **Fail-closed**: brak dokumentu, dokument bez `offline_hotp_allowed`, pusta lista grup i konto spoza
   listy znacza dokladnie to samo — danych offline HOTP nie wydajemy.
5. **Obie drogi wydania sa zamkniete** (pierwsza partia i dopelnienie), a konto dopuszczone przechodzi
   dalej ta sama droga: liczba kodow z opcji `count`, refilltoken zapisany, PIN w skrocie kodu.
6. **Tor FIDO2 jest nietkniety**: ten krok nie czyta nawet dokumentu dla tokenow webauthn/passkey.

Uruchamianie w drzewie privacyIDEA (cwd = korzen podrepozytorium):
    python -m pytest tests/test_amfa_krok12_offline-hotp-z-dokumentu.py -q
    python tests/test_amfa_krok12_offline-hotp-z-dokumentu.py       # bez pytest, wlasny runner nizej
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import pathlib
import sys
import types

KORZEN = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KORZEN))

from privacyidea.lib import amfa_dokument_wdrozeniowy as dokument  # noqa: E402
from privacyidea.lib.applications.offline import MachineApplication  # noqa: E402
from privacyidea.lib.error import ParameterError  # noqa: E402

#: Odcisk modulu klucza produktu — **wartosc z listy kluczy stacji** (`PinnedFlagKeys` w
#: `forks/credential-provider/CredentialProvider/core/DeploymentFlags.h`, wpis `amfa-licence-2026`).
#: Trzymamy ja tu po to, zeby rozjazd kluczy wyszedl czerwono w silniku, a nie dopiero na stacji
#: jako "podpis dokumentu nie pasuje", gdy obie strony maja racje.
ODCISK_STACJI = "ba892c74f6156bb568aa4d07e447c7d8457bc8ebb4b9d7ec79b04ac6420a18e1"

#: Grupa z dokumentu, nazwana tak, jak nazywa ja czlowiek w katalogu.
GRUPA = "AMFA-offline-hotp"


def _odcisk_modulu(klucz_publiczny) -> str:
    """Odcisk SHA-256 surowego modulu (ta sama regula co `sha256Modulus` po stronie stacji)."""
    modul = klucz_publiczny.public_numbers().n
    return hashlib.sha256(modul.to_bytes((modul.bit_length() + 7) // 8, "big")).hexdigest()


class _KluczTestowy:
    """Podstawia klucz produktu na klucz testowy.

    Klucz prywatny produktu jest w Vaultwardenie i nigdy nie wchodzi do repozytorium, wiec straznik
    podpisuje wlasnym kluczem, a podmienia tylko **material klucza** i jego odcisk. Droga weryfikacji
    jest przez to ta sama, ktora pojdzie w wydaniu.
    """

    def __init__(self, klucz):
        self.klucz = klucz
        self.zachowane = None

    def __enter__(self):
        from cryptography.hazmat.primitives import serialization

        self.zachowane = (dokument.PUBLIC_KEY_PEM, dokument.ODCISK_KLUCZA, dokument.KEY_ID)
        publiczny = self.klucz.public_key().public_bytes(serialization.Encoding.PEM,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo)
        dokument.PUBLIC_KEY_PEM = publiczny.decode("utf-8").rstrip("\n")
        dokument.ODCISK_KLUCZA = _odcisk_modulu(self.klucz.public_key())
        dokument.KEY_ID = "klucz-testowy"
        return self

    def __exit__(self, *_):
        dokument.PUBLIC_KEY_PEM, dokument.ODCISK_KLUCZA, dokument.KEY_ID = self.zachowane


def _para_kluczy():
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _podpis(klucz, tresc_dokumentu: dict) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    podpis = klucz.sign(dokument.canoniczne_bajty(tresc_dokumentu), padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(podpis).decode("ascii")


def _dokument(flagi: dict | None = None, termin: str = "2027-04-30") -> dict:
    """Tresc dokumentu: `flags` jak podaje narzedzie, z terminem wymaganym przez obie strony."""
    domyslne = {dokument.POLE_HOTP: True, dokument.POLE_GRUP_HOTP: [GRUPA]}
    return {"format_version": dokument.FORMAT_VERSION, "type": dokument.TYPE, "issued_at": "2026-10-18",
            "valid_until": termin, "flags": dict(domyslne if flagi is None else flagi)}


def _zapisz(sciezka: pathlib.Path, tresc: dict, klucz, key_id: str = "klucz-testowy") -> pathlib.Path:
    """Zapisuje dokument w tej samej kopercie, ktora wystawia narzedzie."""
    sciezka.write_text(json.dumps({"document": tresc,
                                   "signature": {"algorithm": dokument.ALGORITHM, "key_id": key_id,
                                                 "value": _podpis(klucz, tresc)}}, ensure_ascii=False),
                       encoding="utf-8")
    return sciezka


def _odmowa(sciezka, fragment: str, dzis=None) -> None:
    """Dokument musi zostac odrzucony, a powod musi nazywac przyczyne (bez tego nie wiemy, co naprawic)."""
    try:
        dokument.wczytaj_dokument(sciezka, dzis=dzis)
    except dokument.DokumentNieprzyjety as blad:
        assert fragment.lower() in str(blad).lower(), f"{fragment!r} nie ma w powodzie {blad!s}"
        return
    raise AssertionError(f"dokument przyjety, a mial byc odrzucony: {sciezka}")


#: Konto-atrapa: tylko to, po co siega bramka w torze offline.
class Konto:
    def __init__(self, grupy, login="amfa-test-offline"):
        self.login = login
        self.grupy = grupy

    def is_empty(self):
        return not self.login

    def get_specific_info(self, attributes=None):
        if attributes == ["groups"]:
            return {"groups": self.grupy}
        return {"username": self.login}


class _SilnikBezBazy:
    """Kontekst aplikacji i podstawiona konfiguracja systemowa — straznik nie stawia bazy.

    Sciezka wydania danych offline siega dwoch miejsc konfiguracji: `get_app_config_value` (pi.cfg,
    wystarczy kontekst aplikacji) i `get_from_config` (konfiguracja systemowa z bazy). Kontekst dajemy,
    a to drugie podstawiamy — tak samo jak straznik kroku 3.
    """

    def __init__(self, ustawienia=None):
        self.ustawienia = dict(ustawienia or {})

    def __enter__(self):
        import privacyidea.lib.config as config
        from flask import Flask

        self.aplikacja = Flask(__name__)
        self.kontekst = self.aplikacja.app_context()
        self.kontekst.push()
        self.zachowane = config.get_from_config
        config.get_from_config = lambda klucz=None, domyslne=None, **_k: self.ustawienia.get(klucz, domyslne)
        return self

    def __exit__(self, *_):
        import privacyidea.lib.config as config

        config.get_from_config = self.zachowane
        self.kontekst.pop()


class Token:
    """Token-atrapa: zapisuje to, co silnik z nim zrobil, zeby dalo sie dowiesc, ze nie ruszyl niczego."""

    def __init__(self, grupy, typ="hotp"):
        self.type = typ
        self.user = Konto(grupy)
        self.token = types.SimpleNamespace(count=10)
        self.zapisane = []
        self.ruchy = []

    def get_serial(self):
        return "AMFAOFF001"

    def get_tokeninfo(self, key=None):
        return {"pubKey": "klucz-testowy", "relying_party_id": "amfa.test"}.get(key)

    def decrypt_otpkey(self):
        return "credential-id"

    def write_tokeninfo(self, key, value):
        self.zapisane.append((key, value))

    def split_pin_pass(self, password):
        self.ruchy.append("split_pin_pass")
        return True, password, "654321"

    def get_multi_otp(self, **kw):
        self.ruchy.append(("get_multi_otp", kw.get("count")))
        return True, None, {"otp": {"0": "123456"}}

    def inc_otp_counter(self, increment=1):
        self.ruchy.append(("inc_otp_counter", increment))

    def check_otp(self, *a, **k):
        self.ruchy.append("check_otp")
        return 5

    def set_otp_count(self, count):
        self.ruchy.append(("set_otp_count", count))


def test_klucz_w_kodzie_jest_kluczem_produktu() -> None:
    """Klucz silnika to ten sam material, ktory przypina stacja, a jego odcisk jest w kodzie."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    assert isinstance(dokument.klucz_publiczny(), rsa.RSAPublicKey)
    assert dokument.odcisk_klucza() == dokument.ODCISK_KLUCZA, \
        "klucz w kodzie nie zgadza sie z odciskiem, ktory sam deklaruje (blad rotacji)"
    assert dokument.ODCISK_KLUCZA == ODCISK_STACJI, \
        "odcisk modulu nie jest odciskiem klucza z listy stacji - dokument podpisany kluczem produktu " \
        "bylby przyjety po jednej stronie i odrzucony po drugiej"
    assert dokument.KEY_ID == "amfa-licence-2026", dokument.KEY_ID
    assert dokument.ALGORITHM == "rsa-sha256", dokument.ALGORITHM
    assert (dokument.FORMAT_VERSION, dokument.TYPE) == (1, "deployment-flags")
    # Sciezka domyslna i limit rozmiaru musza byc te same, ktore zna wdrozenie i stacja.
    assert dokument.SCIEZKA_DOMYSLNA.startswith("/etc/amfa/"), dokument.SCIEZKA_DOMYSLNA
    assert dokument.MAKS_ROZMIAR_BAJTOW == 64 * 1024, dokument.MAKS_ROZMIAR_BAJTOW


def test_kanoniczna_postac_jest_ta_sama_co_u_narzedzia() -> None:
    """Podpisywana postac: klucze posortowane, separatory bez spacji, znaki spoza ASCII bez escapowania.

    Ta sama regula, co `canonical_bytes` w module licencji produktu — narzedzie wystawienia podpisuje
    dokladnie te bajty. Rozjazd znaczylby, ze poprawnie podpisany dokument jest odrzucany bez sladu
    po stronie dokumentu, bo tresc wyglada na wlasciwa.
    """
    tresc = {"type": "deployment-flags", "valid_until": "2027-04-30", "format_version": 1,
             "flags": {"offline_hotp_groups": [GRUPA]}}
    oczekiwane = ('{"flags":{"offline_hotp_groups":["AMFA-offline-hotp"]},"format_version":1,'
                  '"type":"deployment-flags","valid_until":"2027-04-30"}').encode("utf-8")
    assert dokument.canoniczne_bajty(tresc) == oczekiwane, dokument.canoniczne_bajty(tresc)
    assert dokument.canoniczne_bajty({"a": "ZMOWA-ŻÓŁĆ"}) == '{"a":"ZMOWA-ŻÓŁĆ"}'.encode("utf-8")


def test_dokument_przyjety_i_kazda_droga_odmowy(tmp_path) -> None:
    """Kazda droga odmowy odrzuca caly dokument; przyjety oddaje `flags`."""
    klucz = _para_kluczy()
    obcy = _para_kluczy()
    with _KluczTestowy(klucz):
        # Przyjety: dokladnie ten ksztalt, ktory wystawia narzedzie.
        flagi = dokument.wczytaj_dokument(_zapisz(tmp_path / "dobre.json", _dokument(), klucz))
        assert flagi[dokument.POLE_HOTP] is True
        assert flagi[dokument.POLE_GRUP_HOTP] == [GRUPA]
        # Dokument z polami bez konsumenta jest przyjmowany i nic nie zmienia (runda 1 z #1042).
        z_odpadami = _zapisz(tmp_path / "odpady.json",
                             _dokument({dokument.POLE_HOTP: True, dokument.POLE_GRUP_HOTP: [GRUPA],
                                        "method_order": ["passkey", "password"]}), klucz)
        assert dokument.wczytaj_dokument(z_odpadami)[dokument.POLE_GRUP_HOTP] == [GRUPA]

        # Podpis: obcy klucz, podmieniona tresc, zly algorytm, klucz spoza listy.
        _odmowa(_zapisz(tmp_path / "obcy.json", _dokument(), obcy), "signature does not match the document")
        podmieniona = _zapisz(tmp_path / "podmiana.json", _dokument(), klucz)
        podmieniona.write_text(podmieniona.read_text(encoding="utf-8").replace('"offline_hotp_allowed": true',
                                                                              '"offline_hotp_allowed": false'),
                               encoding="utf-8")
        _odmowa(podmieniona, "signature does not match the document")
        zly_algorytm = _zapisz(tmp_path / "algo.json", _dokument(), klucz)
        zly_algorytm.write_text(zly_algorytm.read_text(encoding="utf-8").replace('"rsa-sha256"', '"rsa-sha1"'),
                                encoding="utf-8")
        _odmowa(zly_algorytm, "unknown signature algorithm")
        _odmowa(_zapisz(tmp_path / "klucz.json", _dokument(), klucz, key_id="amfa-licence-2027"),
                "unknown signing key")

        # Koperta i JSON.
        brak_koperty = tmp_path / "brak-koperty.json"
        brak_koperty.write_text('{"document": {"format_version": 1}}', encoding="utf-8")
        _odmowa(brak_koperty, "missing 'document' or 'signature'")
        nie_json = tmp_path / "nie-json.json"
        nie_json.write_text("to nie jest JSON", encoding="utf-8")
        _odmowa(nie_json, "not valid JSON")

        # Termin: wymagany i nie moze byc miniony (swiezosc jest tym, czym zmiana sie rozchodzi).
        _odmowa(_zapisz(tmp_path / "bez-terminu.json", _dokument(termin=""), klucz), "without valid_until")
        miniony = _zapisz(tmp_path / "miniony.json", _dokument(termin="2026-01-01"), klucz)
        _odmowa(miniony, "document expired")
        assert dokument.wczytaj_dokument(miniony, dzis=datetime.date(2025, 12, 31))[dokument.POLE_HOTP] is True

        # Wersja, typ i pola nieznane: pole spoza kontraktu uniewaznia dokument, bo inaczej starszy
        # odbiorca ignorowalby nowa regule po cichu.
        zla_wersja = _dokument()
        zla_wersja["format_version"] = 2
        _odmowa(_zapisz(tmp_path / "wersja.json", zla_wersja, klucz), "unknown format version")
        zly_typ = _dokument()
        zly_typ["type"] = "licence"
        _odmowa(_zapisz(tmp_path / "typ.json", zly_typ, klucz), "unknown document type")
        _odmowa(_zapisz(tmp_path / "pole.json",
                        _dokument({dokument.POLE_HOTP: True, dokument.POLE_GRUP_HOTP: [GRUPA],
                                   "offline_grupy": [GRUPA]}), klucz), "unknown field(s) in flags")
        pole_w_dokumencie = _dokument()
        pole_w_dokumencie["podpisane_przez"] = "AMITRONIC"
        _odmowa(_zapisz(tmp_path / "pole-dok.json", pole_w_dokumencie, klucz),
                "unknown field(s) in the document")

        # Ksztalt wartosci i granice listy grup (te same co po stronie stacji).
        _odmowa(_zapisz(tmp_path / "typ-flagi.json",
                        _dokument({dokument.POLE_HOTP: "true", dokument.POLE_GRUP_HOTP: [GRUPA]}), klucz),
                "is not a boolean")
        _odmowa(_zapisz(tmp_path / "grupa-nie-lista.json",
                        _dokument({dokument.POLE_HOTP: True, dokument.POLE_GRUP_HOTP: GRUPA}), klucz),
                "is not a list")
        _odmowa(_zapisz(tmp_path / "grupa-powtorzona.json",
                        _dokument({dokument.POLE_HOTP: True,
                                   dokument.POLE_GRUP_HOTP: [GRUPA, GRUPA.lower()]}), klucz), "repeats")
        _odmowa(_zapisz(tmp_path / "grupa-pusta.json",
                        _dokument({dokument.POLE_HOTP: True, dokument.POLE_GRUP_HOTP: ["  "]}), klucz),
                "group name is empty")
        _odmowa(_zapisz(tmp_path / "grupa-dluga.json",
                        _dokument({dokument.POLE_HOTP: True,
                                   dokument.POLE_GRUP_HOTP: ["G" + "x" * dokument.GRUPA_DLUGOSC_LIMIT]}), klucz),
                "longer than")
        _odmowa(_zapisz(tmp_path / "grupy-duzo.json",
                        _dokument({dokument.POLE_HOTP: True,
                                   dokument.POLE_GRUP_HOTP: [f"GRP-{i}" for i in range(dokument.GRUPY_LIMIT + 1)]}),
                        klucz), "more entries than")

        # Plik: brak, katalog zamiast pliku, za duzy.
        _odmowa(tmp_path / "nie-ma.json", "missing or unreadable")
        _odmowa(tmp_path, "missing or unreadable")
        za_duzy = tmp_path / "za-duzy.json"
        za_duzy.write_text("x" * (dokument.MAKS_ROZMIAR_BAJTOW + 1), encoding="utf-8")
        _odmowa(za_duzy, "larger than")


def test_fail_closed_to_nie_wydajemy_danych(tmp_path) -> None:
    """Pustka i kazde "nie wiem" znacza "nie wydajemy" — nigdy "wszyscy"."""
    from privacyidea.lib.config import SYSCONF

    klucz = _para_kluczy()
    # Grupy z katalogu: DN z `memberOf`, dokladnie to, co oddaje resolver wdrozenia.
    w_grupie = Konto([f"CN={GRUPA},CN=Users,DC=amitronic,DC=test"])
    inna_grupa = Konto(["CN=AMFA-haslo-fido,CN=Users,DC=amitronic,DC=test"])
    podobna = Konto([f"CN={GRUPA}2,CN=Users,DC=amitronic,DC=test"])
    bez_grup = Konto([])

    with _KluczTestowy(klucz):
        plik = _zapisz(tmp_path / "dobre.json", _dokument(), klucz)
        zachowana = dokument.wczytaj_dokument
        dokument.wczytaj_dokument = lambda *a, **k: zachowana(plik, *a, **k)
        try:
            assert dokument.offline_hotp_allowed_for_user(w_grupie) is True
            # Nazwa z przedrostkiem domeny w dokumencie i goly CN w katalogu to ta sama grupa.
            assert dokument.dopuszczony([f"CN={GRUPA},CN=Users,DC=amitronic,DC=test"],
                                        [f"AMITRONIC\\{GRUPA}"]) is True
            # Konto spoza listy, grupa podobna nazwa, konto bez grup, brak konta — nie.
            assert dokument.offline_hotp_allowed_for_user(inna_grupa) is False
            assert dokument.offline_hotp_allowed_for_user(podobna) is False
            assert dokument.offline_hotp_allowed_for_user(bez_grup) is False
            assert dokument.offline_hotp_allowed_for_user(None) is False

            # Pusta lista grup: dokument przyjety, a mimo to nikt nie jest dopuszczony.
            dokument.wczytaj_dokument = lambda *a, **k: dokument.waliduj_dokument(
                _dokument({dokument.POLE_HOTP: True, dokument.POLE_GRUP_HOTP: []}))
            assert dokument.offline_hotp_allowed_for_user(w_grupie) is False

            # Dokument, ktory nie otwiera toru HOTP, oraz dokument, ktory nie wymienia ani jednej grupy.
            dokument.wczytaj_dokument = lambda *a, **k: dokument.waliduj_dokument(
                _dokument({dokument.POLE_HOTP: False, dokument.POLE_GRUP_HOTP: [GRUPA]}))
            assert dokument.offline_hotp_allowed_for_user(w_grupie) is False
            dokument.wczytaj_dokument = lambda *a, **k: dokument.waliduj_dokument(
                _dokument({dokument.POLE_HOTP: True}))
            assert dokument.offline_hotp_allowed_for_user(w_grupie) is False
        finally:
            dokument.wczytaj_dokument = zachowana

    # Brak pliku: ustawienie sciezki wskazuje na nieistniejacy dokument.
    brak = pathlib.Path("/etc/amfa/nie-ma-takiego-dokumentu.json")
    oryginalne_branie = dokument.get_from_config
    dokument.get_from_config = lambda klucz, domyslne=None, **k: (str(brak)
                                                                 if klucz == SYSCONF.AMFA_DEPLOYMENT_FLAGS_FILE
                                                                 else domyslne)
    try:
        assert dokument.flagi() == {}, "brak pliku musi znaczyc brak flag"
        assert dokument.offline_hotp_allowed_for_user(w_grupie) is False, \
            "bez dokumentu silnik wydalby dane offline HOTP - doloz fail-closed"
    finally:
        dokument.get_from_config = oryginalne_branie


def test_obie_drogi_wydania_zamkniete_dla_niedopuszczonego(tmp_path) -> None:
    """Pierwsza partia i dopelnienie: konto niedopuszczone nie dostaje nic, dopuszczone idzie dalej."""
    import privacyidea.lib.applications.offline as offline

    klasa_offline = offline.MachineApplication
    dopuszczone = [f"CN={GRUPA},CN=Users,DC=amitronic,DC=test"]
    niedopuszczone = ["CN=AMFA-inna,CN=Users,DC=amitronic,DC=test"]

    klucz = _para_kluczy()
    with _SilnikBezBazy(), _KluczTestowy(klucz):
        plik = _zapisz(tmp_path / "dobre.json", _dokument(), klucz)
        zachowana = dokument.wczytaj_dokument
        dokument.wczytaj_dokument = lambda *a, **k: zachowana(plik, *a, **k)
        oryginalne_branie = offline.get_one_token
        oryginalne_otp = klasa_offline.get_offline_otps
        oryginalne_losowanie = offline.geturandom
        # Refilltoken powstaje z HSM-a silnika; straznik nie stawia HSM-a, wiec podstawiamy losowanie.
        offline.geturandom = lambda rozmiar, hex=False: "ab" * rozmiar if hex else b"\x00" * rozmiar
        try:
            # (a) pierwsza partia: konto niedopuszczone nie dostaje nic i nie rusza tokena.
            token_zly = Token(niedopuszczone)
            offline.get_one_token = lambda serial: token_zly
            assert klasa_offline.get_authentication_item("hotp", "AMFAOFF001", challenge="1234",
                                                         options={"count": 5}) == {}
            assert token_zly.zapisane == [] and token_zly.ruchy == [], \
                "bramka przepuscila zapis tokeninfo albo ruszenie licznika dla konta niedopuszczonego"

            # (a2) dopelnienie: kontu niedopuszczonemu silnik odmawia (zwykla odmowa, nie brak danych).
            try:
                klasa_offline.get_refill(Token(niedopuszczone), "1234")
                raise AssertionError("silnik dopelnil partie kontu niedopuszczonemu")
            except ParameterError:
                pass

            # (b) konto dopuszczone idzie dalej ta sama droga: liczba kodow z opcji `count`,
            #     refilltoken zapisany, PIN wchodzi do skrotu kodu.
            token_ok = Token(dopuszczone)
            wywolania = []

            def atrapa_otp(token, otppin, amount, rounds=offline.ROUNDS):
                wywolania.append((token, otppin, amount, rounds))
                return {"0": "$pbkdf2-sha512$6549$sol$skrot"}

            offline.get_one_token = lambda serial: token_ok
            klasa_offline.get_offline_otps = staticmethod(atrapa_otp)
            pozycja = klasa_offline.get_authentication_item("hotp", "AMFAOFF001", challenge="1234",
                                                            options={"count": 5})
            assert pozycja["response"] == {"0": "$pbkdf2-sha512$6549$sol$skrot"}, pozycja
            assert len(wywolania) == 1 and wywolania[0][2] == 5 and wywolania[0][1] == "1234", wywolania
            assert len(pozycja["refilltoken"]) == offline.REFILLTOKEN_LENGTH * 2, pozycja["refilltoken"]
            assert [nazwa for nazwa, _ in token_ok.zapisane] == ["refilltoken"], token_ok.zapisane

            # (b2) dopelnienie konta dopuszczonego dochodzi do oceny kodu i oddaje tyle kodow, ile zuzyto.
            klasa_offline.get_offline_otps = staticmethod(oryginalne_otp)
            token_refill = Token(dopuszczone)
            kody = klasa_offline.get_refill(token_refill, "1234")
            assert list(kody) == ["0"] and kody["0"].startswith("$pbkdf2-sha512$"), kody
            assert "check_otp" in token_refill.ruchy, token_refill.ruchy
            assert ("get_multi_otp", 6) in token_refill.ruchy, token_refill.ruchy
            assert ("offline_counter", 100) in token_refill.zapisane, token_refill.zapisane
        finally:
            dokument.wczytaj_dokument = zachowana
            offline.get_one_token = oryginalne_branie
            klasa_offline.get_offline_otps = oryginalne_otp
            offline.geturandom = oryginalne_losowanie


def test_tor_fido2_nietkniety_przez_ten_krok() -> None:
    """webauthn/passkey nie czytaja nawet dokumentu — ta bramka nalezy do toru HOTP (#1070 zostaje osobno)."""
    import privacyidea.lib.applications.offline as offline

    def nie_wolno(*_a, **_k):
        raise AssertionError("ten krok nie moze czytac dokumentu dla tokenu FIDO2")

    class TokenFido2(Token):
        def __init__(self):
            super().__init__([])
            self.type = "webauthn"

        def get_tokeninfo(self, key=None):
            return "klucz-testowy" if key == "pubKey" else "amfa.test"

    zachowane = (dokument.wczytaj_dokument, offline.get_one_token, offline.geturandom)
    dokument.wczytaj_dokument = nie_wolno
    offline.get_one_token = lambda serial: TokenFido2()
    # Refilltoken klucza sprzetowego powstaje z HSM-a silnika; straznik nie stawia HSM-a.
    offline.geturandom = lambda rozmiar, hex=False: "ab" * rozmiar if hex else b"\x00" * rozmiar
    try:
        with _SilnikBezBazy():
            pozycja = offline.MachineApplication.get_authentication_item(
                "webauthn", "WAN0000001", user_agent="amfa-cp/1.0 Windows/amfa-145",
                user_verification="required")
            assert pozycja["response"]["credentialId"] == "credential-id", pozycja
            assert pozycja["response"]["userVerification"] == "required", pozycja
    finally:
        dokument.wczytaj_dokument, offline.get_one_token, offline.geturandom = zachowane


def test_zrodlo_bramki_stoi_przed_wydaniem_danych() -> None:
    """Bramka w zrodle: przed pierwsza partia, przed dopelnieniem i przed zapisem `refilltokenu`."""
    zrodlo = (KORZEN / "privacyidea" / "lib" / "applications" / "offline.py").read_text(encoding="utf-8")
    assert "offline_hotp_allowed_for_token" in zrodlo, "brak bramki w torze offline"
    # Pierwsza partia: bramka przed `generate_new_refilltoken` (nowy refilltoken uniewaznilby zapas stacji).
    bramka = zrodlo.index('if token_type == "hotp" and not offline_hotp_allowed_for_token(token):')
    assert bramka < zrodlo.index('ret["refilltoken"] = MachineApplication.generate_new_refilltoken')
    assert bramka < zrodlo.index("MachineApplication.get_offline_otps(token,", bramka)
    # Dopelnienie: bramka przed ocena kodu i przed ruszeniem licznika.
    dopelnienie = zrodlo.index('if token.type.lower() == "hotp" and not offline_hotp_allowed_for_token(token):')
    assert dopelnienie < zrodlo.index("token.split_pin_pass(password)")
    assert dopelnienie < zrodlo.index("token.check_otp(otpval")
    # Bramka jest w torze HOTP i tylko w nim: galaz FIDO2 ma wlasny kod i nie wola tej funkcji.
    assert zrodlo.count("offline_hotp_allowed_for_token") == 3, zrodlo.count("offline_hotp_allowed_for_token")
    # Klucz ustawienia sciezki dokumentu jest kontraktem z wdrozeniem (ustawienia.cfg -> env kontenera).
    assert dokument.SYSCONF.AMFA_DEPLOYMENT_FLAGS_FILE == "AMFADeploymentFlagsFile"
    ustalenia = (KORZEN / "privacyidea" / "lib" / "config.py").read_text(encoding="utf-8")
    assert 'AMFA_DEPLOYMENT_FLAGS_FILE = "AMFADeploymentFlagsFile"' in ustalenia


if __name__ == "__main__":
    # Bez pytest (na wezlach go nie ma) uruchamiamy wszystkie strazniki i konczymy kodem wyjscia.
    import sys as _sys
    import tempfile

    _bledy = 0
    for _nazwa, _funkcja in sorted(globals().items()):
        if _nazwa.startswith("test_") and callable(_funkcja):
            try:
                if _funkcja.__code__.co_argcount:
                    with tempfile.TemporaryDirectory() as _katalog:
                        _funkcja(pathlib.Path(_katalog))
                else:
                    _funkcja()
                print(f"OK   {_nazwa}")
            except Exception as _blad:            # takze brak zaleznosci: straznik nie mogl ruszyc
                _bledy += 1
                print(f"FAIL {_nazwa}: {type(_blad).__name__}: {_blad}")
    sys.exit(1 if _bledy else 0)

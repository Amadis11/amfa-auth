"""Ktore opcje przylaczenia decyduja o oknie refillu offline HOTP (#1156, audyt 20.11.2026).

`/validate/offlinerefill` bierze `count`/`rounds` z przylaczenia offline i przekazuje je do
`MachineApplication.get_refill()`, ktore uzywa ich jako **okna akceptacji** prezentowanego OTP
(`first_offline_counter = current_counter - count`). Gdy token ma wiecej niz jedno przylaczenie offline,
a stacje roznia sie limitem, odczyt jednego przylaczenia rozciaga okno akceptacji wszystkich pozostalych
— czyli jedna stacja dostaje polityke innej. Zwykly refill HOTP nie niesie nazwy maszyny (w odroznieniu
od webauthn/passkey, ktore maja `refilltoken_<computer>` z naglowka), wiec rozbieznosci nie da sie tu
rozstrzygnac: serwer ma odmowic **zdefiniowanym** bledem zamiast zgadywac.
"""
from __future__ import annotations

from privacyidea.lib.machine import attach_token
from privacyidea.lib.machineresolver import save_resolver as save_machine_resolver
from privacyidea.lib.token import get_tokens, init_token, remove_token
from privacyidea.lib.user import User

from .api_validate_common import HOSTSFILE
from .base import MyApiTestCase

SERIAL = "AMFA-REFILL-OPTS-1156"
RESOLVER = "refill-opts-hosts"


class OfflineRefillOptionsTests(MyApiTestCase):
    """Przylaczenia offline moga miec rozne `count`/`rounds` — refill nie moze wybierac po cichu."""

    def setUp(self):
        super().setUp()
        self.setUp_user_realms()
        save_machine_resolver({
            "name": RESOLVER, "type": "hosts", "filename": HOSTSFILE,
            "type.filename": "string", "desc.filename": "hosts",
            "pw": "secret", "type.pw": "password",
        })

    def _attach(self, hostname, count, rounds=None):
        options = {"count": count}
        if rounds is not None:
            options["rounds"] = rounds
        attach_token(SERIAL, "offline", hostname=hostname, resolver_name=RESOLVER, options=options)

    def _login_and_take_window(self, hostname):
        """Jedno udane `/validate/check`; zwraca (refilltoken, lista wpisow offline)."""
        with self.app.test_request_context(
            "/validate/check", method="POST",
            data={"serial": SERIAL, "pass": "pin755224"},
            environ_base={"REMOTE_ADDR": "192.168.0.2"},
        ):
            response = self.app.full_dispatch_request()
            self.assertEqual(response.status_code, 200, response.json)
            self.assertTrue(response.json["result"]["value"], response.json)
            entries = response.json["auth_items"]["offline"]
        self.assertTrue(entries, response.json)
        return entries[0]["refilltoken"], entries

    def _refill(self, refilltoken, otp):
        with self.app.test_request_context(
            "/validate/offlinerefill", method="POST",
            data={"serial": SERIAL, "pass": "pin" + otp, "refilltoken": refilltoken},
            environ_base={"REMOTE_ADDR": "192.168.0.2"},
        ):
            return self.app.full_dispatch_request()

    def test_01_single_attachment_refill_uses_its_own_window(self):
        """Jedno przylaczenie: refill dziala i rotuje refilltoken (zachowanie bez zmian)."""
        init_token({"serial": SERIAL, "otpkey": self.otpkey, "type": "hotp", "pin": "pin"},
                   user=User("cornelius", self.realm1))
        try:
            self._attach("pippin", count=3)
            refilltoken, entries = self._login_and_take_window("pippin")
            counter = min(int(key) for key in entries[0]["response"])
            token = get_tokens(serial=SERIAL)[0]
            response = self._refill(refilltoken, token._calc_otp(counter))
            self.assertEqual(response.status_code, 200, response.json)
            self.assertTrue(response.json["result"]["value"], response.json)
            replacement = response.json["auth_items"]["offline"][0]["refilltoken"]
            self.assertNotEqual(refilltoken, replacement, "refill must rotate the secret")
        finally:
            remove_token(SERIAL)

    def test_02_matching_windows_still_refill(self):
        """Dwa przylaczenia z **takimi samymi** limitami: refill dziala jak dotad."""
        init_token({"serial": SERIAL, "otpkey": self.otpkey, "type": "hotp", "pin": "pin"},
                   user=User("cornelius", self.realm1))
        try:
            self._attach("pippin", count=3, rounds=1)
            self._attach("borodin", count=3, rounds=1)
            refilltoken, entries = self._login_and_take_window("pippin")
            counter = min(int(key) for key in entries[0]["response"])
            token = get_tokens(serial=SERIAL)[0]
            response = self._refill(refilltoken, token._calc_otp(counter))
            self.assertEqual(response.status_code, 200, response.json)
            self.assertTrue(response.json["result"]["value"], response.json)
        finally:
            remove_token(SERIAL)

    def test_03_disagreeing_windows_are_refused_not_guessed(self):
        """Rozne limity przylaczen: serwer odmawia zdefiniowanym bledem i nic nie zuzywa.

        Wartosc `count` jest jednoczesnie **oknem akceptacji** refillu, wiec odczyt pierwszego
        przylaczenia rozciaga polityke jednej stacji na druga (audyt 20.11.2026). Zwykly refill HOTP
        nie niesie nazwy maszyny, wiec rozstrzygniecie nie istnieje — zostaje fail-closed.

        Pomiar sprzed poprawki (na tym samym ukladzie): przylaczenie `count=100` postawione pierwsze
        przyjmowalo refill licznikami 0…5 (`200`), a postawione drugie odrzucalo je (`400 ERR401`),
        czyli wynik zalezal od **kolejnosci przylaczen**, nie od stacji. Teraz obie kolejnosc sa
        odmowa, a OTP jest poprawny dla tokenu — dowod, ze odmowa dotyczy konfiguracji, nie kodu.
        """
        init_token({"serial": SERIAL, "otpkey": self.otpkey, "type": "hotp", "pin": "pin"},
                   user=User("cornelius", self.realm1))
        try:
            self._attach("borodin", count=100)
            self._attach("pippin", count=3)
            refilltoken, entries = self._login_and_take_window("borodin")
            counter = min(int(key) for key in entries[0]["response"])
            token = get_tokens(serial=SERIAL)[0]
            before_count = token.token.count
            response = self._refill(refilltoken, token._calc_otp(counter))
            self.assertEqual(response.status_code, 400, response.json)
            self.assertIn("ambiguous", response.json["result"]["error"]["message"].lower(),
                          response.json)
            after = get_tokens(serial=SERIAL)[0]
            self.assertEqual(after.get_tokeninfo("refilltoken"), refilltoken,
                             "refused refill must not rotate the credential")
            self.assertEqual(after.token.count, before_count,
                             "refused refill must not consume offline counters")
            # Online authentication keeps working: the refusal is a defined
            # configuration error, not a broken token. Use a FRESH code —
            # `pin755224` was already consumed by the login above.
            fresh = get_tokens(serial=SERIAL)[0]
            with self.app.test_request_context(
                "/validate/check", method="POST",
                data={"serial": SERIAL, "pass": "pin" + fresh._calc_otp(fresh.token.count)},
                environ_base={"REMOTE_ADDR": "192.168.0.2"},
            ):
                online = self.app.full_dispatch_request()
                self.assertTrue(online.json["result"]["value"], online.json)
        finally:
            remove_token(SERIAL)

    def test_04_refusal_does_not_depend_on_attachment_order(self):
        """Ta sama rozbieznosc z przylaczeniami w odwrotnej kolejnosci — tez odmowa."""
        init_token({"serial": SERIAL, "otpkey": self.otpkey, "type": "hotp", "pin": "pin"},
                   user=User("cornelius", self.realm1))
        try:
            self._attach("pippin", count=3)
            self._attach("borodin", count=100)
            refilltoken, entries = self._login_and_take_window("pippin")
            counter = min(int(key) for key in entries[0]["response"])
            token = get_tokens(serial=SERIAL)[0]
            response = self._refill(refilltoken, token._calc_otp(counter))
            self.assertEqual(response.status_code, 400, response.json)
            self.assertIn("ambiguous", response.json["result"]["error"]["message"].lower(),
                          response.json)
        finally:
            remove_token(SERIAL)

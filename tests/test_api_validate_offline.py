# SPDX-FileCopyrightText: 2024 NetKnights GmbH <https://netknights.it>
# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import datetime
import json
import logging
import os
import re
import shutil
import tempfile
import time
from base64 import b32encode
from datetime import timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import mock
import responses
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dateutil.tz import tzlocal
from passlib.hash import argon2
from testfixtures import Replace, test_datetime
from testfixtures import log_capture

from privacyidea.lib import _
from privacyidea.lib.amfa_offline_entitlement import EXPECTED_KID, POLICY_FILE, PUBLIC_KEY_FILE
from privacyidea.lib.applications.offline import REFILLTOKEN_LENGTH
from privacyidea.lib.authcache import _hash_password
from privacyidea.lib.challenge import get_challenges
from privacyidea.lib.config import (set_privacyidea_config,
                                    get_inc_fail_count_on_false_pin,
                                    delete_privacyidea_config, SYSCONF)
from privacyidea.lib.container import init_container, find_container_by_serial, create_container_template
from privacyidea.lib.error import Error
from privacyidea.lib.event import delete_event
from privacyidea.lib.event import set_event
from privacyidea.lib.machine import attach_token, detach_token
from privacyidea.lib.machineresolver import save_resolver as save_machine_resolver
from privacyidea.lib.policies.actions import PolicyAction
from privacyidea.lib.policy import SCOPE, set_policy, delete_policy, AUTHORIZED
from privacyidea.lib.radiusserver import add_radius
from privacyidea.lib.realm import set_realm, set_default_realm, delete_realm
from privacyidea.lib.resolver import save_resolver, get_resolver_list, delete_resolver
from privacyidea.lib.smsprovider.SMSProvider import set_smsgateway
from privacyidea.lib.token import (get_tokens, init_token, remove_token,
                                   reset_token, enable_token, revoke_token,
                                   set_pin, get_one_token, unassign_token)
from privacyidea.lib.tokenclass import (ClientMode, FAILCOUNTER_EXCEEDED,
                                        FAILCOUNTER_CLEAR_TIMEOUT, DATE_FORMAT,
                                        AUTH_DATE_FORMAT)
from privacyidea.lib.tokens.passwordtoken import DEFAULT_LENGTH as DEFAULT_LENGTH_PW
from privacyidea.lib.tokens.pushtoken import PushAction, POLL_ONLY, strip_pem_headers
from privacyidea.lib.tokens.registrationtoken import DEFAULT_LENGTH as DEFAULT_LENGTH_REG
from privacyidea.lib.tokens.registrationtoken import RegistrationTokenClass
from privacyidea.lib.tokens.smstoken import SmsTokenClass
from privacyidea.lib.tokens.totptoken import HotpTokenClass
from privacyidea.lib.tokens.yubikeytoken import YubikeyTokenClass
from privacyidea.lib.user import (User)
from privacyidea.lib.users.internal_user_attributes import InternalUserAttributes
from privacyidea.lib.utils import AUTH_RESPONSE
from privacyidea.lib.utils import to_unicode
from privacyidea.models import (Token, Policy, Challenge, AuthCache, db, TokenOwner, Realm, CustomUserAttribute,
                                NodeName)
from . import smtpmock, ldap3mock, radiusmock
from .base import MyApiTestCase
from .test_lib_tokencontainer import MockSmartphone

from .api_validate_common import LDAPDirectory, OTPs, HOSTSFILE, DICT_FILE, setup_sms_gateway


HOTP_OFFLINE_GROUP = "AMFA-hotp"
OFFLINE_FLAGS_KEY_ID = "offline-test-issuer"


def _signed_offline_flags_env(directory, hotp_groups, hotp_allowed=True):
    """Provision the signed deployment-flags document a deployment publishes.

    Offline issuance is authorised against this document (#1605), so any test
    switching the signer on has to publish it next to the pinned public half.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    document = {
        "format_version": 1,
        "type": "deployment-flags",
        "valid_until": (datetime.datetime.now(timezone.utc).date()
                        + datetime.timedelta(days=7)).isoformat(),
        "flags": {"offline_hotp_allowed": bool(hotp_allowed),
                  "offline_hotp_groups": list(hotp_groups)},
    }
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    directory = Path(directory)
    (directory / "flags.json").write_text(json.dumps({
        "document": document,
        "signature": {
            "algorithm": "rsa-sha256",
            "key_id": OFFLINE_FLAGS_KEY_ID,
            "value": base64.b64encode(
                key.sign(payload, padding.PKCS1v15(), hashes.SHA256())).decode("ascii"),
        },
    }), encoding="utf-8")
    (directory / "public.pem").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return {POLICY_FILE: str(directory / "flags.json"),
            PUBLIC_KEY_FILE: str(directory / "public.pem"),
            EXPECTED_KID: OFFLINE_FLAGS_KEY_ID}


def _directory_with_groups(groups):
    """Stand-in for the AD resolver; only the reported membership matters."""
    return SimpleNamespace(
        group_attribute_mapping_key="groups",
        get_available_info_keys=lambda: ["groups"],
        get_user_info=lambda _uid, attributes=None: {"groups": list(groups)},
    )


class AValidateOfflineTestCase(MyApiTestCase):
    """
    Test api.validate endpoints that are responsible for offline auth.
    """

    def _resend_and_check_unspecific_error(self, status_code: int):
        set_policy(name="hide_specific_error_message", scope=SCOPE.TOKEN,
                   action=f"{PolicyAction.HIDE_SPECIFIC_ERROR_MESSAGE_FOR_OFFLINE_REFILL}=true")
        try:
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, status_code, res)
            data = res.json
            self.assertEqual(Error.VALIDATE, data["result"]["error"]["code"])
            self.assertEqual("Failed offline token refill", data["result"]["error"]["message"])

            # hide_auth_error_status additionally normalizes the masked failure's
            # HTTP status code to a uniform 401
            set_policy(name="hide_auth_error_status", scope=SCOPE.HARDENING,
                       action=PolicyAction.HIDE_AUTH_ERROR_STATUS)
            try:
                res = self.app.full_dispatch_request()
                self.assertEqual(res.status_code, 401, res)
                self.assertEqual(res.json["result"]["error"]["message"], "Failed offline token refill")
            finally:
                delete_policy("hide_auth_error_status")
        finally:
            delete_policy("hide_specific_error_message")

    def test_00_create_realms(self):
        self.setUp_user_realms()
        self.setUp_user_realm2()

        # create a  token and assign it to the user
        db_token = Token(self.serials[0], tokentype="hotp")
        db_token.update_otpkey(self.otpkey)
        db_token.save()
        token = HotpTokenClass(db_token)
        self.assertTrue(token.token.serial == self.serials[0], token)
        token.add_user(User("cornelius", self.realm1))
        token.set_pin("pin")
        self.assertEqual(token.token.first_owner.user_id, "1000")

    def test_01_validate_offline(self):
        # create offline app
        # tokenobj = get_tokens(self.serials[0])[0]
        mr_obj = save_machine_resolver({"name": "testresolver",
                                        "type": "hosts",
                                        "filename": HOSTSFILE,
                                        "type.filename": "string",
                                        "desc.filename": "the filename with the "
                                                         "hosts",
                                        "pw": "secret",
                                        "type.pw": "password"})
        self.assertTrue(mr_obj > 0)
        # Attach the offline app to pippin
        attach_token(self.serials[0], "offline", hostname="pippin",
                     resolver_name="testresolver", options={"count": 100})

        # first online validation
        with self.app.test_request_context('/validate/check',
                                           method='POST',
                                           data={"user": "cornelius",
                                                 "pass": "pin287082"},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            data = res.json
            result = data.get("result")
            self.assertTrue(result.get("status"), result)
            self.assertTrue(result.get("value"), result)
            detail = res.json.get("detail")
            self.assertEqual(detail.get("otplen"), 6)
            auth_items = res.json.get("auth_items")
            offline = auth_items.get("offline")[0]
            # Check the number of OTP values
            self.assertEqual(len(offline.get("response")), 100)
            self.assertEqual(offline.get("username"), "cornelius")
            # A HOTP offline item is a mapping of counter values to hashed OTP values, so it carries no FIDO2
            # user verification requirement
            self.assertNotIn("userVerification", offline.get("response"))
            refilltoken_1 = offline.get("refilltoken")
            self.assertEqual(len(refilltoken_1), 2 * REFILLTOKEN_LENGTH)
            # check the token counter
            tok = get_tokens(serial=self.serials[0])[0]
            self.assertEqual(tok.token.count, 102)

        # first refill with the 5th value
        with self.app.test_request_context('/validate/offlinerefill',
                                           method='POST',
                                           data={"serial": self.serials[0],
                                                 "pass": "pin338314",
                                                 "refilltoken": refilltoken_1},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            data = res.json
            result = res.json.get("result")
            self.assertTrue(result.get("status") is True, result)
            self.assertTrue(result.get("value") is True, result)
            auth_items = res.json.get("auth_items")
            offline = auth_items.get("offline")[0]
            # Check the number of OTP values
            self.assertEqual(len(offline.get("response")), 3)
            self.assertTrue("102" in offline.get("response"))
            self.assertTrue("103" in offline.get("response"))
            self.assertTrue("104" in offline.get("response"))
            refilltoken_2 = offline.get("refilltoken")
            self.assertEqual(len(refilltoken_2), 2 * REFILLTOKEN_LENGTH)
            # check the token counter
            tok = get_tokens(serial=self.serials[0])[0]
            self.assertEqual(tok.token.count, 105)
            # The refilltoken changes each time
            self.assertNotEqual(refilltoken_1, refilltoken_2)

        # refill with wrong refill token fails
        with self.app.test_request_context('/validate/offlinerefill',
                                           method='POST',
                                           data={"serial": self.serials[0],
                                                 "pass": "pin520489",
                                                 "refilltoken": 'a' * 2 * REFILLTOKEN_LENGTH},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            data = res.json
            self.assertEqual(data.get("result").get("error").get("message"),
                             "ERR905: Token is not an offline token or refill token is incorrect")

            self._resend_and_check_unspecific_error(400)
            # A failed refill must not rotate the stored refilltoken
            self.assertEqual(refilltoken_2, get_tokens(serial=self.serials[0])[0].get_tokeninfo("refilltoken"))

        # Simulate an admin disabling the token while this request waited
        # for the row lock: the refreshed token is disabled even though
        # get_tokens() initially returned an active token. The refill must
        # not issue OTPs or rotate its authorization token.
        original_refresh = db.session.refresh

        def disabled_after_lock(record, *args, **kwargs):
            original_refresh(record, *args, **kwargs)
            if isinstance(record, Token) and record.serial == self.serials[0]:
                record.active = False

        with mock.patch.object(db.session, "refresh", side_effect=disabled_after_lock):
            with self.app.test_request_context('/validate/offlinerefill',
                                               method='POST',
                                               data={"serial": self.serials[0],
                                                     "pass": "pin520489",
                                                     "refilltoken": refilltoken_2},
                                               environ_base={'REMOTE_ADDR': '192.168.0.2'}):
                response = self.app.full_dispatch_request()
                self.assertEqual(response.status_code, 400, response)
                self.assertIn("The token is not valid.", response.json["result"]["error"]["message"])
        # Restore normal token state for subsequent success-path checks.
        enable_token(self.serials[0], True)
        self.assertEqual(refilltoken_2, get_tokens(serial=self.serials[0])[0].get_tokeninfo("refilltoken"))

        # Disable token. Refill should fail.
        enable_token(self.serials[0], False)
        with self.app.test_request_context('/validate/offlinerefill',
                                           method='POST',
                                           data={"serial": self.serials[0],
                                                 "pass": "pin520489",
                                                 "refilltoken": refilltoken_2},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            result = res.json.get("result")
            self.assertFalse(result.get("status"))
            error = result.get("error")
            self.assertEqual(905, error.get("code"))
            self.assertEqual("ERR905: The token is not valid.", error.get("message"))

            self._resend_and_check_unspecific_error(400)
            self.assertEqual(refilltoken_2, get_tokens(serial=self.serials[0])[0].get_tokeninfo("refilltoken"))

        # Enable token again
        enable_token(self.serials[0], True)

        # 2nd refill with 10th value
        with self.app.test_request_context('/validate/offlinerefill',
                                           method='POST',
                                           data={"serial": self.serials[0],
                                                 "pass": "pin520489",
                                                 "refilltoken": refilltoken_2},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            data = res.json
            result = res.json.get("result")
            self.assertTrue(result.get("status") is True, result)
            self.assertTrue(result.get("value") is True, result)
            auth_items = res.json.get("auth_items")
            offline = auth_items.get("offline")[0]
            # Check the number of OTP values
            self.assertEqual(len(offline.get("response")), 5)
            self.assertTrue("105" in offline.get("response"))
            self.assertTrue("106" in offline.get("response"))
            self.assertTrue("107" in offline.get("response"))
            self.assertTrue("108" in offline.get("response"))
            self.assertTrue("109" in offline.get("response"))
            refilltoken_3 = offline.get("refilltoken")
            self.assertEqual(len(refilltoken_3), 2 * REFILLTOKEN_LENGTH)
            # check the token counter
            tok = get_tokens(serial=self.serials[0])[0]
            self.assertEqual(tok.token.count, 110)
            # The refilltoken changes each time
            self.assertNotEqual(refilltoken_2, refilltoken_3)
            self.assertNotEqual(refilltoken_1, refilltoken_3)

        # A refill with a totally wrong OTP value fails
        token_obj = get_tokens(serial=self.serials[0])[0]
        old_counter = token_obj.token.count
        with self.app.test_request_context('/validate/offlinerefill',
                                           method='POST',
                                           data={"serial": self.serials[0],
                                                 "pass": "pin000000",
                                                 "refilltoken": refilltoken_3},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            data = res.json
            self.assertTrue(res.status_code == 400, res)
            self.assertEqual(data.get("result").get("error").get("message"),
                             "ERR401: You provided a wrong OTP value.")

            self._resend_and_check_unspecific_error(400)
            self.assertEqual(refilltoken_3, get_tokens(serial=self.serials[0])[0].get_tokeninfo("refilltoken"))

        # The failed refill should not modify the token counter!
        self.assertEqual(old_counter, token_obj.token.count)

        # A refill with a wrong serial number fails
        with self.app.test_request_context('/validate/offlinerefill',
                                           method='POST',
                                           data={"serial": 'ABCDEF123',
                                                 "pass": "pin000000",
                                                 "refilltoken": refilltoken_3},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            data = res.json
            self.assertTrue(res.status_code == 400, res)
            self.assertEqual(data.get("result").get("error").get("message"),
                             "ERR905: The token does not exist")

            self._resend_and_check_unspecific_error(400)
            self.assertEqual(refilltoken_3, get_tokens(serial=self.serials[0])[0].get_tokeninfo("refilltoken"))

        # Detach the token, refill should then fail
        detach_token(self.serials[0], "offline", "pippin")
        with self.app.test_request_context('/validate/offlinerefill',
                                           method='POST',
                                           data={"serial": self.serials[0],
                                                 "pass": "pin520489",
                                                 "refilltoken": refilltoken_3},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            data = res.json
            self.assertTrue(res.status_code == 400, res)
            self.assertEqual(data.get("result").get("error").get("message"),
                             "ERR905: Token is not an offline token or refill token is incorrect")

            self._resend_and_check_unspecific_error(400)
            self.assertEqual(refilltoken_3, get_tokens(serial=self.serials[0])[0].get_tokeninfo("refilltoken"))

    def test_02_empty_pass_hotp_refill(self):
        """An HOTP refill with empty ``pass`` cannot be split into PIN+OTP and is rejected."""
        serial = "SE_OFFLINE_EMPTY"
        init_token({"serial": serial, "otpkey": self.otpkey, "type": "hotp", "pin": "pin"},
                   user=User("cornelius", self.realm1))
        attach_token(serial, "offline", hostname="pippin",
                     resolver_name="testresolver", options={"count": 100})
        with self.app.test_request_context('/validate/check',
                                           method='POST',
                                           data={"serial": serial, "pass": "pin755224"},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            self.assertEqual(200, res.status_code, res)
            refilltoken = res.json["auth_items"]["offline"][0]["refilltoken"]
        with self.app.test_request_context('/validate/offlinerefill',
                                           method='POST',
                                           data={"serial": serial, "pass": "", "refilltoken": refilltoken},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            self.assertEqual(400, res.status_code, res)
            self.assertEqual("ERR905: Could not split password",
                             res.json["result"]["error"]["message"])
            self.assertEqual(refilltoken, get_tokens(serial=serial)[0].get_tokeninfo("refilltoken"))
        remove_token(serial)

    def test_03_refill_unsupported_token_type(self):
        """A TOTP token with an offline attachment hits neither branch in offlinerefill and
        returns the generic 'not an offline token' error. Pins down current (misleading) behavior.
        """
        serial = "SE_OFFLINE_TOTP"
        init_token({"serial": serial, "otpkey": self.otpkey, "type": "totp", "pin": "pin"},
                   user=User("cornelius", self.realm1))
        attach_token(serial, "offline", hostname="pippin",
                     resolver_name="testresolver", options={"count": 100})
        with self.app.test_request_context('/validate/offlinerefill',
                                           method='POST',
                                           data={"serial": serial, "pass": "pin123456",
                                                 "refilltoken": "a" * 2 * REFILLTOKEN_LENGTH},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            self.assertEqual(400, res.status_code, res)
            self.assertEqual("ERR905: Token is not an offline token or refill token is incorrect",
                             res.json["result"]["error"]["message"])
        remove_token(serial)

    def test_04a_signer_failure_preserves_online_hotp_consumption(self):
        """Failure to issue offline credentials must not make an accepted OTP reusable."""
        serial = "AMFA-SIGNER-FAILURE-ONLINE-COUNTER"
        init_token({"serial": serial, "otpkey": self.otpkey, "type": "hotp", "pin": "pin"},
                   user=User("cornelius", self.realm1))
        try:
            attach_token(serial, "offline", hostname="pippin",
                         resolver_name="testresolver", options={"count": 3, "rounds": 1})
            token = get_tokens(serial=serial)[0]
            first_count = token.token.count
            success, _reason, values = token.get_multi_otp(count=1)
            self.assertTrue(success)
            password = "pin" + next(iter(values["otp"].values()))
            with mock.patch("privacyidea.lib.amfa_offline_signatures.signed_auth_items",
                            side_effect=RuntimeError("test signer unavailable")):
                with self.app.test_request_context("/validate/check", method="POST",
                                                   data={"serial": serial, "pass": password},
                                                   environ_base={"REMOTE_ADDR": "192.168.0.2"}):
                    result = self.app.full_dispatch_request().json
                    self.assertTrue(result["result"]["value"], result)
                    self.assertNotIn("auth_items", result)
            db.session.expire_all()
            persisted = get_tokens(serial=serial)[0]
            self.assertEqual(persisted.token.count, first_count + 1,
                             "offline rollback must not undo successful online authentication")
            self.assertIsNone(persisted.get_tokeninfo("refilltoken"))
            with self.app.test_request_context("/validate/check", method="POST",
                                               data={"serial": serial, "pass": password},
                                               environ_base={"REMOTE_ADDR": "192.168.0.2"}):
                replay = self.app.full_dispatch_request().json
                self.assertFalse(replay["result"]["value"], "accepted HOTP cannot be replayed")
        finally:
            remove_token(serial)

    def test_04b_failed_signed_refill_does_not_consume_otp_or_rotate_refilltoken(self):
        """One failing signature must leave a valid refill retryable."""
        serial = "AMFA-SIGNER-FAIL-REFILL"
        init_token({"serial": serial, "otpkey": self.otpkey, "type": "hotp", "pin": "pin"},
                   user=User("cornelius", self.realm1))
        try:
            attach_token(serial, "offline", hostname="pippin",
                         resolver_name="testresolver", options={"count": 3, "rounds": 1})
            with self.app.test_request_context("/validate/check", method="POST",
                                               data={"serial": serial, "pass": "pin755224"},
                                               environ_base={"REMOTE_ADDR": "192.168.0.2"}):
                response = self.app.full_dispatch_request()
                self.assertTrue(response.json["result"]["value"], response.json)
                offline_entry = response.json["auth_items"]["offline"][0]
            refilltoken = offline_entry["refilltoken"]
            counter = min(int(k) for k in offline_entry["response"])
            token = get_tokens(serial=serial)[0]
            password = "pin" + token._calc_otp(counter)
            before = token.token.count
            payload = {"serial": serial, "pass": password, "refilltoken": refilltoken}
            # secrets.compare_digest only accepts ASCII str (or bytes): reject
            # malformed Unicode refill credentials as an ordinary bad token,
            # not an uncaught TypeError/HTTP 500.
            bad_payload = dict(payload, refilltoken=chr(0x017C) * len(refilltoken))
            with self.app.test_request_context("/validate/offlinerefill", method="POST",
                                               data=bad_payload,
                                               environ_base={"REMOTE_ADDR": "192.168.0.2"}):
                bad_response = self.app.full_dispatch_request()
                self.assertEqual(bad_response.status_code, 400, bad_response.json)
            with mock.patch("privacyidea.lib.amfa_offline_signatures.signed_auth_items",
                            side_effect=RuntimeError("test signer unavailable")):
                with self.app.test_request_context("/validate/offlinerefill", method="POST",
                                                   data=payload,
                                                   environ_base={"REMOTE_ADDR": "192.168.0.2"}):
                    try:
                        failed = self.app.full_dispatch_request()
                    except RuntimeError:
                        pass  # An unmasked signing failure may propagate to the caller.
                    else:
                        self.assertNotEqual(failed.status_code, 200)
            db.session.expire_all()
            after = get_tokens(serial=serial)[0]
            self.assertEqual(after.token.count, before, "signing failure consumed offline counters")
            self.assertEqual(after.get_tokeninfo("refilltoken"), refilltoken,
                             "signing failure rotated a credential the client never received")
            with self.app.test_request_context("/validate/offlinerefill", method="POST",
                                               data=payload,
                                               environ_base={"REMOTE_ADDR": "192.168.0.2"}):
                retry = self.app.full_dispatch_request()
                self.assertEqual(retry.status_code, 200, retry.json)
                self.assertTrue(retry.json["result"]["value"], retry.json)
        finally:
            remove_token(serial)

    def test_04_multiple_offline_attachments_share_one_refilltoken(self):
        """Dwa przylaczenia offline (HOTP) dostaja **ten sam** refilltoken (AMFA: #1156, plaster 04, Z4).

        Zachowanie podstawy: kazde udane `/validate/check` wolalo `generate_new_refilltoken`, wiec
        kazde przylaczenie w odpowiedzi nioslo **inny** token, a przezywal tylko ostatni — wczesniejsze
        byly po cichu uniewazniane (test przypinal to jako `current (buggy) behavior`). Klient, ktory
        zapisal pierwsza partie i nie zdazyl zapisac drugiej, trzymal martwy token i dostawal `ERR905`
        bez zadnego sygnalu.

        W naszej linii refilltoken jest **stabilny miedzy logowaniami** i odnawia go dopiero udany
        refill, wiec oba przylaczenia widza ten sam token, zapisany w tokeninfo, i refill nim przechodzi.
        """
        serial = "SE_OFFLINE_MULTI"
        init_token({"serial": serial, "otpkey": self.otpkey, "type": "hotp", "pin": "pin"},
                   user=User("cornelius", self.realm1))
        attach_token(serial, "offline", hostname="pippin",
                     resolver_name="testresolver", options={"count": 100})
        attach_token(serial, "offline", hostname="borodin",
                     resolver_name="testresolver", options={"count": 100})
        with self.app.test_request_context('/validate/check',
                                           method='POST',
                                           data={"serial": serial, "pass": "pin755224"},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            self.assertEqual(200, res.status_code, res)
            offline_entries = res.json["auth_items"]["offline"]
        self.assertEqual(2, len(offline_entries))
        tokeny = {entry["refilltoken"] for entry in offline_entries}
        self.assertEqual(1, len(tokeny), "przylaczenia dostaly rozne refilltokeny — wracamy do rotacji przy logowaniu")
        refilltoken = tokeny.pop()
        self.assertEqual(refilltoken, get_tokens(serial=serial)[0].get_tokeninfo("refilltoken"))
        # Test the actual refill contract with an OTP from the second
        # offline window. A hard-coded OTP could succeed or fail depending on
        # counter state, so it cannot prove the refilltoken is still usable.
        token = get_tokens(serial=serial)[0]
        refill_counter = min(int(counter) for counter in offline_entries[-1]["response"])
        correct_otp = token._calc_otp(refill_counter)
        with self.app.test_request_context('/validate/offlinerefill',
                                           method='POST',
                                           data={"serial": serial, "pass": "pin" + correct_otp,
                                                 "refilltoken": refilltoken},
                                           environ_base={'REMOTE_ADDR': '192.168.0.2'}):
            res = self.app.full_dispatch_request()
            self.assertEqual(200, res.status_code, res.json)
            self.assertTrue(res.json["result"]["value"], res.json)
            replacement = res.json["auth_items"]["offline"][0]["refilltoken"]
        self.assertNotEqual(refilltoken, replacement, "successful refill must rotate the secret")
        self.assertEqual(replacement, get_tokens(serial=serial)[0].get_tokeninfo("refilltoken"))
        remove_token(serial)


    def test_05_refill_without_entitlement_is_a_defined_refusal(self):
        """A refill is a NEW offline issuance, so it re-checks the published allowlist.

        With the signer enabled and the signed deployment-flags document withdrawn or
        not yet published, the station has to receive a defined refusal (not an HTTP
        500), the token must stay untouched, and online authentication must keep
        working (#1605).
        """
        serial = "AMFA-REFILL-UNENTITLED"
        flags_directory = tempfile.mkdtemp()
        try:
            init_token({"serial": serial, "otpkey": self.otpkey, "type": "hotp", "pin": "pin"},
                       user=User("cornelius", self.realm1))
            attach_token(serial, "offline", hostname="pippin",
                         resolver_name="testresolver", options={"count": 3, "rounds": 1})
            environment = {
                "AMFA_OFFLINE_ED25519_ENABLED": "1",
                "AMFA_OFFLINE_ED25519_PRIVATE_KEY_FILE": "/test-only/ed25519.pem",
                "AMFA_OFFLINE_ED25519_KEY_ID": "test-only",
                **_signed_offline_flags_env(flags_directory, [HOTP_OFFLINE_GROUP]),
            }
            # The allowlist is published and the owner is inside it: the online
            # authentication hands out a signed HOTP batch with a refilltoken.
            with mock.patch.dict(os.environ, environment), mock.patch(
                    "privacyidea.lib.amfa_offline_signatures._load_key",
                    return_value=Ed25519PrivateKey.generate()), mock.patch(
                    "privacyidea.lib.amfa_offline_entitlement.get_resolver_object",
                    return_value=_directory_with_groups([HOTP_OFFLINE_GROUP])):
                token = get_tokens(serial=serial)[0]
                success, _reason, values = token.get_multi_otp(count=1)
                self.assertTrue(success)
                password = "pin" + next(iter(values["otp"].values()))
                with self.app.test_request_context("/validate/check", method="POST",
                                                   data={"serial": serial, "pass": password},
                                                   environ_base={"REMOTE_ADDR": "192.168.0.2"}):
                    online = self.app.full_dispatch_request()
                self.assertTrue(online.json["result"]["value"], online.json)
                envelope = online.json["auth_items"]["offline"][0]
                signed_item = json.loads(base64.b64decode(envelope["signed_payload"], validate=True))
                self.assertEqual("hotp", signed_item["offline_grant"])
                self.assertEqual(2, signed_item["format_version"])
                refilltoken = signed_item["refilltoken"]
                db.session.expire_all()
                before = get_tokens(serial=serial)[0]
                counter_before = before.token.count
                self.assertEqual(refilltoken, before.get_tokeninfo("refilltoken"))

            # The published document is withdrawn (or never published yet) while the
            # signer stays on: the stored refilltoken now meets the gate.
            withdrawn = dict(environment, **{POLICY_FILE: "",
                                            PUBLIC_KEY_FILE: "",
                                            EXPECTED_KID: ""})
            with mock.patch.dict(os.environ, withdrawn), mock.patch(
                    "privacyidea.lib.amfa_offline_signatures._load_key",
                    return_value=Ed25519PrivateKey.generate()):
                with self.app.test_request_context("/validate/offlinerefill", method="POST",
                                                   data={"serial": serial, "pass": "",
                                                         "refilltoken": refilltoken},
                                                   environ_base={"REMOTE_ADDR": "192.168.0.2"}):
                    refused = self.app.full_dispatch_request()
                self.assertEqual(400, refused.status_code, refused.json)
                self.assertFalse(refused.json["result"]["status"], refused.json)
                error = refused.json["result"]["error"]
                self.assertEqual(905, error["code"], error)
                self.assertEqual("ERR905: Offline issuance is not allowed for this account",
                                 error["message"])
                # A defined refusal names the reason; the directory-side detail stays in the log.
                self.assertNotIn("provisioned", error["message"])
                self.assertNotIn("auth_items", refused.json)
                # A refused refill must not reserve counters or rotate the credential.
                db.session.expire_all()
                after = get_tokens(serial=serial)[0]
                self.assertEqual(counter_before, after.token.count,
                                 "refused refill consumed offline counters")
                self.assertEqual(refilltoken, after.get_tokeninfo("refilltoken"),
                                 "refused refill rotated the refill credential")
                # Online authentication is unaffected by the missing allowlist.
                success, _reason, values = after.get_multi_otp(count=1)
                self.assertTrue(success)
                password = "pin" + next(iter(values["otp"].values()))
                with self.app.test_request_context("/validate/check", method="POST",
                                                   data={"serial": serial, "pass": password},
                                                   environ_base={"REMOTE_ADDR": "192.168.0.2"}):
                    online_after = self.app.full_dispatch_request()
                self.assertTrue(online_after.json["result"]["value"], online_after.json)
                self.assertNotIn("auth_items", online_after.json)
        finally:
            remove_token(serial)
            shutil.rmtree(flags_directory, ignore_errors=True)


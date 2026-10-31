#  2015-04-08 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#             Add options ROUNDS to avoid timeouts during OTP hash calculation
#  2015-04-03 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#             Use pbkdf2 for OTP hashing
#  2015-03-13 Cornelius Kölbel, <cornelius@privacyidea.org>
#             initial writeup
#
# License:  AGPLv3
#  contact:  http://www.privacyidea.org
#
# This code is free software; you can redistribute it and/or
# modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
# License as published by the Free Software Foundation; either
# version 3 of the License, or any later version.
#
# This code is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU AFFERO GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import logging

from passlib.hash import pbkdf2_sha512
from sqlalchemy import select

from privacyidea.models import Token, TokenInfo, db

from privacyidea.lib.applications import MachineApplicationBase
from privacyidea.lib.config import get_prepend_pin
from privacyidea.lib.crypto import geturandom
from privacyidea.lib.error import ValidateError, ParameterError
from privacyidea.lib.fido2.token_info import FIDO2TokenInfo
from privacyidea.lib.policy import TYPE
from privacyidea.lib.token import get_one_token
from privacyidea.lib.tokens.HMAC import HmacOtp
from privacyidea.lib.utils import get_computer_name_from_user_agent

log = logging.getLogger(__name__)
ROUNDS = 6549
REFILLTOKEN_LENGTH = 40


class MachineApplication(MachineApplicationBase):
    """
    This is the application for Offline authentication with PAM or
    the privacyIDEA credential provider.

    The machine application returns a list of salted OTP hashes to be used with
    offline authentication. The token then is disabled, so that it can not
    be used for online authentication anymore, to avoid reusing a fished OTP
    value.

    The server stores the information, which OTP values were issued.

    options:
      * user: a username.
      * count: is the number of OTP values returned

    """
    application_name = "offline"

    @staticmethod
    def generate_new_refilltoken(token, user_agent=None, *, commit_db_session=True):
        """
        Generate new refill token and store it in the tokeninfo of the token.
        :param token: token in question
        :param user_agent: name of the machine, taken from the user-agent header
        :return: a string
        """
        log.debug(f"Generating refilltoken for {token.get_serial()} with user agent {user_agent}")

        # If the token is a FIDO2 token, we need to store the machine name with the refill token, because
        # the token can be on multiple machines, which need to be managed separately
        # TODO improve where the information about offline capabilities is stored
        if token.type.lower() in ["webauthn", "passkey"]:
            computer_name = get_computer_name_from_user_agent(user_agent)
            if not computer_name:
                log.warning(f"No computer name found in user agent {user_agent}. Unable to generate refill token.")
                raise ParameterError("Unable to generate refill token without computer name.")
            key = "refilltoken_" + computer_name
        else:
            key = "refilltoken"

        new_refilltoken = geturandom(REFILLTOKEN_LENGTH, hex=True)
        token.write_tokeninfo(key, new_refilltoken, commit_db_session=commit_db_session)
        return new_refilltoken

    @staticmethod
    def existing_refilltoken(token, user_agent=None):
        """Zapisany refilltoken dla tego tokenu (a dla FIDO2 — dla tej maszyny) albo None."""
        if token.type.lower() in ["webauthn", "passkey"]:
            # Bez `user_agent` nie wiadomo, ktorej maszyny dotyczy zapisany token — a pytanie
            # `get_computer_name_from_user_agent(None)` siega `request` i wymaga kontekstu aplikacji.
            # Wtedy nie ma czego odnawiac: refilltoken powstaje jak dotad (pierwsze logowanie).
            if not user_agent:
                return None
            computer_name = get_computer_name_from_user_agent(user_agent)
            if not computer_name:
                return None
            key = "refilltoken_" + computer_name
        else:
            key = "refilltoken"
        return token.get_tokeninfo(key)

    @staticmethod
    def existing_or_new_refilltoken(token, user_agent=None):
        """Stabilny refilltoken miedzy logowaniami (audyt 26.10.2026, plaster 04, Z4).

        Kazde udane `/validate/check` wolalo `generate_new_refilltoken`, co **nadpisywalo** zapisany
        refilltoken. Klient, ktory zapisal pierwsza partie i nie zapisal drugiej (dwa kafle tego samego
        konta, dwa rownolegle kroki), trzymal token, ktorym nie mogl dociagnac zapasu (`ERR905`) —
        i nie mial zadnego sygnalu, ze jest martwy.

        Teraz refilltoken powstaje **raz** (przy pierwszym logowaniu bez zapisanego tokenu), a odnawia
        go dopiero udany refill w `offlinerefill`. Odpowiedzi logowania sa wiec wzgledem niego
        idempotentne, a powtorzone zadanie nie unieważnia tego, co klient juz zapisal.
        """
        # Two /validate/check requests for the same new token may both reach
        # here before either writes tokeninfo. A read-then-insert alone either
        # issues an obsolete refilltoken or hits UNIQUE(token_id, Key).
        # Lock the parent row (it already exists), then use a locking read of
        # TokenInfo so even MariaDB REPEATABLE READ does not reuse an old
        # snapshot. The winning insertion commits before the waiting request
        # rechecks the database. Do not serialize only within one process.
        if not isinstance(token.token, Token):
            # The standalone offline serializer contract also accepts token
            # test doubles (which have no ORM identity or database session).
            # Real persisted token models always take the SQL locking path.
            istniejacy = MachineApplication.existing_refilltoken(token, user_agent)
            return istniejacy or MachineApplication.generate_new_refilltoken(token, user_agent)
        token_id = token.token.id
        if token_id is None:
            raise ParameterError("Offline refill requires a persisted token.")
        db.session.execute(
            select(Token.id).where(Token.id == token_id).with_for_update()
        ).scalar_one()
        if token.type.lower() in ("webauthn", "passkey"):
            computer_name = get_computer_name_from_user_agent(user_agent)
            if not computer_name:
                raise ParameterError("Unable to generate refill token without computer name.")
            key = "refilltoken_" + computer_name
        else:
            key = "refilltoken"
        istniejacy = db.session.execute(
            select(TokenInfo.Value)
            .where(TokenInfo.token_id == token_id, TokenInfo.Key == key)
            .with_for_update()
        ).scalar_one_or_none()
        if istniejacy:
            # get_tokeninfo() uses a lazy relationship that may have been
            # populated before the lock; invalidate it before later reads.
            db.session.expire(token.token, ["info_list"])
            return istniejacy
        return MachineApplication.generate_new_refilltoken(token, user_agent)

    @staticmethod
    def get_offline_otps(token, otppin, amount, rounds=ROUNDS, *, atomic=False):
        """
        Retrieve the desired number of passwords (= PIN + OTP), hash them
        and return them in a dictionary. Increase the token counter.

        :param token: token in question
        :param otppin: The OTP PIN to prepend in the passwords. The PIN is not validated!
        :param amount: Number of OTP values (non-negative!)
        :param rounds: Number of PBKDF2 rounds
        :return: dictionary
        """
        if not isinstance(amount, int) or not 0 <= amount <= 1024:
            raise ParameterError(f"Invalid offline OTP amount: {amount!r}")
        if not isinstance(rounds, int) or not 1 <= rounds <= 100000:
            raise ParameterError(f"Invalid offline OTP PBKDF2 rounds: {rounds!r}")
        (res, err, otp_dict) = token.get_multi_otp(count=amount, counter_index=True)
        otps = otp_dict.get("otp")
        prepend_pin = get_prepend_pin()
        for key, otp in otps.items():
            # Return the hash of OTP PIN and OTP values
            otp_with_pin = otppin + otp if prepend_pin else otp + otppin
            otps[key] = pbkdf2_sha512.using(rounds=rounds, salt_size=10).hash(otp_with_pin)
        # We do not disable the token, so if all offline OTP values
        # are used, the token can be used to authenticate online again.
        # token_obj.enable(False)
        # increase the counter by the consumed values and
        # also store it in tokeninfo.
        if atomic:
            token.inc_otp_counter(increment=amount, commit_db_session=False)
        else:
            token.inc_otp_counter(increment=amount)

        return otps

    @staticmethod
    def get_refill(token, password, options=None, *, atomic=False):
        """
        Returns new authentication OTPs to refill the client

        To do so we also verify the password, which may consist of PIN + OTP.

        :param token: Token object
        :param password: PIN + OTP
        :param options: dict that might contain "count" and "rounds"
        :return: a dictionary of auth items
        """
        options = options or {}
        otps = {}
        if token.type.lower() == "hotp":
            count = int(options.get("count", 100))
            rounds = int(options.get("rounds", ROUNDS))
            if not 1 <= count <= 1024:
                raise ParameterError(f"Invalid offline refill window: {count!r}")
            if not 1 <= rounds <= 100000:
                raise ParameterError(f"Invalid offline refill PBKDF2 rounds: {rounds!r}")
            _r, otppin, otpval = token.split_pin_pass(password)
            if not _r:
                raise ParameterError("Could not split password")
            current_token_counter = token.token.count
            first_offline_counter = current_token_counter - count
            if first_offline_counter < 0:
                first_offline_counter = 0
            if atomic:
                # offlinerefill holds SELECT ... FOR UPDATE until the *single*
                # final commit. HotpTokenClass.check_otp calls set_otp_count(),
                # which commits and silently releases that lock. Verify the
                # same HOTP window without mutating the counter instead.
                verifier = HmacOtp(
                    token.token.get_otpkey(), first_offline_counter, int(token.token.otplen),
                    token.get_hashlib(token.hashlib),
                )
                matching_count = verifier.checkOtp(otpval, count)
            else:
                # Legacy callers keep their prior counter and autosync logic.
                matching_count = token.check_otp(otpval, first_offline_counter, count)
                token.set_otp_count(current_token_counter)
            if matching_count < 0:
                raise ValidateError("You provided a wrong OTP value.")
            # We have to add 1 here: Assume *first_offline_counter* is the counter value of the first offline OTP
            # we sent to the client. Assume the client then requests a refill with that exact OTP value.
            # Then, we need to respond with a refill of one OTP value, as the client has consumed one OTP value.
            counter_diff = matching_count - first_offline_counter + 1
            otps = MachineApplication.get_offline_otps(token, otppin, counter_diff, rounds, atomic=atomic)
            token.write_tokeninfo(
                key="offline_counter", value=count, commit_db_session=not atomic,
            )
        elif token.type.lower() in ["webauthn", "passkey"]:
            pass
        return otps

    @staticmethod
    def _add_user_verification(response, user_verification):
        """
        Add the resolved FIDO2 user verification requirement to the ``response`` part of an offline auth item.

        The field is only added if a value was provided. The client entry type detection keys on the fields
        ``credentialId``, ``rpId`` and ``pubKey`` only, and clients that do not know the field ignore it, so
        adding it keeps the offline data contract backwards compatible for existing clients.

        :param response: the ``response`` dictionary of the offline auth item
        :type response: dict
        :param user_verification: the user verification requirement or None
        :type user_verification: basestring
        """
        if user_verification:
            response["userVerification"] = user_verification

    @staticmethod
    def _reserve_initial_hotp_bundle(token, otppin, count, rounds, user_agent=None, *, commit_db_session=True):
        """Reserve the complete offline HOTP batch under one token-row lock.

        Two successful online validations can overlap after HOTP checkUserPass
        has returned. The first login must not hand out a stale/overlapping
        offline bag while another node allocates from the same counter.
        Re-read the counter *after* SELECT FOR UPDATE, and do not commit
        TokenInfo or counter changes until both are staged.
        """
        token_id = token.token.id
        if token_id is None:
            raise ParameterError("Offline HOTP token has no database identity.")
        db.session.execute(
            select(Token.id).where(Token.id == token_id).with_for_update()
        ).scalar_one()
        db.session.refresh(token.token)
        db.session.expire(token.token, ["info_list"])
        messages = []
        if not token.check_all(messages):
            raise ValidateError("Token is no longer valid for offline issuance.")
        refilltoken = token.get_tokeninfo("refilltoken")
        if not refilltoken:
            refilltoken = MachineApplication.generate_new_refilltoken(
                token, user_agent, commit_db_session=False,
            )
        otps = MachineApplication.get_offline_otps(
            token, otppin, count, rounds, atomic=True,
        )
        if commit_db_session:
            db.session.commit()
        return refilltoken, otps

    @staticmethod
    def get_authentication_item(token_type, serial, challenge=None, options=None, filter_param=None, user_agent=None,
                                user_verification=None, commit_db_session=True):
        """
        :param token_type: the type of the token. At the moment
                           we support HOTP and WebAuthn/Passkey tokens.
        :param serial:     the serial number of the token.
        :param challenge:  this can contain the password (otp pin + otp value)
                           so that we can put the OTP PIN into the hashed response.
        :type challenge: basestring
        :param options: options
        :param filter_param: parameters
        :param user_agent: The user agent of the request
        :param user_verification: The FIDO2 user verification requirement ("required", "preferred" or
                           "discouraged") resolved from the policy by the caller, which has the policy
                           context. It is handed to the client together with the offline data of WebAuthn
                           and Passkey tokens, so that the machine enforces the same user verification
                           requirement offline as the server does online. This function is static and has
                           no access to ``g``, so the value is passed in rather than resolved here. It is
                           not used for HOTP tokens.
        :return auth_item: A list of hashed OTP values or pubKey, rpId and credentialId for WebAuthn token
        """
        ret = {}
        options = options or {}
        password = challenge
        token_type = token_type.lower()
        # TODO improve where the information about offline capabilities is stored
        if token_type in ["hotp", "webauthn", "passkey"]:
            ret["response"] = {}
            token = get_one_token(serial=serial)
            user = token.user
            if user:
                user_info = user.get_specific_info(["username", FIDO2TokenInfo.USER_ID])
                if "username" in user_info:
                    ret["user"] = ret["username"] = user_info.get("username")
                if token_type in ["webauthn", "passkey"] and FIDO2TokenInfo.USER_ID in user_info:
                    ret["response"].update({"userId": user_info[FIDO2TokenInfo.USER_ID]})

            # Refilltoken stabilny miedzy logowaniami (audyt 26.10.2026, plaster 04, Z4): rotacja przy
            # kazdym udanym `/validate/check` uniewazniala token, ktory klient juz zapisal. Odnawia go
            # dopiero udany refill w `offlinerefill`.
            if token_type != "hotp" or not isinstance(getattr(token, "token", None), Token):
                # WebAuthn/Passkey and standalone serializers retain the
                # existing contract. Persisted HOTP reserves its counter and
                # refilltoken *together* in the branch below.
                ret["refilltoken"] = MachineApplication.existing_or_new_refilltoken(token, user_agent)

            # Gather offline data depending on the token type
            if token_type == "webauthn":
                # return the pubKey, rpId and the credentialId (contained in the otpkey) to allow the machine to
                # verify the WebAuthn assertions signed with the token
                ret["response"].update({
                    "pubKey": token.get_tokeninfo("pubKey"),
                    "credentialId": token.decrypt_otpkey(),
                    "rpId": token.get_tokeninfo("relying_party_id")
                })
                MachineApplication._add_user_verification(ret["response"], user_verification)
            elif token_type == "hotp":
                if password:
                    success, otppin, _ = token.split_pin_pass(password)
                    if not success:
                        raise ParameterError("Could not split password")
                else:
                    otppin = ""

                count = int(options.get("count", 100))
                rounds = int(options.get("rounds", ROUNDS))
                if isinstance(getattr(token, "token", None), Token):
                    ret["refilltoken"], ret["response"] = MachineApplication._reserve_initial_hotp_bundle(
                        token, otppin, count, rounds, user_agent,
                        commit_db_session=commit_db_session,
                    )
                else:
                    ret["response"] = MachineApplication.get_offline_otps(token, otppin, count, rounds)
            elif token_type == "passkey":
                ret["response"].update({
                    "pubKey": token.get_tokeninfo("public_key"),
                    "rpId": token.get_tokeninfo("relying_party_id"),
                    "credentialId": token.token.get_otpkey().getKey().decode("utf-8")
                })
                MachineApplication._add_user_verification(ret["response"], user_verification)
        else:
            log.info(f"Token {serial} of type {token_type} is not supported by OFFLINE application module")

        return ret

    @staticmethod
    def get_options():
        """
        Returns a dictionary with a list of required and optional options
        """
        options = {
            "hotp": {
                "count": {"type": TYPE.STRING},
                "rounds": {"type": TYPE.STRING}
            },
            "webauthn": {},
            "passkey": {}
        }
        return options

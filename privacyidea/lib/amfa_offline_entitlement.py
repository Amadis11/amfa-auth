"""Authorize offline issuance online using the native AUTH policy engine.

No deployment-flags document, group cache or directory lookup on a workstation.
Only a fresh resolved token owner and an explicit allow policy can receive a
signed offline batch. Online authentication remains independent.
"""
from __future__ import annotations

import copy
import logging

from privacyidea.lib.resolver import get_resolver_object

LOG = logging.getLogger(__name__)


class OfflineEntitlementError(ValueError):
    """A requested offline issuance cannot be authorised."""


def _policy_allows(user, grant: str, info: dict, token) -> bool:
    """Use the existing AUTH policy engine, including userinfo conditions."""
    from flask import g, has_request_context
    from privacyidea.lib.policy import PolicyClass, SCOPE
    from privacyidea.lib.config import get_privacyidea_node
    from privacyidea.lib.policies.actions import PolicyAction

    action = {
        "hotp": PolicyAction.AMFA_OFFLINE_HOTP,
        "fido2": PolicyAction.AMFA_OFFLINE_FIDO2,
        "key_only": PolicyAction.AMFA_KEY_ONLY_LOGIN,
    }[grant]
    # No request context must not accidentally satisfy a client-scoped rule.
    if not has_request_context() or not g.get("client_ip"):
        return False
    # The owner is resolved by token UID. Evaluate userinfo against the same
    # fresh resolver read, not cached membership or editable custom attributes.
    current = copy.copy(user)
    if isinstance(info.get("username"), str) and info["username"]:
        current.login = current.used_login = info["username"]
    current.get_specific_info = lambda keys=None: {
        key: value for key, value in info.items() if keys is None or key in keys}
    engine = PolicyClass()
    policies = engine.match_policies(
        scope=SCOPE.AUTH, action=action, active=True, user_object=current,
        client=g.client_ip, pinode=get_privacyidea_node(),
        serial=token.get_serial(), user_agent=g.get("user_agent") or "")
    values = engine.extract_action_values(policies, action, unique=True)
    return set(values) == {"allow"}


def offline_grant_for_token(token) -> str:
    """Authorize issuance from the live owner policy."""
    kind = str(getattr(token, "type", "")).lower()
    grant = "hotp" if kind == "hotp" else ("fido2" if kind in ("webauthn", "passkey") else "")
    if not grant:
        raise OfflineEntitlementError("token kind cannot be used offline")
    require_owner_policy(token, grant)
    LOG.debug("AMFA offline %s issuance: owner policy allowed", grant)
    return grant


def require_owner_policy(token, grant: str, *, expected_sid: str | None = None) -> None:
    """Evaluate an explicit allow for the actual token owner, never the supplied login."""
    try:
        user = token.user
        if user is None or not user.resolver or not user.uid or not user.realm or not user.login:
            raise OfflineEntitlementError("token has no resolved owner")
        if expected_sid is not None and str(user.uid).casefold() != expected_sid.casefold():
            raise OfflineEntitlementError("token owner SID mismatch")
        resolver = get_resolver_object(user.resolver)
        if resolver is None:
            raise OfflineEntitlementError("offline issuance resolver is unavailable")
        info = resolver.get_user_info(user.uid)
        if not isinstance(info, dict) or not info:
            raise OfflineEntitlementError("offline issuance owner could not be read")
        if not _policy_allows(user, grant, info, token):
            raise OfflineEntitlementError("offline issuance denied by owner policy")
    except OfflineEntitlementError:
        raise
    except Exception as error:
        raise OfflineEntitlementError("offline issuance policy or resolver failed") from error


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


def offline_claims_for_token(token) -> dict:
    """Authorize issuance and return the signed subject of the token owner.

    The AD subject (SID, realm, canonical account name) is bound into the signed
    batch, so it must come from a FRESH directory read of the token owner - never
    from a cached membership verdict and never from a workstation-supplied name.
    """
    kind = str(getattr(token, "type", "")).lower()
    grant = "hotp" if kind == "hotp" else ("fido2" if kind in ("webauthn", "passkey") else "")
    if not grant:
        raise OfflineEntitlementError("token kind cannot be used offline")
    info = require_owner_policy(token, grant)
    user = token.user
    resolver = get_resolver_object(user.resolver)
    from privacyidea.lib.amfa_offline_subject import offline_subject
    try:
        subject = offline_subject(user, resolver)
    except ValueError as error:
        raise OfflineEntitlementError(str(error)) from error
    username = info.get("username") if isinstance(info, dict) else None
    if not isinstance(username, str) or not username:
        raise OfflineEntitlementError("directory did not return the account name")
    LOG.debug("AMFA offline %s issuance: owner policy allowed", grant)
    return dict(subject, offline_grant=grant, username=username)


def offline_grant_for_token(token) -> str:
    """Authorize issuance from the live owner policy."""
    return offline_claims_for_token(token)["offline_grant"]


def require_owner_policy(token, grant: str, *, expected_sid: str | None = None) -> dict:
    """Evaluate an explicit allow for the actual token owner, never the supplied login.

    Returns the fresh directory record used for the verdict, so callers that also
    need the canonical account name do not read the directory twice.
    """
    try:
        user = token.user
        if user is None or not user.resolver or not user.uid or not user.realm or not user.login:
            raise OfflineEntitlementError("token has no resolved owner")
        if expected_sid is not None and str(user.uid).casefold() != expected_sid.casefold():
            raise OfflineEntitlementError("token owner SID mismatch")
        resolver = get_resolver_object(user.resolver)
        if resolver is None:
            raise OfflineEntitlementError("offline issuance resolver is unavailable")
        # LDAP get_user_info is cached; a revoked group must not mint a new
        # grant from an earlier directory observation. SQL and passwd resolvers
        # implement direct get_user_info and remain supported without AD.
        fresh_lookup = getattr(resolver, "get_user_info_uncached", None)
        info = fresh_lookup(user.uid) if callable(fresh_lookup) else resolver.get_user_info(user.uid)
        if not isinstance(info, dict) or not info:
            raise OfflineEntitlementError("offline issuance owner could not be read")
        if not _policy_allows(user, grant, info, token):
            raise OfflineEntitlementError("offline issuance denied by owner policy")
        return info
    except OfflineEntitlementError:
        raise
    except Exception as error:
        raise OfflineEntitlementError("offline issuance policy or resolver failed") from error

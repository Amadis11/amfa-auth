"""Authorise offline batch ISSUANCE online, never on Windows offline logon.

The server reads the *same signed deployment-flags envelope* published to
stations. The signing key is separately pinned on this host. No flag file,
unknown issuer, expired document, missing LDAP group mapping or failing DC:
no offline batch. Online authentication remains unaffected.

This module deliberately does not perform any workstation-side group lookup.
"""
from __future__ import annotations

import base64
import datetime
import json
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from privacyidea.lib.resolver import get_resolver_object

LOG = logging.getLogger(__name__)

POLICY_FILE = "AMFA_OFFLINE_DEPLOYMENT_FLAGS_FILE"
PUBLIC_KEY_FILE = "AMFA_OFFLINE_DEPLOYMENT_FLAGS_PUBLIC_KEY_FILE"
EXPECTED_KID = "AMFA_OFFLINE_DEPLOYMENT_FLAGS_KEY_ID"


class OfflineEntitlementError(ValueError):
    """A requested offline issuance cannot be authorised."""


def _load_authorised_groups(path: str) -> list[str]:
    policy_path = os.environ.get(POLICY_FILE, "")
    public_path = os.environ.get(PUBLIC_KEY_FILE, "")
    expected_kid = os.environ.get(EXPECTED_KID, "")
    if not policy_path or not public_path or not expected_kid:
        raise OfflineEntitlementError("offline issuance policy is not provisioned")
    if not os.path.isabs(policy_path) or not os.path.isabs(public_path):
        raise OfflineEntitlementError("offline issuance policy paths must be absolute")
    raw = Path(policy_path).read_bytes()
    if len(raw) > 65536:
        raise OfflineEntitlementError("offline issuance policy exceeds size limit")
    envelope = json.loads(raw)
    document = envelope["document"]
    signature = envelope["signature"]
    if (not isinstance(document, dict) or not isinstance(signature, dict)
            or signature.get("algorithm") != "rsa-sha256"
            or signature.get("key_id") != expected_kid
            or "cert_base64" in signature):
        raise OfflineEntitlementError("unsupported offline issuance policy signature")
    if (document.get("format_version") != 1
            or document.get("type") != "deployment-flags"
            or not isinstance(document.get("valid_until"), str)
            or datetime.date.fromisoformat(document["valid_until"]) < datetime.date.today()):
        raise OfflineEntitlementError("invalid or expired offline issuance policy")
    # Same UTF-8 canonical representation as the Gateway deployment-flags signer.
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    public_pem = Path(public_path).read_bytes()
    if len(public_pem) > 8192:
        raise OfflineEntitlementError("oversized public key")
    public_key = serialization.load_pem_public_key(public_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise OfflineEntitlementError("offline deployment key must be RSA")
    public_key.verify(base64.b64decode(signature["value"], validate=True),
                      canonical, padding.PKCS1v15(), hashes.SHA256())
    flags = document.get("flags")
    if not isinstance(flags, dict):
        raise OfflineEntitlementError("missing deployment flag object")
    group_key = "offline_hotp_groups" if path == "hotp" else "offline_fido2_groups"
    groups = flags.get(group_key)
    if (not isinstance(groups, list) or len(groups) > 32 or
            any(not isinstance(x, str) or not x or len(x) > 255 for x in groups)):
        raise OfflineEntitlementError("malformed offline group allowlist")
    if path == "hotp" and flags.get("offline_hotp_allowed") is not True:
        return []
    return groups


def _same_group(member: str, permitted: str) -> bool:
    """Qualified allowlist requires qualified LDAP data (never guess a domain)."""
    if not isinstance(member, str):
        return False
    if "\\" in permitted:
        return member.casefold() == permitted.casefold()
    return member.rsplit("\\", 1)[-1].casefold() == permitted.casefold()


def offline_grant_for_token(token) -> str:
    """Return signed grant kind only when the token owner is in an allowed AD group.

    Always fetch group membership from the resolver in the ONLINE issuance call.
    A cache or a workstation-provided name must not grant offline access.
    """
    kind = str(getattr(token, "type", "")).lower()
    grant = "hotp" if kind == "hotp" else ("fido2" if kind in ("webauthn", "passkey") else "")
    if not grant:
        raise OfflineEntitlementError("token kind cannot be used offline")
    allowed = _load_authorised_groups(grant)
    if not allowed:
        raise OfflineEntitlementError("offline access not enabled for token owner")
    user = token.user
    if user is None or not user.resolver or not user.uid:
        raise OfflineEntitlementError("token has no resolved directory owner")
    resolver = get_resolver_object(user.resolver)
    if resolver is None:
        raise OfflineEntitlementError("offline issuance directory resolver is unavailable")
    group_key = getattr(resolver, "group_attribute_mapping_key", None) or "groups"
    if group_key not in resolver.get_available_info_keys():
        raise OfflineEntitlementError("resolver cannot return AD group membership")
    # A direct lookup rather than cached_user_info prevents a stale user-cache
    # membership verdict from authorising a new offline batch.
    # LDAP recursive group filters may interpolate other mapped attributes
    # (e.g. {username}); requesting only [groups] strips those fields before
    # building the group filter and silently yields empty membership.
    info = resolver.get_user_info(user.uid)
    members = info.get(group_key) if isinstance(info, dict) else None
    if not isinstance(members, (list, tuple)):
        raise OfflineEntitlementError("directory did not return a complete group list")
    if not all(isinstance(x, str) for x in members):
        raise OfflineEntitlementError("malformed directory group membership")
    if not any(_same_group(member, allowed_group)
               for member in members for allowed_group in allowed):
        raise OfflineEntitlementError("token owner is outside offline allowlist")
    LOG.debug("AMFA offline %s issuance: AD entitlement checked for token owner", grant)
    return grant

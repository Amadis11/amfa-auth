"""Authorise offline batch ISSUANCE online, never on Windows offline logon.

The server reads the *same signed deployment-flags envelope* published to
stations and accepts exactly the two signature forms the workstations accept:
the issuer key pinned on this host, or the customer CA form (#1550) whose
envelope carries the signing certificate. No flag file, unknown issuer, expired
document, stale certificate, missing LDAP group mapping or failing DC: no
offline batch. Online authentication remains unaffected.

This module deliberately does not perform any workstation-side group lookup.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import logging
import os
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from privacyidea.lib.resolver import get_resolver_object

LOG = logging.getLogger(__name__)

POLICY_FILE = "AMFA_OFFLINE_DEPLOYMENT_FLAGS_FILE"
PUBLIC_KEY_FILE = "AMFA_OFFLINE_DEPLOYMENT_FLAGS_PUBLIC_KEY_FILE"
EXPECTED_KID = "AMFA_OFFLINE_DEPLOYMENT_FLAGS_KEY_ID"
CA_FILE = "AMFA_OFFLINE_DEPLOYMENT_FLAGS_CA_FILE"
CERT_KID_PREFIX = "cert-sha256:"
MAX_POLICY_BYTES = 65536
MAX_KEY_BYTES = 8192
MAX_CERTIFICATE_BYTES = 16384


class OfflineEntitlementError(ValueError):
    """A requested offline issuance cannot be authorised."""


def _read_limited(path: str, limit: int, reason: str) -> bytes:
    """Read a policy artefact, turning every failure into a defined refusal."""
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise OfflineEntitlementError(reason) from error
    if len(raw) > limit:
        raise OfflineEntitlementError(reason)
    return raw


def _certificate_validity(certificate) -> tuple[datetime.datetime, datetime.datetime]:
    """Validity window as aware UTC bounds (older cryptography has no *_utc)."""
    before = getattr(certificate, "not_valid_before_utc", None)
    after = getattr(certificate, "not_valid_after_utc", None)
    if before is None or after is None:
        before = certificate.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        after = certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return before, after


def _verify_signature_value(public_key, signature: dict, canonical: bytes) -> None:
    try:
        value = base64.b64decode(signature.get("value", ""), validate=True)
        public_key.verify(value, canonical, padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, TypeError, ValueError) as error:
        raise OfflineEntitlementError(
            "offline issuance policy signature does not match") from error


def _verify_pinned_signature(signature: dict, canonical: bytes) -> None:
    """Issuer key form: one pinned key_id plus one PEM on this host, no certificate on the wire."""
    public_path = os.environ.get(PUBLIC_KEY_FILE, "")
    expected_kid = os.environ.get(EXPECTED_KID, "")
    if not public_path or not expected_kid or not os.path.isabs(public_path):
        raise OfflineEntitlementError("offline issuance policy is not provisioned")
    if signature.get("key_id") != expected_kid:
        raise OfflineEntitlementError("unknown offline issuance signing key")
    public_pem = _read_limited(public_path, MAX_KEY_BYTES, "oversized offline issuance public key")
    try:
        public_key = serialization.load_pem_public_key(public_pem)
    except ValueError as error:
        raise OfflineEntitlementError("offline issuance public key is not readable") from error
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise OfflineEntitlementError("offline deployment key must be RSA")
    _verify_signature_value(public_key, signature, canonical)


def _verify_customer_ca_signature(document: dict, signature: dict, canonical: bytes) -> None:
    """Customer CA form (#1550): the envelope carries the signing certificate itself.

    The rule mirrors the workstation verifier: the signature must come from a currently
    valid RSA *leaf* that carries digitalSignature, is not a CA and is issued by the
    pinned customer CA. A document the stations accept is the one accepted here.
    """
    ca_path = os.environ.get(CA_FILE, "")
    if not ca_path or not os.path.isabs(ca_path):
        raise OfflineEntitlementError("offline issuance policy is not provisioned")
    revision = document.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or not 1 <= revision <= 2147483647:
        raise OfflineEntitlementError("customer CA signature requires a monotonic revision")
    try:
        der = base64.b64decode(signature.get("cert_base64", ""), validate=True)
    except (TypeError, ValueError) as error:
        raise OfflineEntitlementError(
            "offline issuance signing certificate is not readable") from error
    if len(der) > MAX_CERTIFICATE_BYTES:
        raise OfflineEntitlementError("oversized offline issuance signing certificate")
    if signature.get("key_id") != CERT_KID_PREFIX + hashlib.sha256(der).hexdigest():
        raise OfflineEntitlementError("customer signing certificate fingerprint mismatch")
    try:
        leaf = x509.load_der_x509_certificate(der)
    except ValueError as error:
        raise OfflineEntitlementError(
            "offline issuance signing certificate is not readable") from error
    now = datetime.datetime.now(datetime.timezone.utc)
    before, after = _certificate_validity(leaf)
    if not before <= now <= after:
        raise OfflineEntitlementError("offline issuance signing certificate is not currently valid")
    try:
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as error:
        raise OfflineEntitlementError("customer signer lacks digitalSignature key usage") from error
    if not usage.digital_signature:
        raise OfflineEntitlementError("customer signer lacks digitalSignature key usage")
    try:
        constraints = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        constraints = None
    if constraints is not None and constraints.ca:
        raise OfflineEntitlementError("a CA certificate may not directly sign deployment flags")
    ca_pem = _read_limited(ca_path, MAX_CERTIFICATE_BYTES, "oversized offline issuance CA certificate")
    try:
        ca = x509.load_pem_x509_certificate(ca_pem)
    except ValueError as error:
        raise OfflineEntitlementError("offline issuance CA certificate is not readable") from error
    ca_before, ca_after = _certificate_validity(ca)
    if not ca_before <= now <= ca_after:
        raise OfflineEntitlementError("offline issuance CA certificate is not currently valid")
    ca_key = ca.public_key()
    if not isinstance(ca_key, rsa.RSAPublicKey) or not isinstance(leaf.public_key(), rsa.RSAPublicKey):
        raise OfflineEntitlementError("offline issuance certificates must be RSA")
    if leaf.issuer != ca.subject:
        raise OfflineEntitlementError("customer signing certificate is not issued by the pinned CA")
    parameters = getattr(leaf, "signature_algorithm_parameters", None) or padding.PKCS1v15()
    algorithm = leaf.signature_hash_algorithm
    if algorithm is None:
        raise OfflineEntitlementError("customer signing certificate has no signature hash")
    try:
        ca_key.verify(leaf.signature, leaf.tbs_certificate_bytes, parameters, algorithm)
    except (InvalidSignature, TypeError, ValueError) as error:
        raise OfflineEntitlementError(
            "customer signing certificate is not issued by the pinned CA") from error
    _verify_signature_value(leaf.public_key(), signature, canonical)


def _load_authorised_selectors(path: str) -> tuple[list[str], list[tuple[str, ...]]]:
    policy_path = os.environ.get(POLICY_FILE, "")
    if not policy_path or not os.path.isabs(policy_path):
        raise OfflineEntitlementError("offline issuance policy is not provisioned")
    raw = _read_limited(policy_path, MAX_POLICY_BYTES, "offline issuance policy is unreadable")
    try:
        envelope = json.loads(raw)
    except ValueError as error:
        raise OfflineEntitlementError("offline issuance policy is not valid JSON") from error
    if not isinstance(envelope, dict):
        raise OfflineEntitlementError("offline issuance policy is not valid JSON")
    document = envelope.get("document")
    signature = envelope.get("signature")
    if (not isinstance(document, dict) or not isinstance(signature, dict)
            or signature.get("algorithm") != "rsa-sha256"):
        raise OfflineEntitlementError("unsupported offline issuance policy signature")
    valid_until = document.get("valid_until")
    if (document.get("format_version") != 1
            or document.get("type") != "deployment-flags"
            or not isinstance(valid_until, str)):
        raise OfflineEntitlementError("invalid offline issuance policy")
    try:
        expired = datetime.date.fromisoformat(valid_until) < datetime.date.today()
    except ValueError as error:
        raise OfflineEntitlementError("invalid offline issuance policy") from error
    if expired:
        raise OfflineEntitlementError("expired offline issuance policy")
    # Same UTF-8 canonical representation as the Gateway deployment-flags signer.
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    if "cert_base64" in signature:
        _verify_customer_ca_signature(document, signature, canonical)
    else:
        _verify_pinned_signature(signature, canonical)
    flags = document.get("flags")
    if not isinstance(flags, dict):
        raise OfflineEntitlementError("missing deployment flag object")
    group_key = "offline_hotp_groups" if path == "hotp" else "offline_fido2_groups"
    groups = flags.get(group_key, [])
    if (not isinstance(groups, list) or len(groups) > 32 or
            any(not isinstance(x, str) or not x or len(x) > 255 for x in groups)):
        raise OfflineEntitlementError("malformed offline group allowlist")
    rule_key = "offline_hotp_rules" if path == "hotp" else "offline_fido2_rules"
    raw_rules = flags.get(rule_key, [])
    if not isinstance(raw_rules, list) or len(raw_rules) > 32:
        raise OfflineEntitlementError("malformed offline rule allowlist")
    rules = []
    for entry in raw_rules:
        if not isinstance(entry, str) or not entry or len(entry.encode("utf-8")) > 255:
            raise OfflineEntitlementError("malformed offline selector")
        source, sep, value = entry.partition(":")
        parts = value.split("/", 2)
        if (not sep or source not in ("realm", "user", "group")
                or len(parts) != (1 if source == "realm" else 3)
                or any(not part or part != part.strip() for part in parts)
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in entry)):
            raise OfflineEntitlementError("malformed offline selector")
        rules.append((source, *parts))
    if path == "hotp" and flags.get("offline_hotp_allowed") is not True:
        return [], []
    return groups, rules


def _same_group(member: str, permitted: str) -> bool:
    """Qualified allowlist requires qualified LDAP data (never guess a domain)."""
    if not isinstance(member, str):
        return False
    if "\\" in permitted:
        return member.casefold() == permitted.casefold()
    return member.rsplit("\\", 1)[-1].casefold() == permitted.casefold()


def offline_grant_for_token(token) -> str:
    """Authorize the resolved token owner during online issuance, never on CP.

    Explicit rules are scoped to the authoritative realm/resolver/UID, not a
    caller-provided username. A realm grant includes all its resolved users.
    Legacy group entries retain their existing semantics.
    """
    kind = str(getattr(token, "type", "")).lower()
    grant = "hotp" if kind == "hotp" else ("fido2" if kind in ("webauthn", "passkey") else "")
    if not grant:
        raise OfflineEntitlementError("token kind cannot be used offline")
    allowed, rules = _load_authorised_selectors(grant)
    if not allowed and not rules:
        raise OfflineEntitlementError("offline access not enabled for token owner")
    user = token.user
    if user is None or not user.resolver or not user.uid:
        raise OfflineEntitlementError("token has no resolved directory owner")
    resolver = get_resolver_object(user.resolver)
    if resolver is None:
        raise OfflineEntitlementError("offline issuance directory resolver is unavailable")
    realm = getattr(user, "realm", "")
    scoped = [rule for rule in rules if rule[1] == realm]
    direct = any(rule[0] == "realm" or (
        rule[0] == "user" and rule[2] == user.resolver and rule[3] == str(user.uid))
        for rule in scoped)
    # Verify current existence against the actual resolver even for explicit
    # user/realm rights. No cache or local Windows username grants access.
    try:
        info = resolver.get_user_info(user.uid)
    except Exception as error:
        raise OfflineEntitlementError("offline issuance resolver lookup failed") from error
    if not isinstance(info, dict) or not info:
        raise OfflineEntitlementError("offline issuance owner could not be read")
    if direct:
        LOG.debug("AMFA offline %s issuance: explicit owner or realm entitlement", grant)
        return grant
    allowed = allowed + [rule[3] for rule in scoped
                         if rule[0] == "group" and rule[2] == user.resolver]
    if not allowed:
        raise OfflineEntitlementError("token owner is outside offline allowlist")
    group_key = getattr(resolver, "group_attribute_mapping_key", None) or "groups"
    if group_key not in resolver.get_available_info_keys():
        raise OfflineEntitlementError("resolver cannot return group membership")
    members = info.get(group_key)
    if not isinstance(members, (list, tuple)):
        raise OfflineEntitlementError("directory did not return a complete group list")
    if not all(isinstance(x, str) for x in members):
        raise OfflineEntitlementError("malformed directory group membership")
    if not any(_same_group(member, allowed_group)
               for member in members for allowed_group in allowed):
        raise OfflineEntitlementError("token owner is outside offline allowlist")
    LOG.debug("AMFA offline %s issuance: resolver group entitlement checked", grant)
    return grant

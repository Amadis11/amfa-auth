"""AMFA signed offline batch v1 (#1156, root->leaf anchor #1692).

Never put a signing key in source control. Set AMFA_OFFLINE_ED25519_PRIVATE_KEY_FILE
to a root-owned PEM file and AMFA_OFFLINE_ED25519_KEY_ID to a pinned identifier.

Wire: {"alg":"Ed25519","key_id":"...","anchor":"<base64>",
       "anchor_signature":"<base64>","signed_payload":"<base64>",
       "signature":"<base64>"}
The signed payload is the *original immutable* offline item (not the mutable
consumed-code store). Signature input includes a fixed domain-separation prefix.

Trust chain (#1692): the station package pins ONLY the AMITRONIC product root
public key, so one package serves every customer. This engine signs batches with
its own installation key and proves that key with an *anchor* already signed by
the root key (provisioned at deployment, ``AMFA_OFFLINE_ED25519_ANCHOR_FILE``).
The root PRIVATE key never reaches an appliance; this code never signs an anchor.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

LOG = logging.getLogger(__name__)
SIGNING_CONTEXT = b"AMFA-OFFLINE-BATCH-v1\x00"
ANCHOR_CONTEXT = b"AMFA-OFFLINE-ANCHOR-v1\x00"
ALG = "Ed25519"
#: Anchor JSON is canonical (sorted keys, compact) and carries exactly these two fields.
ANCHOR_FIELDS = ("key_id", "public_key_b64")
MAX_ANCHOR_BYTES = 512


class OfflineSigningError(RuntimeError):
    pass


def canonical_item(item: dict) -> bytes:
    if not isinstance(item, dict) or not item.get("serial") or not item.get("refilltoken"):
        raise OfflineSigningError("offline batch missing serial or refilltoken")
    if not isinstance(item.get("response"), dict):
        raise OfflineSigningError("offline batch response must be an object")
    # ASCII-only canonical JSON; server and C++ verify identical signed bytes,
    # rather than independently reserializing potentially different JSON types.
    return json.dumps(item, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def anchor_bytes(key_id: str, public_key: str) -> bytes:
    """Canonical anchor document - exactly what the root key signs."""
    if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
        raise OfflineSigningError("invalid anchor key identifier")
    payload = {"key_id": key_id, "public_key_b64": public_key}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _load_anchor(path: str, private_key: Ed25519PrivateKey, key_id: str) -> dict:
    """Read the root-signed anchor for THIS installation key.

    Provisioned at deployment from the product root key; this appliance never
    holds the root private key. A mismatching anchor is fatal: sending it would
    only make every station reject the batch.
    """
    if not os.path.isabs(path):
        raise OfflineSigningError("anchor path must be absolute")
    with open(path, "rb") as fh:
        raw = fh.read(4 * MAX_ANCHOR_BYTES + 1)
    if len(raw) > 4 * MAX_ANCHOR_BYTES:
        raise OfflineSigningError("anchor file is unexpectedly large")
    try:
        envelope = json.loads(raw.decode("utf-8"))
        anchor_b64 = envelope["anchor"]
        anchor_signature = envelope["anchor_signature"]
        anchor_doc = base64.b64decode(anchor_b64, validate=True)
        signed = json.loads(anchor_doc.decode("ascii"))
    except (ValueError, KeyError, TypeError) as exc:
        raise OfflineSigningError("anchor file is not a signed anchor document") from exc
    if len(anchor_doc) > MAX_ANCHOR_BYTES or not isinstance(anchor_signature, str):
        raise OfflineSigningError("anchor file is not a signed anchor document")
    if sorted(signed) != sorted(ANCHOR_FIELDS):
        raise OfflineSigningError("anchor carries unexpected fields")
    if anchor_bytes(signed["key_id"], signed["public_key_b64"]) != anchor_doc:
        raise OfflineSigningError("anchor is not canonical JSON")
    if signed["key_id"] != key_id:
        raise OfflineSigningError("anchor names another installation key")
    if signed["public_key_b64"] != public_key_b64(private_key):
        raise OfflineSigningError("anchor does not match the installation key")
    # Optional self-check: when the product root public key is configured here we
    # verify the anchor locally instead of discovering the problem on a station.
    root_public = os.environ.get("AMFA_OFFLINE_ROOT_PUBLIC_KEY_B64", "").strip()
    if root_public:
        try:
            root = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(root_public, validate=True))
        except (ValueError, TypeError):
            root = None
        if root is None:
            raise OfflineSigningError("configured root public key is unreadable")
        try:
            root.verify(base64.b64decode(anchor_signature, validate=True),
                        ANCHOR_CONTEXT + anchor_doc)
        except Exception as exc:
            raise OfflineSigningError("anchor is not signed by the configured root key") from exc
    return {"anchor": anchor_b64, "anchor_signature": anchor_signature}


def sign_item(item: dict, private_key: Ed25519PrivateKey, key_id: str,
              anchor: dict | None = None) -> dict:
    if not key_id or len(key_id) > 128 or not all(
            (c.isascii() and (c.isalnum() or c in "._-")) for c in key_id):
        raise OfflineSigningError("invalid signing key identifier")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise OfflineSigningError("offline signing key must be Ed25519")
    # Server time limits the signed batch. The workstation must NEVER infer a
    # longer validity from its own clock for a signed payload.
    # Pre-production 1.0 contract: an offline batch may be renewed by a
    # successful online authentication, but can never be issued for >30 days.
    # The issuer controls the TTL; local offline logons never extend it.
    validity = int(os.environ.get("AMFA_OFFLINE_ED25519_TTL_SECONDS", "2592000"))
    if not 60 <= validity <= 30 * 24 * 3600:
        raise OfflineSigningError("signed offline TTL must be between 60 seconds and 30 days")
    # v2 ties offline entitlement to this issuer-signed batch.
    grant = item.get("offline_grant")
    response = item.get("response", {})
    expected = "fido2" if ("credentialId" in response or "pubKey" in response) else "hotp"
    if grant != expected:
        raise OfflineSigningError("offline batch has no authenticated issuance grant")
    item = dict(item)
    # One server clock sample binds the issuance order and the signed expiry.
    # Never accept an issuance timestamp supplied by the caller.
    issued_at_us = time.time_ns() // 1000
    item["issued_at_us"] = issued_at_us
    item["expiration"] = issued_at_us // 1_000_000 + validity
    item["format_version"] = 2
    payload = canonical_item(item)
    signature = private_key.sign(SIGNING_CONTEXT + payload)
    envelope = {
        "alg": ALG,
        "key_id": key_id,
        "signed_payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    if anchor:
        envelope["anchor"] = anchor["anchor"]
        envelope["anchor_signature"] = anchor["anchor_signature"]
    return envelope


def _load_key(path: str) -> Ed25519PrivateKey:
    if not os.path.isabs(path):
        raise OfflineSigningError("private key path must be absolute")
    # The key must be provisioned outside the repository, protected by OS ACL
    # (root/service account only), and identical on all signing HA nodes.
    with open(path, "rb") as fh:
        pem = fh.read(8192)
        if len(pem) >= 8192:
            raise OfflineSigningError("offline signing PEM is unexpectedly large")
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise OfflineSigningError("offline signing PEM does not contain Ed25519")
    return key


def signing_enabled() -> bool:
    return os.environ.get("AMFA_OFFLINE_ED25519_ENABLED", "").strip() == "1"


def signed_auth_items(auth_items: dict) -> dict:
    """Sign every offline item. On misconfiguration raise; never send unsigned.

    Callers must drop the offline payload on error (online auth remains usable).
    """
    if not signing_enabled():
        return auth_items  # only for legacy deployments until client rollout
    path = os.environ.get("AMFA_OFFLINE_ED25519_PRIVATE_KEY_FILE", "")
    key_id = os.environ.get("AMFA_OFFLINE_ED25519_KEY_ID", "")
    anchor_path = os.environ.get("AMFA_OFFLINE_ED25519_ANCHOR_FILE", "")
    if not path or not key_id or not anchor_path:
        raise OfflineSigningError("signing enabled but private key, key id or root-signed anchor is missing")
    key = _load_key(path)
    anchor = _load_anchor(anchor_path, key, key_id)
    if not isinstance(auth_items, dict) or not isinstance(auth_items.get("offline"), list):
        raise OfflineSigningError("offline items have unexpected shape")
    # Sign all-or-nothing: never mix signed and unsigned entries in one response.
    return dict(auth_items, offline=[
        sign_item(item, key, key_id, anchor) for item in auth_items["offline"]
    ])

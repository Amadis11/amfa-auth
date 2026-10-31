"""AMFA signed offline batch v1 (#1156).

Never put a signing key in source control. Set AMFA_OFFLINE_ED25519_PRIVATE_KEY_FILE
to a root-owned PEM file and AMFA_OFFLINE_ED25519_KEY_ID to a pinned identifier.

Wire: {"alg":"Ed25519","key_id":"...","signed_payload":"<base64>",
       "signature":"<base64>"}
The signed payload is the *original immutable* offline item (not the mutable
consumed-code store). Signature input includes a fixed domain-separation prefix.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

LOG = logging.getLogger(__name__)
SIGNING_CONTEXT = b"AMFA-OFFLINE-BATCH-v1\x00"
ALG = "Ed25519"


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


def sign_item(item: dict, private_key: Ed25519PrivateKey, key_id: str) -> dict:
    if not key_id or len(key_id) > 128 or not all(
            (c.isascii() and (c.isalnum() or c in "._-")) for c in key_id):
        raise OfflineSigningError("invalid signing key identifier")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise OfflineSigningError("offline signing key must be Ed25519")
    # Server time limits the signed batch. The workstation must NEVER infer a
    # longer validity from its own clock for a signed payload.
    validity = int(os.environ.get("AMFA_OFFLINE_ED25519_TTL_SECONDS", "3888000"))
    if not 60 <= validity <= 45 * 24 * 3600:
        raise OfflineSigningError("signed offline TTL must be between 60 seconds and 45 days")
    item = dict(item)
    item["expiration"] = int(time.time()) + validity
    item["format_version"] = 1
    payload = canonical_item(item)
    signature = private_key.sign(SIGNING_CONTEXT + payload)
    return {
        "alg": ALG,
        "key_id": key_id,
        "signed_payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


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
    if not path or not key_id:
        raise OfflineSigningError("signing enabled but private key or key id is missing")
    key = _load_key(path)
    if not isinstance(auth_items, dict) or not isinstance(auth_items.get("offline"), list):
        raise OfflineSigningError("offline items have unexpected shape")
    # Sign all-or-nothing: never mix signed and unsigned entries in one response.
    return dict(auth_items, offline=[
        sign_item(item, key, key_id) for item in auth_items["offline"]
    ])

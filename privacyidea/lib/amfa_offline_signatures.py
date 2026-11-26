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
import re
import stat
import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

LOG = logging.getLogger(__name__)
SIGNING_CONTEXT = b"AMFA-OFFLINE-BATCH-v1\x00"
ANCHOR_CONTEXT = b"AMFA-OFFLINE-ANCHOR-v1\x00"
ALG = "Ed25519"
#: Canonical root-signed anchor binds the leaf to one stable installation UUID.
ANCHOR_FIELDS = ("installation_id", "key_id", "public_key_b64")
MAX_ANCHOR_BYTES = 512

#: Signed batches name the AD account they were issued for. The regex is ASCII-only
#: and the canonical form is checked part by part, so two spellings of one SID can
#: never both validate on the workstation.
_AD_SID = re.compile(r"S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10}", re.ASCII)


def validate_subject(sid, realm) -> None:
    if (not isinstance(sid, str) or not _AD_SID.fullmatch(sid)
            or not isinstance(realm, str) or not realm or realm != realm.strip()):
        raise ValueError("offline issuance requires a resolved AD SID and realm")
    parts = sid.split("-")[4:]
    if any(str(int(part)) != part or int(part) > 0xffffffff for part in parts):
        raise ValueError("offline issuance requires a canonical AD SID")


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


def validate_installation_id(value: str) -> str:
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
            raise ValueError("noncanonical installation UUID")
    except (ValueError, AttributeError, TypeError) as exc:
        raise OfflineSigningError("invalid installation UUID") from exc
    return value


def anchor_bytes(key_id: str, public_key: str, installation_id: str) -> bytes:
    """Canonical anchor document - exactly what the root key signs."""
    if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
        raise OfflineSigningError("invalid anchor key identifier")
    payload = {"installation_id": validate_installation_id(installation_id),
               "key_id": key_id, "public_key_b64": public_key}
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
    if anchor_bytes(signed["key_id"], signed["public_key_b64"], signed["installation_id"]) != anchor_doc:
        raise OfflineSigningError("anchor is not canonical JSON")
    expected_installation = validate_installation_id(os.environ.get("AMFA_OFFLINE_INSTALLATION_ID", ""))
    if signed["installation_id"] != expected_installation:
        raise OfflineSigningError("anchor belongs to another installation")
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
    return {"anchor": anchor_b64, "anchor_signature": anchor_signature,
            "installation_id": expected_installation}


def sign_item(item: dict, private_key: Ed25519PrivateKey, key_id: str,
              anchor: dict | None = None) -> dict:
    # The Windows client demands these exact identity fields. Never emit a
    # cryptographically valid but unusable snapshot (e.g. a batch without
    # username): the issuer must fail atomically, not make the client guess.
    if not isinstance(item, dict):
        raise OfflineSigningError("offline item must be an object")
    for name, limit in (("serial", 128), ("username", 256), ("refilltoken", 1024)):
        value = item.get(name)
        if (not isinstance(value, str) or not value.strip() or len(value) > limit
                or any(ord(c) < 32 for c in value)):
            raise OfflineSigningError(f"offline batch has invalid {name}")
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
    # v3 binds entitlement and immutable AD subject to the signed batch.
    grant = item.get("offline_grant")
    response = item.get("response", {})
    expected = "fido2" if ("credentialId" in response or "pubKey" in response) else "hotp"
    if grant != expected:
        raise OfflineSigningError("offline batch has no authenticated issuance grant")
    item = dict(item)
    # v3: the signed subject (AD SID + realm + canonical account name) is part of
    # the batch, so it must be canonical BEFORE the signature is computed. The
    # workstation verifies these bytes verbatim; it never re-derives them.
    try:
        validate_subject(item.get("account_sid"), item.get("realm"))
    except ValueError as error:
        raise OfflineSigningError(str(error)) from error
    if not isinstance(item.get("username"), str) or not item["username"]:
        raise OfflineSigningError("offline batch missing canonical account name")
    # One server clock sample binds the issuance order and the signed expiry.
    # Never accept an issuance timestamp supplied by the caller.
    issued_at_us = time.time_ns() // 1000
    item["issued_at_us"] = issued_at_us
    item["expiration"] = issued_at_us // 1_000_000 + validity
    item["format_version"] = 3
    # Production issuance always supplies a validated anchor. Bind the grant itself
    # to its installation as well; caller-provided identity is never authoritative.
    if anchor is not None:
        item["installation_id"] = validate_installation_id(anchor.get("installation_id"))
    else:
        item.pop("installation_id", None)  # low-level unanchored test vectors only
    payload = canonical_item(item)
    # OfflineSignedBatch::kMaxPayload in CP is 256 KiB; a signer must not
    # return a payload that the pinned release will inevitably reject.
    if len(payload) > 256 * 1024:
        raise OfflineSigningError("signed offline payload exceeds Windows CP limit")
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
    """Read the private signing key only from a regular owner-private file.

    The signing key is a server secret, unlike the PUBLIC release anchor.
    A readable-for-everyone volume mount or a symlink must not silently turn
    offline issuance into a compromised signer. Check the OPEN file descriptor
    (not a racy os.stat(path) before opening it). This daemon runs on Linux.
    """
    if not os.path.isabs(path):
        raise OfflineSigningError("private key path must be absolute")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise OfflineSigningError("secure offline signing key access requires Linux")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise OfflineSigningError("cannot securely open offline signing key") from exc
    try:
        with os.fdopen(fd, "rb") as fh:
            info = os.fstat(fh.fileno())
            if (not stat.S_ISREG(info.st_mode)
                    or info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o077
                    or not info.st_mode & stat.S_IRUSR):
                raise OfflineSigningError(
                    "offline signing key must be a regular owner-readable file,"
                    " owned by root/service, without group/other permissions"
                )
            if info.st_size <= 0 or info.st_size >= 8192:
                raise OfflineSigningError("offline signing PEM size is invalid")
            pem = fh.read(8192)
            if len(pem) != info.st_size:
                raise OfflineSigningError("offline signing PEM changed while being read")
    except OSError as exc:
        raise OfflineSigningError("cannot securely read offline signing key") from exc
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as exc:
        raise OfflineSigningError("offline signing PEM is invalid") from exc
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

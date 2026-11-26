"""Root-signed anchor for tests that exercise signed offline batches (#1692).

The product ROOT private key never reaches an appliance and never reaches a test.
Here we mint a throwaway root pair and sign an anchor for the test installation
key, exactly like the deployment step does. Nothing in this file is a product
secret and nothing here may be copied into a deployment.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

#: Must match privacyidea.lib.amfa_offline_signatures.ANCHOR_CONTEXT.
ANCHOR_CONTEXT = b"AMFA-OFFLINE-ANCHOR-v1\x00"

#: Stub anchor for tests that already patch the installation key loader. Such a
#: test cannot present a real anchor: a real one must name the key it signs for.
LAB_INSTALLATION_ID = "11223344-1122-4122-8122-112233445566"
LAB_ANCHOR = {"installation_id": LAB_INSTALLATION_ID, "anchor": "a290LWtvdHdpY2EtbGFidQ==", "anchor_signature": "cG9kcGlzLXJvb3QtbGFidQ=="}
STUB_ANCHOR = LAB_ANCHOR


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    return _b64(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))


def anchor_environment(directory: str, private_key: Ed25519PrivateKey, key_id: str,
                       root_key: Ed25519PrivateKey | None = None) -> dict:
    """Environment provisioning a root-signed anchor for ``private_key``.

    ``root_key`` defaults to a freshly generated throwaway root, so a test never
    needs (and never gets) the product root private key.
    """
    root_key = root_key or Ed25519PrivateKey.generate()
    anchor_doc = json.dumps({"installation_id": LAB_INSTALLATION_ID, "key_id": key_id, "public_key_b64": public_key_b64(private_key)},
                            sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    path = os.path.join(directory, "offline-anchor.json")
    with open(path, "w", encoding="ascii") as handle:
        json.dump({"anchor": _b64(anchor_doc),
                   "anchor_signature": _b64(root_key.sign(ANCHOR_CONTEXT + anchor_doc))}, handle)
    return {
        "AMFA_OFFLINE_INSTALLATION_ID": LAB_INSTALLATION_ID,
        "AMFA_OFFLINE_ED25519_ANCHOR_FILE": path,
        "AMFA_OFFLINE_ROOT_PUBLIC_KEY_B64": public_key_b64(root_key),
    }


def stub_anchor_environment(directory: str) -> dict:
    """Environment for tests that patch ``_load_anchor`` itself.

    ``signed_auth_items`` refuses to sign when the anchor path is missing, so the
    path must exist in the environment even though the loader is stubbed.
    """
    return {"AMFA_OFFLINE_ED25519_ANCHOR_FILE": os.path.join(directory, "offline-anchor.json")}

#!/usr/bin/env python3
"""Generate an AMFA offline Ed25519 key pair on the *deployment host*.

NEVER commit or upload the private PEM. Output only the public raw-key Base64,
which should be embedded in the signed Windows Credential Provider build.
"""
from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key-file", required=True, help="absolute private PEM path")
    parser.add_argument("--key-id", required=True, help="stable name, e.g. amfa-offline-2026-01")
    args = parser.parse_args()
    path = Path(args.private_key_file)
    if not path.is_absolute():
        parser.error("private key path must be absolute")
    if not args.key_id or len(args.key_id) > 128 or not all(
            ch.isascii() and (ch.isalnum() or ch in "._-") for ch in args.key_id):
        parser.error("key-id must use only ASCII letters, digits, ., _ or -")

    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    # O_EXCL avoids overwriting an existing key and does not follow an existing
    # symlink at the target. Restrict access before writing any secret bytes.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(pem)
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
    pub = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print(f"Private key: {path} (mode 0600; keep only on signing server)")
    print(f"AMFA_OFFLINE_ED25519_KEY_ID={args.key_id}")
    print("AMFA_OFFLINE_ED25519_PUBLIC_KEY_B64=" + base64.b64encode(pub).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

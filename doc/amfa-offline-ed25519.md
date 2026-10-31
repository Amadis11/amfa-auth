# AMFA offline: signed Ed25519 batches (issue #1156, Z12)

## Status and safety boundary

This is an **opt-in, coordinated protocol upgrade**. The signing key exists
**only** on the privacyIDEA backend. Windows receives a pinned **public** key
in the compiled Credential Provider. The local Windows SYSTEM account cannot
forge a new offline code, token identity, refill token or expiry by editing
the DPAPI store, even though SYSTEM can decrypt that store.

This does **not** make Windows administrator/SYSTEM untrusted-safe overall:
they can patch a locally running DLL, roll back a whole encrypted store,
alter the system clock, and bypass protections outside the offline-batch
format. It also does **not** provide per-batch revocation (#1156/Z14),
offline attempt throttling, network-free knowledge of AD lockout or centralized
offline usage logs. Those need separate changes.

This feature depends on the separately proposed **offline consumption
persistence fail-closed** change (Credential Provider PR #222): never permit an
offline OTP login after consumption could not be stored.

## Wire format

The original server response remains `auth_items.offline: []`, but each
element becomes an envelope:

```json
{
  "alg": "Ed25519",
  "key_id": "amfa-offline-2026-01",
  "signed_payload": "<standard base64 of canonical JSON bytes>",
  "signature": "<standard base64 of 64-byte signature>"
}
```

The exact bytes signed are:
`ASCII("AMFA-OFFLINE-BATCH-v1") || NUL || signed_payload_decoded_bytes`.

The canonical JSON has ASCII escapes, `sort_keys=True`, separators
`(',', ':')` and **no NaN**. It includes `serial`, `username`,
`refilltoken`, `response`, `format_version:1` and a server-issued,
signed Unix `expiration` in UTC. Never sign a reserialized JSON document on
Windows: verify the **original signed bytes**.

An online refill produces a **new complete signed snapshot**. The client
replaces the previous signed snapshot; it must not append new hashes to a
signature that refers to another batch. The client retains the original
signed payload separately from its mutable map of remaining codes; at load it
verifies both the signature and that only originally issued codes remain.

## Create keys on the deployment host (not on a laptop/GitHub runner)

```bash
install -d -m 0700 /etc/amfa/offline-signing
python3 tools/amfa_offline_ed25519_keygen.py \
  --private-key-file /etc/amfa/offline-signing/ed25519-2026-01.pem \
  --key-id amfa-offline-2026-01
stat -c '%a %U %n' /etc/amfa/offline-signing/ed25519-2026-01.pem
```

The script creates the file using `O_EXCL` with mode `0600`, refuses to
overwrite an existing key, and prints **only the public key** to stdout.
Never commit the PEM, store it in public configuration, send it by email,
place it on Windows workstations or put it in a support archive. All HA
signing nodes must have the **same** provisioned key (or use a documented
multi-key rotation plan) and be able to read it as the application service
account.

## Server enablement (all HA nodes, after compatible clients are staged)

```bash
AMFA_OFFLINE_ED25519_ENABLED=1
AMFA_OFFLINE_ED25519_PRIVATE_KEY_FILE=/etc/amfa/offline-signing/ed25519-2026-01.pem
AMFA_OFFLINE_ED25519_KEY_ID=amfa-offline-2026-01
AMFA_OFFLINE_ED25519_TTL_SECONDS=3888000
```

The TTL is capped at **45 days** and must be between 60 and 3888000 seconds.
A signing error **does not produce an unsigned offline payload**: the online
login remains available but no new offline batch is issued. Inspect server
ERROR logs before enabling at scale.

Default: `AMFA_OFFLINE_ED25519_ENABLED` unset/0 — legacy server behavior,
for the upgrade window only. **Once clients require signatures, do not revert
the backend to emitting unsigned batches.** The client must be built with a
nonempty pinned public key and matching key ID before enabling signatures.

## Checks and test scope

```bash
python3 -m pytest tests/test_amfa_offline_ed25519_batches.py -q
```

Required before production acceptance:

1. Byte-identical Python + Windows C++ Ed25519 test vector.
2. New online enrollment yields valid signed data for HOTP and FIDO2.
3. Correct FIDO refill returns a signed **complete** pubkey/credential snapshot.
4. Signed offline payload survives saving to DPAPI, consuming a HOTP, reloading,
   and verifying the remaining-code subset. Tamper must be denied.
5. Absent public key, unknown key ID, malformed signature, expired or old
   unsigned snapshot must not enable offline login in the hardened client.
6. Online login still works if signing key is unavailable. Offline issuance is
   visibly alarmed on the server.
7. Windows build, TOKEN2 PIN/UV handling, GPO deployment, failover, rollback,
   server key permissions and correct signing on each HA node.

### Rollout/rotation warning

The current initial implementation pins **one Ed25519 public key** in a
Credential Provider build; it has no seamless multi-key rotation yet. Rotating
requires coordination: stage clients with the replacement trusted key
before switching the server. If unsupported multi-key transition would strand
offline clients, plan controlled re-enrollment/online refresh. Do not attempt
an unplanned key rotation or emergency switch to unsigned responses.

The old unsigned DPAPI store is **not trusted** by a public-key-pinned build.
Users must first perform an online login to receive new signed offline data;
deploy a pilot and retain an authorized recovery login route.

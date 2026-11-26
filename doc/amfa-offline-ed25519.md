# AMFA offline: signed Ed25519 batches (issue #1156, Z12)

**Universal MSI / ROOT → installation leaf (target architecture, not yet integrated):** see the [canonical issuance and deployment procedure](https://github.com/Amadis11/amitronic-amfa/blob/master/docs/deployment/kotwica-offline-ed25519.md). The build-time installation-key pin described below is the current implementation, not the intended commercial rollout. The final design pins only the AMITRONIC product ROOT in CP, signs each installation's public key and identity once, and requires no offline-anchor certificate import on Windows. Do not treat the target workflow as released until AUTH, CP, release tooling and native acceptance are aligned.


## Status and safety boundary

Signed v2 batches are the required offline authentication contract. The signing key exists
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

Signed offline v1 now also includes `issued_at_us` (UTC Unix microseconds).
Its signature prevents a previous, correctly signed refill from being replayed to
restore used HOTP codes. Windows compares this signed issuance timestamp instead
of `expiration`: two new snapshots can have the same expiration second.
Older already-issued signed v1 payloads without `issued_at_us` remain verifiable
for a one-time upgrade, but must not downgrade a timestamped snapshot.
If HA node clocks move backwards, the workstation refuses the older timestamp
(fail-closed); NTP synchronization on all signers is required. Physical rollback
of the entire DPAPI disk image still requires TPM monotonic state or an online
revalidation, and is NOT solved by the signed timestamp.

The exact bytes signed are:
`ASCII("AMFA-OFFLINE-BATCH-v1") || NUL || signed_payload_decoded_bytes`.

The canonical JSON has ASCII escapes, `sort_keys=True`, separators
`(',', ':')` and **no NaN**. It includes `serial`, `username`,
`refilltoken`, `response`, `format_version`, `offline_grant` and a
server-issued, signed Unix `expiration` in UTC. Never sign a reserialized JSON
document on Windows: verify the **original signed bytes**.

`format_version: 2` is the current format. The signer only signs a batch that
carries the issuance grant the online entitlement check attached: `fido2` for a
response carrying `pubKey`/`credentialId`, `hotp` otherwise — any other
combination fails signing. Only v2 carries the entitlement required for offline login.
The issuer evaluates the native AUTH policy of the resolved token owner at issuance and refill. Prerequisites are described in
`docs/amfa-offline-v2-issue-time-entitlement.md`.

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
# MUSI być zwykłym plikiem (bez symlinków), z prawami właściciela
# np. 0600/0400 i właścicielem root lub UID procesu privacyIDEA.
# Tryby 0640/0644/0666 oraz dowiązania symboliczne są odrzucane
# przez _load_key na podstawie fstat otwartego deskryptora (fail-closed).
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
AMFA_OFFLINE_ED25519_TTL_SECONDS=2592000
```

The TTL is capped at **30 days** (`2592000` seconds) and must be between 60 and
`2592000` seconds. This is the release contract pinned by
`tests/test_amfa_offline_ttl_30.py`: a successful online authentication may
renew a batch, but a batch is never signed for longer than 30 days.
A signing error **does not produce an unsigned offline payload**: the online
login remains available but no new offline batch is issued. Inspect server
ERROR logs before enabling at scale.

Enable signing on all AUTH nodes before accepting offline logon. The client must have the matching pinned public key and key ID. Unsigned batches cannot authorize offline authentication.

## Checks and test scope

```bash
python3 -m pytest tests/test_amfa_offline_ed25519_batches.py \
                   tests/test_amfa_offline_entitlement.py \
                   tests/test_amfa_offline_ttl_30.py \
                   tests/test_api_validate_offline.py \
                   tests/test_api_passkey.py -q
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
8. Issue-time entitlement: explicit native AUTH `amfa_offline_fido2` or `amfa_offline_hotp` allow for the resolved owner; absent allow, deny, conflicting policy or unreachable resolver issues **no** new offline data (online login unaffected). Verify both AD and local resolvers.
9. Issue-time entitlement never degrades an online path: an authentication and a
   passkey enrollment whose owner may not receive offline material still succeed
   (no `auth_items`), while a refill is refused with a defined answer — HTTP 400,
   error code `905`, `Offline issuance is not allowed for this account`, with no
   counter reserved and no refill credential rotated — instead of an HTTP 500.
   Pinned by
   `tests/test_api_validate_offline.py::AValidateOfflineTestCase::test_05_refill_without_entitlement_is_a_defined_refusal`
   and
   `tests/test_api_passkey.py::PasskeyAPITest::test_09b_offline_enrollment_without_entitlement_stays_online_only`.

### Rollout/rotation warning

The current initial implementation pins **one Ed25519 public key** in a
Credential Provider build; it has no seamless multi-key rotation yet. Rotating
requires coordination: stage clients with the replacement trusted key
before switching the server. If unsupported multi-key transition would strand
offline clients, plan controlled re-enrollment/online refresh. Do not attempt
an unplanned key rotation or emergency switch to unsigned responses.

Users perform an online logon to obtain the first signed offline data. Pilot the exact release and retain an authorized recovery login route.

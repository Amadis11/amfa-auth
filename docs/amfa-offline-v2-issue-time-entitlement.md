# #1605 — Signed offline issue-time entitlement (v2)

An offline login on Windows must never query AD or AMFA. Eligibility is
evaluated by the AUTH **server** during initial signed issuance and on every
signed refill, using the current group membership of the **token owner**
obtained directly from the configured LDAP/AD resolver (not a user-supplied
account string or a cached group decision).

## Deployment prerequisites

Configure the policy file plus **one** of the two accepted signature forms:

- `AMFA_OFFLINE_DEPLOYMENT_FLAGS_FILE` (required): absolute path to the **exact
  signed deployment-flags envelope** published to the stations by the
  gateway/panel. This is JSON with `document.flags.offline_fido2_groups`
  and `document.flags.offline_hotp_groups`, NOT a second manually maintained
  list of groups. Mount it as an operator-owned read-only file and sync every
  signed revision to all AUTH/HA nodes.
- **Issuer key form** — `AMFA_OFFLINE_DEPLOYMENT_FLAGS_PUBLIC_KEY_FILE`
  (absolute path to the pinned trusted RSA public key) together with
  `AMFA_OFFLINE_DEPLOYMENT_FLAGS_KEY_ID` (the exact expected issuer key ID).
  The envelope must not carry a certificate.
- **Customer CA form** (#1550) — `AMFA_OFFLINE_DEPLOYMENT_FLAGS_CA_FILE`
  (absolute path to the PEM of the customer CA that also roots the stations'
  trust). The envelope then carries the signing certificate in
  `signature.cert_base64` and `signature.key_id` is
  `cert-sha256:<SHA-256 of the DER certificate>`.

Both forms are verified with the rules the workstations apply, so the document
accepted here is the document the stations accept: `rsa-sha256` only, the
signing certificate must be a currently valid RSA **leaf** that carries
`digitalSignature`, is not a CA itself and is issued by the pinned CA, and the
customer form additionally requires the document's monotonic `revision`.
Configuring both forms is allowed; the envelope decides which one is used.

For HOTP the signed document must additionally carry
`document.flags.offline_hotp_allowed: true`. Without it the HOTP allowlist is
treated as empty and **no** HOTP batch is issued; FIDO2/Passkey issuance is
unaffected. The flag is deliberately independent of the group list, so a
deployment can withdraw HOTP offline access without touching the document's
group membership.

The existing `AMFA_OFFLINE_ED25519_ENABLED=1` and Ed25519 private key
configuration are still required to sign the resulting v2 batch. Neither
private key nor plaintext Windows password is transported to the station.

**Do not enable rollout until the gateway/panel publication also updates the
file mounted in AUTH.** A missing or invalid file results in NO new offline
data (online login still succeeds). Every failure inside this module is a
defined refusal: an unreadable, oversized, malformed, expired or unprovisioned
policy, an unknown signing key, a stale or foreign certificate and a
non-matching signature all raise the same error class instead of an unexpected
server error. Never treat an unverified or customer-supplied group list as
authoritative.

The LDAP resolver must expose the group attribute as a list (normally
`groups`, with recursive_group_search configured for nested membership).
The server reads current membership from the resolver on each issuance.
Unknown group membership or unreachable directory = deny new issuance.
Short group names work; domain-qualified allowlist entries require the
resolver to return the correspondingly qualified group name. Never
synthesize the domain prefix from a username.

## Wire contract

- Ed25519 canonical payload `format_version: 2`.
- Top-level signed `offline_grant: "fido2"` for WebAuthn/Passkey or
  `offline_grant: "hotp"` for HOTP.
- A client with pinned Ed25519 verification accepts v1 only for parsing and
  migration; no offline use until a v2 batch is issued online.
- Any offline result uses the signed expiry (up to 30 days), account binding
  and local factor proof; removing membership from AD affects **future**
  issuance/refill only. Previously issued grants cannot be remotely revoked
  while the machine has no network.

## Fail-closed behaviour (what a station sees)

| Path | Document missing/invalid, or owner outside the allowlist |
| --- | --- |
| `/validate/check` (authentication) | login unchanged; **no** `auth_items.offline` — the bag is dropped and the reason logged on the server |
| passkey enrollment with `enroll_via_multichallenge_passkey_offline` | the enrollment succeeds (`result.value: true`) with no offline data; the machine keeps the offline attachment, so the next online login carries the bag once the allowlist is published — no re-enrollment |
| `/validate/offlinerefill` | defined refusal: HTTP 400, error code `905`, `Offline issuance is not allowed for this account`; no counter reserved and no refill credential rotated. The station keeps its current batch (valid until its signed expiry) and retries later |

The directory-side reason (`offline issuance policy is not provisioned`,
`token owner is outside offline allowlist`, `directory did not return a complete
group list`, ...) is logged on the server only; it never travels to the station.
An account outside the allowlist therefore never receives a **signed** batch,
while no online path fails because of it — the signer can be enabled before the
first flags document is published without breaking authentication or enrollment.

Known boundary: the administrative machine fetch (`GET /machine/authitems`) is
not covered by this contract; for an unentitled token that call fails instead of
returning items. It is not part of any station issuance path.

When triaging a station report, separate the two failures: **400/905 is a
refusal** (the document or the group membership does not allow this owner to
receive offline material) while a **masks-off server error is a fault of ours**
(unreadable signing key, invalid `AMFA_OFFLINE_ED25519_TTL_SECONDS`, signing
key id mismatch). A signing fault never produces an unsigned batch and never
consumes counters, so the station keeps using its last valid snapshot.

## Deployment sequence (both AUTH/HA nodes)

1. Publish the **same signed deployment-flags envelope** the stations receive to
   every AUTH node (do not maintain a second list) and place the trust anchor
   next to it: either the pinned RSA public key or the customer CA certificate,
   matching the form the envelope was signed with; the file is operator-owned
   and read-only for the service.
2. Set `AMFA_OFFLINE_DEPLOYMENT_FLAGS_FILE` and the variables of the matching
   form (`..._PUBLIC_KEY_FILE` + `..._KEY_ID`, or `..._CA_FILE`) in the service
   environment of **both** nodes and reload the service. Publishing the document
   while the signer is already enabled is safe: until the document is there no
   batch is signed, while authentication and enrollment keep working.
3. Verify the prerequisite is actually read by the running container, not only
   present in a file on the host:

   ```bash
   podman exec amfa-auth env | grep -E "^AMFA_OFFLINE_DEPLOYMENT"
   podman exec amfa-auth test -r "$AMFA_OFFLINE_DEPLOYMENT_FLAGS_FILE" && echo flags-readable
   ```
4. Check one entitled and one unentitled owner before rollout: the entitled
   owner gets a v2 batch (`format_version: 2` with the matching
   `offline_grant`) and the unentitled one is refused on refill with HTTP 400 /
   code `905` while still authenticating online.
5. Repeat the sequence on the partner node and keep the two documents in sync on
   every signed revision (a node with a stale document refuses new issuance
   instead of signing an outdated allowlist).

## Release blockers

Native Windows LogonUI + LSA acceptance with NIC link down; FIDO2,
HOTP, unlock and multi-user isolation. Test both AMFA and DC unreachable,
not merely the AMFA endpoint. Verify no HTTP refill on offline login, and
that removing group membership prevents issuing/refilling the next batch.

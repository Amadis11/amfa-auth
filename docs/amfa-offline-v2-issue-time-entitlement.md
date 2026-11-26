# Offline: native AUTH authorization

AUTH evaluates `amfa_offline_fido2` and `amfa_offline_hotp` (authentication scope)
against the token's actual owner at online issuance and every refill. Explicit
allow is required; absence, deny, policy conflict or resolver failure refuses
new material, without blocking regular online login. A local SQL/passwd
resolver needs no AD membership. Group conditions use fresh resolver data.
The embedded AMITRONIC ROOT verifies the installation leaf anchor; X.509 trust is independent and applies to HTTPS.

The offline Ed25519 signing key remains required, outside the repository,
identical on signing HA nodes. CP verifies the ROOT-signed leaf anchor, v3 grant, installation UUID, method, account SID/realm and expiration. See [issuance and rotation](https://github.com/Amadis11/amitronic-amfa/blob/master/docs/deployment/kotwica-offline-ed25519.md).
Unsigned batches do not authorize offline login. The default validity is
30 days; offline use does not renew it. An authoritative refusal at refill
must not rotate the secret or consume counters; CP handles the refusal using
its token-specific revocation path. Truly disconnected stations cannot receive
revocations and may use valid previously issued data until expiry.

Tests: native policy absence/deny, distinct method grants, local resolver without
groups, resolver failure, signed issuance/refill, and real air-gapped Windows
logon/unlock. Key-only vault authorization is a separate native AUTH policy `amfa_key_only_login`, checked by Gateway for the actual credential owner/SID. The server checks its licence; this online path is independent of offline FIDO2/HOTP.

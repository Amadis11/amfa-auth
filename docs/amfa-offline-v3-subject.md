## Signed v3 subject (#228)

Only signed format v3 is accepted by the pinned release. The original immutable payload includes `account_sid` (AD objectSid), `realm`, `username`, `offline_grant`, `issued_at_us` and expiry. Auth uses the resolved token owner and an uncached directory read, not workstation-supplied identity. The resolver must use UIDTYPE=objectSid. Refill cannot silently change a cached principal.

Offline MFA is restricted to local logon/unlock. FIDO uses the exact verified signed snapshot and HOTP returns the subject of the persisted consumption. Before handing a credential to Windows, CP verifies the subject against TokenUser from a temporary interactive Windows logon token (LogonUserW, no impersonation; token closed). This relies on Windows cached credentials for a disconnected domain workstation, not a directory lookup in the offline MFA grant policy. Missing cached Windows credentials, wrong SID/realm, invalid signature and old formats fail closed.

No production migration: use a fresh lab store on a clean test installation and acquire v3 grants online. Coordinate Auth and CP candidate builds; do not roll out only one component.

Native acceptance: two same-named accounts with distinct SIDs in two domains, HOTP and FIDO2, typed and key-first login, offline unlock, correct password for wrong principal, unqualified/qualified input, tampered signed/local fields, v1/v2 refusal, replay and refill. Disconnect NIC with DC AND AMFA unavailable. Verify actual desktop/session and target account SID, not merely event 4624 (the temporary Windows identity check can generate its own event). Confirm no Credential Provider offline grant in CredUI/RDP/UAC/RunAs. This is a test contract, not a PASS claim.

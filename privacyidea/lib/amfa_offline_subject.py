"""Canonical AD subject for signed offline batches (CP #228).

This helper is deliberately independent of request data and does not perform
directory I/O. Call only with the token's resolved owner and the resolver
used by the online issuance entitlement check.
"""
from __future__ import annotations

from privacyidea.lib.amfa_offline_signatures import validate_subject


def offline_subject(user, resolver) -> dict[str, str]:
    """Return the immutable directory subject, or refuse issuance.

    AMFA's AD resolver uses objectSid as UIDTYPE. Never treat an objectGUID,
    a DN, a short username or a client-supplied SID as equivalent.
    """
    sid = getattr(user, "uid", None)
    realm = getattr(user, "realm", None)
    if str(getattr(resolver, "uidtype", "")).lower() != "objectsid":
        raise ValueError("offline issuance requires an objectSid resolver")
    validate_subject(sid, realm)
    return {"account_sid": sid, "realm": realm}


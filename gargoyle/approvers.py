"""Enrolled approvers: a person's Entra identity bound to a key they hold.

`gargoyle init` writes approver key files. For a team, an approver should
instead sign in with Entra ID in the console, generate a key that never
leaves their browser, and enroll its public half once. The issuer accepts
the enrollment from a token that carries the approver app role (or a
configured group), binds the key to the token's UPN, and persists it here.
From then on the UPN is the approver key id on every grant, a threshold
rule may name UPNs, and removing a line from this file (or the role in
Entra) ends that person's ability to approve.

    approvers.json = {"approvers": {"<upn>": {"public_key_hex": ..., "enrolled_at": ..., "enrolled_by": ...}}}

Trust note. The issuer publishes this map (GET /approvers) and the
middleware fetches it over the issuer's TLS. That makes the issuer's
operator the authority for who may approve, which is weaker than a
root-signed key record (SPEC.md section 10) and the right fit for a site
where the same administrator runs the issuer and the tenant. Separation of
duties still holds at the key level: an approver's key is never the
issuer's, and the issuer never sees a private key.
"""

import json
import os
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

ENV_APPROVERS_PATH = "GARGOYLE_APPROVERS_PATH"
ENV_APPROVER_ROLE = "GARGOYLE_APPROVER_ROLE"        # Entra app role an enrolling token must carry (default Approver)
ENV_APPROVER_GROUPS = "GARGOYLE_APPROVER_GROUPS"    # or: comma-separated group ids, any of which qualifies

DEFAULT_APPROVER_ROLE = "Approver"


class RevokedKeyError(ValueError):
    """The public key offered for enrollment was revoked before: a revoked
    key stays revoked, the browser must generate a new one."""


def valid_public_key_hex(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


class ApproverRegistry:
    """The enrolled approvers, persisted to a JSON file. Thread-safe for the
    single process that owns the file."""

    def __init__(self, path: Optional[str]) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._approvers: Dict[str, Dict[str, Any]] = {}
        self._revoked: Dict[str, Dict[str, Any]] = {}      # former approvers, kept so old grants still verify in audits
        self._mtime: Optional[float] = None
        self._load()

    def _load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        doc = json.loads(self.path.read_text(encoding="utf-8"))
        approvers, revoked = {}, {}
        for upn, entry in (doc.get("approvers") or {}).items():
            if isinstance(entry, dict) and valid_public_key_hex(entry.get("public_key_hex")):
                approvers[upn] = dict(entry)
        for upn, entry in (doc.get("revoked") or {}).items():
            if isinstance(entry, dict) and valid_public_key_hex(entry.get("public_key_hex")):
                revoked[upn] = dict(entry)
        self._approvers, self._revoked = approvers, revoked
        self._mtime = self.path.stat().st_mtime

    def _refresh(self) -> None:
        """Re-read the file when something else wrote it: `gargoyle approvers
        revoke` on the issuer's host takes effect without a restart."""
        if self.path is None:
            return
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return
        if mtime != self._mtime:
            self._load()

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        doc = {"approvers": self._approvers}
        if self._revoked:
            doc["revoked"] = self._revoked
        self.path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        self._mtime = self.path.stat().st_mtime

    def enroll(self, upn: str, public_key_hex: str, *, enrolled_by: Optional[str] = None,
               now: Optional[datetime] = None, oid: Optional[str] = None, tid: Optional[str] = None) -> Dict[str, Any]:
        """Bind `upn` to `public_key_hex`, replacing any earlier key for that
        UPN (one key per approver; a new browser re-enrolls). The directory's
        immutable object id and tenant id are kept beside the UPN when the
        token carried them: the UPN is the name people read, the oid is what
        survives a rename. A key on the revoked list is never enrolled again,
        for anyone (RevokedKeyError): the live exercise of 2026-10-20 showed a
        browser re-enrolling the very key the operator had just revoked. The
        revoked record stays when a fresh key enrolls, so grants signed under
        the old key still audit."""
        if not isinstance(upn, str) or not upn:
            raise ValueError("upn must be a non-empty string")
        if not valid_public_key_hex(public_key_hex):
            raise ValueError("public_key_hex must be 64 lowercase hex characters")
        entry = {"public_key_hex": public_key_hex,
                 "enrolled_at": (now or datetime.now(timezone.utc)).isoformat(),
                 "enrolled_by": enrolled_by or upn}
        if oid:
            entry["oid"] = oid
        if tid:
            entry["tid"] = tid
        with self._lock:
            self._refresh()
            if any(e.get("public_key_hex") == public_key_hex for e in self._revoked.values()):
                raise RevokedKeyError("that key was revoked; enroll a new one")
            replaced = upn in self._approvers
            self._approvers[upn] = entry
            self._save()
        return {"upn": upn, "replaced": replaced, **entry}

    def revoke(self, upn: str, *, revoked_by: Optional[str] = None, now: Optional[datetime] = None) -> bool:
        """Stop trusting `upn`'s key from now on. The entry moves to the
        revoked list with when and by whom, so an audit of earlier evidence
        can still verify the grants it signed; the issuer and the
        middleware stop accepting new ones at once."""
        with self._lock:
            self._refresh()
            entry = self._approvers.pop(upn, None)
            if entry is None:
                return False
            self._revoked[upn] = {**entry, "revoked_at": (now or datetime.now(timezone.utc)).isoformat(),
                                  "revoked_by": revoked_by or upn}
            self._save()
        return True

    def remove(self, upn: str) -> bool:
        with self._lock:
            self._refresh()
            gone = self._approvers.pop(upn, None) is not None
            if gone:
                self._save()
        return gone

    def public_hex(self) -> Dict[str, str]:
        """{upn: public_key_hex}, what GET /approvers publishes."""
        with self._lock:
            self._refresh()
            return {upn: e["public_key_hex"] for upn, e in self._approvers.items()}

    def revoked_entries(self) -> Dict[str, Dict[str, Any]]:
        """The revoked list with when and by whom, re-read from the file: the
        service notices an operator's `gargoyle approvers revoke` here."""
        with self._lock:
            self._refresh()
            return {upn: dict(e) for upn, e in self._revoked.items()}

    def revoked_hex(self) -> Dict[str, str]:
        """{upn: public_key_hex} of revoked approvers: for verifying the
        grants they signed while trusted, never for accepting new ones."""
        with self._lock:
            self._refresh()
            return {upn: e["public_key_hex"] for upn, e in self._revoked.items()}

    def entries(self) -> Dict[str, Dict[str, Any]]:
        """Every current approver's record, for `gargoyle approvers list`."""
        with self._lock:
            self._refresh()
            return {upn: dict(e) for upn, e in self._approvers.items()}

    def keys(self) -> Dict[str, Any]:
        """{upn: Ed25519PublicKey}, the map a verifier uses."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return {upn: Ed25519PublicKey.from_public_bytes(bytes.fromhex(h)) for upn, h in self.public_hex().items()}

    def __contains__(self, upn: str) -> bool:
        with self._lock:
            self._refresh()
            return upn in self._approvers


def may_enroll(who: Dict[str, Any], *, role: str = DEFAULT_APPROVER_ROLE, groups: Optional[list] = None) -> bool:
    """Does an authenticated identity (identity.principal_from_token's
    result) qualify as an approver: the app role, or any configured group."""
    if role and role in (who.get("roles") or []):
        return True
    if groups and any(g in (who.get("groups") or []) for g in groups):
        return True
    return False


def keys_from_hex(mapping: Dict[str, str]) -> Dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    return {k: Ed25519PublicKey.from_public_bytes(bytes.fromhex(v)) for k, v in mapping.items() if valid_public_key_hex(v)}

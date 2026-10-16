"""The consumer side: everything a party that executes tool calls needs to
honor a receipt at most once, and a deployable reference target built on it.

Every consumer (the reference target below, gargoyle.mcp_server, an
integrator's own service) runs the same sequence on each call: establish
the live policy pin, establish the trusted issuer keys, verify_envelope,
demand and verify a human's grant when the receipt is flagged, then claim
the grant and the decision_id in a replay cache. `Consumer` packages it:

    from gargoyle.consumer import Consumer

    consumer = Consumer(
        target_id=TARGET_ID,                             # the identity receipts bind to
        pinned_public_keys={KEY_ID: issuer_public_key},  # or a signed key record
        record_bytes=open(RECORD_PATH, "rb").read(),     # or a record source
    )

    call = {"tool": name, "args": arguments, "principal": peer_identity}
    verdict = consumer.check(envelope, call, grant=grant_or_none)
    if verdict.honored:
        outputs = do_the_side_effect()
        execution = consumer.attest(envelope, outputs)   # signed execution receipt, if a key is configured
    else:
        refuse(verdict.reason)                           # REF_VERIFY_* / REF_TARGET_*

`peer_identity` is who the executor authenticated as the presenting party;
the receipt must name the same principal (see gargoyle.verifier). The
consumer only decides; the caller performs the side effect. Every
undecidable path is honored=False. Two rules are not optional:

  - The signature check always runs. verify_envelope raises when given no
    key material; a Consumer requires issuer-key trust at construction and
    passes an empty map rather than None when a key record is the source,
    so an unsigned receipt is refused, never honored.
  - A receipt without a decision_id is refused (REF_TARGET_NO_DECISION_ID):
    single use cannot be enforced for it.
  - A receipt whose signed requires_approval is true is honored only with a
    grant (gargoyle.approval) that a trusted approver key signed for exactly
    that decision_sha256 and approval_request_id, presented alongside the
    receipt; the grant is single-use too. No grant is
    REF_TARGET_APPROVAL_REQUIRED; no approver trust configured is
    REF_TARGET_NO_APPROVER_TRUST. The human-held key is therefore required
    at the point of execution, not merely at issuance.

Live pin and issuer keys can be static (a validated record dict, anchored
record bytes, a pinned key map, a validated key-record view) or come from a
source called on every check: `record_source(last_seen_serial)` returning
{"record", "reason"} (the shape published_record_source.fetch_signed_record
returns) and `key_record_source(last_seen_serial)` returning {"trust_view",
"reason", "serial"} (key_record_source.fetch_key_record). The consumer keeps
the highest serial it has seen for each and passes it back in, so a signed
record rolled back to an older serial is refused as stale even while it is
still inside its not_after window. A source result with no record or no
trust view fails closed with the source's reason and never falls back to a
static value.

The reference target (build_reference_target_app, `app`) is a FastAPI
service that authenticates the caller, reads the call from the body and the
receipt from the X-Gargoyle-Envelope header, and asks a Consumer. Its
configuration comes from the environment, never the repository; see
config_from_env. Run: uvicorn gargoyle.consumer:app --host 0.0.0.0 --port 9000
"""

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, NamedTuple, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool

from gargoyle.approval import verify_grant
from gargoyle.approver_trust import resolve_approver_keys
from gargoyle.execution import build_execution_receipt, sign_execution_receipt
from gargoyle.key_record_source import fetch_key_record
from gargoyle.published_record_source import fetch_signed_record
from gargoyle.published_source import (
    anchor_sha256,
    fetch_published_record,
    load_record_from_bytes,
)
from gargoyle.replay_cache import InMemoryReplayCache, replay_cache_from_env
from gargoyle.verifier import (
    REF_VERIFY_KEY_RECORD_INVALID,
    REF_VERIFY_PUBLISHED_RECORD_INVALID,
    REF_VERIFY_REPLAY,
    not_after_valid,
    verify_envelope,
)
from gargoyle.approval import REF_APPROVAL_REPLAY


# Refusals the consumer side emits itself. Every other refusal is the
# REF_VERIFY_* code verify_envelope returned, passed through unchanged.
REF_TARGET_NOT_CONFIGURED = "REF_TARGET_NOT_CONFIGURED"
REF_TARGET_ANCHOR_MISMATCH = "REF_TARGET_ANCHOR_MISMATCH"
# A receipt without a decision_id cannot be held to single use.
REF_TARGET_NO_DECISION_ID = "REF_TARGET_NO_DECISION_ID"
# The target could not authenticate the caller: no principal resolver and no
# principal header configured, or the header absent, empty or duplicated.
REF_TARGET_NO_PRINCIPAL = "REF_TARGET_NO_PRINCIPAL"
# The receipt is flagged for a human and no grant was presented with it.
REF_TARGET_APPROVAL_REQUIRED = "REF_TARGET_APPROVAL_REQUIRED"
# The receipt is flagged for a human and this consumer trusts no approver key.
REF_TARGET_NO_APPROVER_TRUST = "REF_TARGET_NO_APPROVER_TRUST"

# The headers carrying the receipt and, for a flagged call, the grant, as JSON
# (see gargoyle.issuer and gargoyle.approval).
ENVELOPE_HEADER = "X-Gargoyle-Envelope"
GRANT_HEADER = "X-Gargoyle-Grant"
# Replay-cache namespace for grant ids, so a grant id can never collide with
# a decision id.
_GRANT_CLAIM_PREFIX = "grant:"


class Verdict(NamedTuple):
    honored: bool
    reason: str


def _parse_not_after(envelope: Dict[str, Any]) -> Optional[datetime]:
    na = envelope.get("not_after")
    if isinstance(na, str):
        try:
            return datetime.fromisoformat(na)
        except ValueError:
            return None
    return None


class HighWater:
    """The highest serial seen on the signed published record and on the
    key record, so a rolled-back record is refused. One instance per
    consumer by default; share one across consumers that stand for the same
    target (the reference target builds a consumer per request and shares
    this and the replay cache). Replicas would need to share it like the
    replay cache."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.record_serial: Optional[int] = None
        self.key_record_serial: Optional[int] = None

    @staticmethod
    def _is_serial(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def advance_record(self, serial: Any) -> None:
        if self._is_serial(serial):
            with self._lock:
                if self.record_serial is None or serial > self.record_serial:
                    self.record_serial = serial

    def advance_key_record(self, serial: Any) -> None:
        if self._is_serial(serial):
            with self._lock:
                if self.key_record_serial is None or serial > self.key_record_serial:
                    self.key_record_serial = serial


class Consumer:
    """Holds a target's trust material, replay cache and serial marks, and
    decides one call at a time."""

    def __init__(
        self,
        *,
        target_id: str,
        pinned_public_keys: Optional[Dict[str, Any]] = None,
        key_record_view: Optional[Dict[str, Any]] = None,
        key_record_source: Optional[Callable[[Optional[int]], Dict[str, Any]]] = None,
        record: Optional[Dict[str, Any]] = None,
        record_bytes: Optional[bytes] = None,
        pinned_root: Optional[str] = None,
        record_source: Optional[Callable[[Optional[int]], Dict[str, Any]]] = None,
        replay_cache=None,
        clock_skew: timedelta = timedelta(0),
        high_water: Optional[HighWater] = None,
        approver_public_keys: Optional[Dict[str, Any]] = None,
        executor_signing_key: Any = None,
        executor_key_id: Optional[str] = None,
    ) -> None:
        """The live pin comes from exactly one of `record` (a validated
        {policy_id, policy_sha256}), `record_bytes` (anchored on `pinned_root`,
        or on its own bytes when that is omitted) or `record_source` (called
        with the highest serial seen). Issuer-key trust comes from
        `pinned_public_keys` (a static pin), `key_record_view` (a validated
        view, never re-validated: the caller owns its refresh) or
        `key_record_source` (called with the highest serial seen; prefer it);
        a view and a source together is a configuration error, and no trust
        at all is one too. Approver trust, needed only for flagged receipts,
        comes from a key record's `approver`-role keys when a key-record view
        or source is in use, else from the static `approver_public_keys`
        map. `executor_signing_key` and `executor_key_id`, both or neither,
        let attest() sign execution receipts (gargoyle.execution)."""
        supplied = [x is not None for x in (record, record_bytes, record_source)]
        if sum(supplied) != 1:
            raise ValueError("supply exactly one of record, record_bytes or record_source")
        if key_record_view is not None and key_record_source is not None:
            raise ValueError("supply key_record_view OR key_record_source, not both")
        if (pinned_public_keys is None and key_record_view is None
                and key_record_source is None):
            raise ValueError(
                "supply issuer-key trust: pinned_public_keys, key_record_view "
                "or key_record_source"
            )
        if clock_skew < timedelta(0):
            raise ValueError("clock_skew must be non-negative")
        if (executor_signing_key is None) != (executor_key_id is None):
            raise ValueError("supply executor_signing_key and executor_key_id together")
        self._executor_signing_key = executor_signing_key
        self.executor_key_id = executor_key_id
        self.target_id = target_id
        self.pinned_public_keys = pinned_public_keys
        self.key_record_view = key_record_view
        self._key_record_source = key_record_source
        self._record = record
        self._record_bytes = record_bytes
        self._pinned_root = (
            pinned_root
            if pinned_root is not None or record_bytes is None
            else anchor_sha256(record_bytes)
        )
        self._record_source = record_source
        self.replay_cache = replay_cache if replay_cache is not None else InMemoryReplayCache()
        self.clock_skew = clock_skew
        self.high_water = high_water if high_water is not None else HighWater()
        self.approver_public_keys = approver_public_keys

    # ----- the live policy pin -----

    def _resolve_record(self) -> Verdict | Dict[str, Any]:
        """The validated record, or the Verdict refusing the call."""
        if self._record is not None:
            return self._record
        if self._record_bytes is not None:
            record = load_record_from_bytes(self._record_bytes, self._pinned_root)
            return record if record is not None else Verdict(False, REF_TARGET_ANCHOR_MISMATCH)
        try:
            res = self._record_source(self.high_water.record_serial)
        except Exception:
            return Verdict(False, REF_VERIFY_PUBLISHED_RECORD_INVALID)
        record = res.get("record") if isinstance(res, dict) else None
        if not isinstance(record, dict):
            reason = res.get("reason") if isinstance(res, dict) else None
            return Verdict(False, reason or REF_TARGET_ANCHOR_MISMATCH)
        self.high_water.advance_record(record.get("serial"))
        return record

    # ----- the trusted issuer keys -----

    def _resolve_key_record_view(self) -> Verdict | Optional[Dict[str, Any]]:
        """The key-record trust view (None when trust is a static pin), or
        the Verdict refusing the call."""
        if self._key_record_source is None:
            return self.key_record_view
        try:
            kres = self._key_record_source(self.high_water.key_record_serial)
        except Exception:
            return Verdict(False, REF_VERIFY_KEY_RECORD_INVALID)
        view = kres.get("trust_view") if isinstance(kres, dict) else None
        if view is None:
            reason = kres.get("reason") if isinstance(kres, dict) else None
            return Verdict(False, reason or REF_VERIFY_KEY_RECORD_INVALID)
        self.high_water.advance_key_record(kres.get("serial"))
        return view

    @property
    def attests(self) -> bool:
        """True when this consumer can sign execution receipts."""
        return self._executor_signing_key is not None

    def attest(self, envelope: Dict[str, Any], outputs: Any,
               executed_at: Optional[datetime] = None) -> Dict[str, Any]:
        """The signed execution receipt for a call this consumer honored and
        the caller has just run with `outputs`. Raises when no executor key
        is configured: an unsigned statement of execution is not evidence."""
        if not self.attests:
            raise ValueError("this consumer has no executor signing key; cannot attest")
        execution = build_execution_receipt(envelope=envelope, outputs=outputs, executed_at=executed_at)
        return sign_execution_receipt(execution, self._executor_signing_key, self.executor_key_id)

    def _approver_keys(self, key_record_view, gate_key_id, now) -> Dict[str, Any]:
        """The approver map for a flagged receipt: from the key record when
        one is in use (only its `approver`-role keys, unrevoked, in window),
        else the static map."""
        if key_record_view is not None:
            return resolve_approver_keys(key_record_view, gate_key_id=gate_key_id,
                                         now=now, clock_skew=self.clock_skew)
        return dict(self.approver_public_keys or {})

    def check(
        self,
        envelope: Any,
        call: Dict[str, Any],
        *,
        grant: Any = None,
        now: Optional[datetime] = None,
    ) -> Verdict:
        """Decide whether to honor `envelope` for `call` ({"tool", "args",
        "principal"}, the principal being the one this consumer
        authenticated), with `grant` the human's release presented alongside
        a flagged receipt (None when none was). Fail-closed on every
        undecidable path; the caller performs the side effect only when
        honored is True."""
        if not isinstance(envelope, dict):
            envelope = None  # absent or not an object: verify_envelope refuses

        record = self._resolve_record()
        if isinstance(record, Verdict):
            return record
        key_record_view = self._resolve_key_record_view()
        if isinstance(key_record_view, Verdict):
            return key_record_view

        # The signature check always runs: an empty map (not None) satisfies
        # verify_envelope's key requirement when the key record is the source.
        pinned_public_keys = (
            self.pinned_public_keys if self.pinned_public_keys is not None else {}
        )
        result = verify_envelope(
            envelope,
            call,
            self.target_id,
            record_source=record,
            pinned_public_keys=pinned_public_keys,
            now=now,
            key_record_view=key_record_view,
            clock_skew=self.clock_skew,
        )
        if not result["accepted"]:
            return Verdict(False, result["reason"])

        # Single use. decision_id is signed, so it cannot be altered once the
        # signature verified. A receipt without one is refused, never "no id,
        # so skip the check".
        decision_id = envelope.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id:
            return Verdict(False, REF_TARGET_NO_DECISION_ID)

        # A flagged receipt: the human-held key is required here, at the
        # point of execution. requires_approval and approval_request_id are
        # inside the signed region, so they are the issuer's word, not the
        # caller's. The grant is checked and claimed before the receipt is
        # claimed, so a refused grant leaves the receipt unspent.
        if envelope["requires_approval"]:
            if grant is None:
                return Verdict(False, REF_TARGET_APPROVAL_REQUIRED)
            approver_keys = self._approver_keys(key_record_view, envelope.get("issuer_key_id"), now)
            if not approver_keys:
                return Verdict(False, REF_TARGET_NO_APPROVER_TRUST)
            g = verify_grant(
                grant,
                expected_decision_sha256=envelope["decision_sha256"],
                expected_approval_request_id=envelope["approval_request_id"],
                approver_public_keys=approver_keys,
                gate_key_id=envelope.get("issuer_key_id"),
                now=now,
                clock_skew=self.clock_skew,
            )
            if not g["accepted"]:
                return Verdict(False, g["reason"])
            grant_exp = None
            try:
                grant_exp = datetime.fromisoformat(grant["not_after"]) + self.clock_skew
            except (ValueError, TypeError, KeyError):
                grant_exp = None
            if not self.replay_cache.check_and_claim(
                    _GRANT_CLAIM_PREFIX + grant["grant_id"], grant_exp, now=now):
                return Verdict(False, REF_APPROVAL_REPLAY)
        # Keep the claim for the whole window the verifier honors: it accepts
        # until not_after + clock_skew, so expiring the claim at the bare
        # not_after would let the id be claimed again inside the skew.
        exp = _parse_not_after(envelope)
        if exp is not None:
            exp = exp + self.clock_skew
        if not self.replay_cache.check_and_claim(decision_id, exp, now=now):
            return Verdict(False, REF_VERIFY_REPLAY)

        return Verdict(True, result["reason"])


# ---------------------------------------------------------------------------
# The reference target
# ---------------------------------------------------------------------------
#
# Configuration (environment, never the repository):
#
#   GARGOYLE_TARGET_URL          the URL this target serves; a receipt's
#                                target_url must equal it.
#   GARGOYLE_PUBLISHER_URL       where the published record (the live policy
#                                pin, {policy_id, policy_sha256}) is fetched.
#   GARGOYLE_PINNED_ROOT_SHA256  sha256 of the authentic published-record
#                                bytes, distributed out of band and never
#                                fetched with the record (that would be
#                                circular).
#   GARGOYLE_GATE_KEY_ID         the pinned issuer key id.
#   GARGOYLE_GATE_PUBLIC_KEY_HEX the pinned issuer public key, raw Ed25519
#                                bytes as hex.
#   GARGOYLE_PRINCIPAL_SOURCE    how the caller is authenticated:
#                                  "xfcc"   (default) the client certificate the
#                                           TLS-terminating proxy verified, from
#                                           its X-Forwarded-Client-Cert header
#                                           (the URI SAN, else the Subject);
#                                  "header" the identity header named below.
#   GARGOYLE_PRINCIPAL_HEADER    with "header": the header a trusted front
#                                proxy sets to the authenticated identity (a
#                                bearer token's subject, for example).
#                                In either mode the proxy must strip any
#                                client-supplied copy of the header; nothing
#                                here can check that. Without a usable
#                                source, and without an injected
#                                principal_resolver, every call is refused.
#   GARGOYLE_APPROVER_KEY_ID / GARGOYLE_APPROVER_PUBLIC_KEY_HEX
#                                a pinned approver key, so flagged receipts
#                                can be honored with that approver's grant.
#                                Optional; in key-record mode the record's
#                                approver-role keys are used instead.
#   GARGOYLE_EXECUTOR_KEY_ID / GARGOYLE_EXECUTOR_KEY_HEX
#                                this target's own Ed25519 signing key (raw
#                                private bytes as hex, never logged), so each
#                                honored call is answered with a signed
#                                execution receipt. Optional, both or neither.
#
# Optional: GARGOYLE_PUBLISHER_KEY_ID / _KEY_HEX + GARGOYLE_SIGNED_RECORD_URL
# for signed-record mode (freshness and serial instead of a byte anchor),
# GARGOYLE_KEY_RECORD_URL / _ROOT_ID / _ROOT_HEX for signed key-record mode
# (revocation and validity windows instead of the static issuer pin),
# GARGOYLE_CLOCK_SKEW_SECONDS for cross-host skew. Distributing the anchor
# and key pins securely, and making sure the principal header can only come
# from the proxy, is the deployer's problem and is not addressed here.

ENV_TARGET_URL = "GARGOYLE_TARGET_URL"
ENV_PUBLISHER_URL = "GARGOYLE_PUBLISHER_URL"
ENV_PINNED_ROOT = "GARGOYLE_PINNED_ROOT_SHA256"
ENV_GATE_KEY_ID = "GARGOYLE_GATE_KEY_ID"
ENV_GATE_PUBLIC_KEY_HEX = "GARGOYLE_GATE_PUBLIC_KEY_HEX"
ENV_PRINCIPAL_SOURCE = "GARGOYLE_PRINCIPAL_SOURCE"
ENV_PRINCIPAL_HEADER = "GARGOYLE_PRINCIPAL_HEADER"
XFCC_HEADER = "x-forwarded-client-cert"
ENV_APPROVER_KEY_ID = "GARGOYLE_APPROVER_KEY_ID"
ENV_APPROVER_PUBLIC_KEY_HEX = "GARGOYLE_APPROVER_PUBLIC_KEY_HEX"
ENV_EXECUTOR_KEY_ID = "GARGOYLE_EXECUTOR_KEY_ID"
ENV_EXECUTOR_KEY_HEX = "GARGOYLE_EXECUTOR_KEY_HEX"
ENV_PUBLISHER_KEY_ID = "GARGOYLE_PUBLISHER_KEY_ID"
ENV_PUBLISHER_KEY_HEX = "GARGOYLE_PUBLISHER_KEY_HEX"
ENV_SIGNED_RECORD_URL = "GARGOYLE_SIGNED_RECORD_URL"
ENV_KEY_RECORD_URL = "GARGOYLE_KEY_RECORD_URL"
ENV_KEY_RECORD_ROOT_ID = "GARGOYLE_KEY_RECORD_ROOT_ID"
ENV_KEY_RECORD_ROOT_HEX = "GARGOYLE_KEY_RECORD_ROOT_HEX"
ENV_CLOCK_SKEW_SECONDS = "GARGOYLE_CLOCK_SKEW_SECONDS"


def config_from_env() -> Optional[Dict[str, Any]]:
    """Resolve the target's configuration from the environment.

    Returns {"target_url", "publisher_url", "pinned_root_sha256",
    "pinned_public_keys": {key_id: Ed25519PublicKey}, ...optional modes}, or
    None when a required value is missing or any key material is malformed.
    None makes every request refuse with REF_TARGET_NOT_CONFIGURED. A partial
    optional mode (some of its settings but not all) is None too; nothing
    silently falls back to the weaker mode. cryptography is imported lazily
    so importing this module does not need it.
    """
    target_url = os.environ.get(ENV_TARGET_URL)
    publisher_url = os.environ.get(ENV_PUBLISHER_URL)
    pinned_root = os.environ.get(ENV_PINNED_ROOT)
    key_id = os.environ.get(ENV_GATE_KEY_ID)
    key_hex = os.environ.get(ENV_GATE_PUBLIC_KEY_HEX)
    if not (target_url and publisher_url and pinned_root and key_id and key_hex):
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
    except Exception:
        return None
    config = {
        "target_url": target_url,
        "publisher_url": publisher_url,
        "pinned_root_sha256": pinned_root,
        "pinned_public_keys": {key_id: public_key},
    }
    principal_source = (os.environ.get(ENV_PRINCIPAL_SOURCE) or "xfcc").strip().lower()
    if principal_source not in ("xfcc", "header"):
        return None
    config["principal_source"] = principal_source
    principal_header = os.environ.get(ENV_PRINCIPAL_HEADER)
    if principal_header:
        config["principal_header"] = principal_header
    ap_key_id = os.environ.get(ENV_APPROVER_KEY_ID)
    ap_key_hex = os.environ.get(ENV_APPROVER_PUBLIC_KEY_HEX)
    if ap_key_id or ap_key_hex:
        if not (ap_key_id and ap_key_hex):
            return None
        try:
            config["approver_public_keys"] = {
                ap_key_id: Ed25519PublicKey.from_public_bytes(bytes.fromhex(ap_key_hex))
            }
        except Exception:
            return None
    ex_key_id = os.environ.get(ENV_EXECUTOR_KEY_ID)
    ex_key_hex = os.environ.get(ENV_EXECUTOR_KEY_HEX)
    if ex_key_id or ex_key_hex:
        if not (ex_key_id and ex_key_hex):
            return None
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            config["executor_signing_key"] = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ex_key_hex))
            config["executor_key_id"] = ex_key_id
        except Exception:
            return None
    pub_key_id = os.environ.get(ENV_PUBLISHER_KEY_ID)
    pub_key_hex = os.environ.get(ENV_PUBLISHER_KEY_HEX)
    if pub_key_id and pub_key_hex:
        try:
            publisher_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_key_hex))
        except Exception:
            return None
        signed_record_url = os.environ.get(ENV_SIGNED_RECORD_URL)
        if not signed_record_url:
            return None  # signed mode names its record URL; nothing is guessed
        config["pinned_publisher_keys"] = {pub_key_id: publisher_key}
        config["signed_record_url"] = signed_record_url
    kr_url = os.environ.get(ENV_KEY_RECORD_URL)
    kr_root_id = os.environ.get(ENV_KEY_RECORD_ROOT_ID)
    kr_root_hex = os.environ.get(ENV_KEY_RECORD_ROOT_HEX)
    if kr_url or kr_root_id or kr_root_hex:
        if not (kr_url and kr_root_id and kr_root_hex):
            return None
        try:
            root_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(kr_root_hex))
        except Exception:
            return None
        config["key_record_url"] = kr_url
        config["pinned_key_record_roots"] = {kr_root_id: root_key}
    return config


def _clock_skew_seconds() -> float:
    """Configured clock-skew tolerance in seconds (default 0). It widens the
    freshness window and replay-cache retention together, so a receipt cannot
    outlive its replay record."""
    try:
        return float(os.environ.get(ENV_CLOCK_SKEW_SECONDS, "0") or "0")
    except ValueError:
        return 0.0


def _refuse(reason: str) -> HTTPException:
    return HTTPException(
        status_code=403,
        detail={"honored": False, "reason": reason},
    )


def principal_from_header(request: Request, config: Dict[str, Any]) -> Optional[str]:
    """The default principal resolver: the one non-empty value of the header
    named by config["principal_header"]. No configured header, an absent or
    empty value, or more than one value (ambiguous) is None: unauthenticated.
    The header is trusted only because the deployment's front proxy sets it
    and strips any client-supplied copy; this function cannot check that."""
    name = config.get("principal_header")
    if not isinstance(name, str) or not name:
        return None
    values = request.headers.getlist(name)
    if len(values) != 1:
        return None
    value = values[0].strip()
    return value or None


def _xfcc_elements(value: str):
    """Split an X-Forwarded-Client-Cert value into its per-hop elements, each
    a dict of key -> value. Values may be double-quoted (a Subject DN with
    commas is); a quoted value keeps its inner text."""
    elements, i, n = [], 0, len(value)
    while i <= n:
        current, pairs = {}, []
        # one element: key=value;key="quoted, value";...
        while i < n and value[i] != ",":
            j = value.find("=", i)
            if j < 0:
                i = n
                break
            key = value[i:j].strip()
            i = j + 1
            if i < n and value[i] == '"':
                k = value.find('"', i + 1)
                if k < 0:
                    return elements  # unterminated quote: stop, trust nothing further
                val, i = value[i + 1:k], k + 1
            else:
                k = i
                while k < n and value[k] not in ";,":
                    k += 1
                val, i = value[i:k].strip(), k
            if key:
                current[key] = val
            if i < n and value[i] == ";":
                i += 1
        if current:
            elements.append(current)
        i += 1
    return elements


def principal_from_xfcc(request: Request, config: Dict[str, Any]) -> Optional[str]:
    """Transport authentication: the client certificate the front proxy
    verified, as Envoy reports it in X-Forwarded-Client-Cert. The last
    element is the immediate downstream the proxy itself authenticated. The
    principal is its URI SAN (a SPIFFE id, for example), else its Subject.
    Absent or duplicated header, no last element, or neither field: None.
    This is only transport authentication if the proxy requires and
    verifies client certificates and never forwards a client-supplied copy
    of the header (Envoy: forward_client_cert_details SANITIZE_SET)."""
    values = request.headers.getlist(XFCC_HEADER)
    if len(values) != 1:
        return None
    elements = _xfcc_elements(values[0])
    if not elements:
        return None
    last = elements[-1]
    for key in ("URI", "Subject"):
        value = last.get(key, "").strip()
        if value:
            return value
    return None


def default_principal_resolver(request: Request, config: Dict[str, Any]) -> Optional[str]:
    """The configured source: the proxy-verified client certificate (xfcc)
    or a proxy-set identity header. An explicit principal_source wins; a
    config that names only a principal_header means header mode; otherwise
    xfcc."""
    source = config.get("principal_source")
    if source is None:
        source = "header" if config.get("principal_header") else "xfcc"
    if source == "header":
        return principal_from_header(request, config)
    return principal_from_xfcc(request, config)


def _call_from_body(body: Any, principal: str) -> Optional[Dict[str, Any]]:
    """The call the receipt must bind: tool and args from the body (exactly
    those two keys, or the body is not a call), principal from the target's
    own authentication. None is refused by the verifier."""
    if not isinstance(body, dict) or set(body.keys()) != {"tool", "args"}:
        return None
    return {"tool": body["tool"], "args": body["args"], "principal": principal}


def build_reference_target_app(
    config_provider: Callable[[], Optional[Dict[str, Any]]] = config_from_env,
    fetch: Callable[..., Optional[Dict[str, Any]]] = fetch_published_record,
    signed_fetch: Callable[..., Dict[str, Any]] = fetch_signed_record,
    replay_cache=None,
    key_record_fetch: Callable[..., Dict[str, Any]] = fetch_key_record,
    principal_resolver: Optional[Callable[[Request, Dict[str, Any]], Optional[str]]] = None,
) -> FastAPI:
    """Build the reference target ASGI app.

    On every POST /target it resolves its configuration (config_provider
    runs per request, so a misconfigured deployment refuses each request
    with REF_TARGET_NOT_CONFIGURED instead of failing to boot), authenticates
    the caller (principal_resolver(request, config), default
    default_principal_resolver: the proxy-verified client certificate, or a
    proxy-set header; nobody -> REF_TARGET_NO_PRINCIPAL before anything
    else), reads the call from the body (exactly {"tool", "args"}) and the
    receipt from the X-Gargoyle-Envelope header (absent, duplicated or
    unparseable -> no receipt), and hands them to a Consumer built from the
    configuration. The fetchers are injectable for tests; the replay cache
    and the serial high-water marks are shared across requests on app.state.

    Every call the target acts on is appended to app.state.received; a
    refused call never is, so tests can assert it acted exactly once.
    """
    app = FastAPI(title="Gargoyle reference enforcing target")
    app.state.received = []
    app.state.replay_cache = replay_cache if replay_cache is not None else InMemoryReplayCache()
    app.state.high_water = HighWater()
    resolve_principal = principal_resolver or default_principal_resolver

    def consumer_for(config: Dict[str, Any], skew: timedelta) -> Consumer:
        # The published record: signed mode checks the publisher signature,
        # freshness and serial; anchor mode only checks the bytes against the
        # pinned hash, which says nothing about age. The fetchers block, so
        # the consumer runs on the thread pool (see below).
        if config.get("pinned_publisher_keys"):
            def record_source(last_seen_serial):
                return signed_fetch(config["signed_record_url"],
                                    config["pinned_publisher_keys"], None, last_seen_serial)
        else:
            def record_source(last_seen_serial):
                return {"record": fetch(config["publisher_url"], config["pinned_root_sha256"]),
                        "reason": REF_TARGET_ANCHOR_MISMATCH}
        # Signed key-record mode: the record's trust view replaces the static
        # pin, so revocation and validity windows are enforced per request.
        key_record_source = None
        if config.get("pinned_key_record_roots"):
            def key_record_source(last_seen_serial):
                return key_record_fetch(config["key_record_url"],
                                        config["pinned_key_record_roots"],
                                        last_seen_serial=last_seen_serial, clock_skew=skew)
        return Consumer(
            target_id=config["target_url"],
            pinned_public_keys=config["pinned_public_keys"],
            key_record_source=key_record_source,
            record_source=record_source,
            replay_cache=app.state.replay_cache,
            clock_skew=skew,
            high_water=app.state.high_water,
            approver_public_keys=config.get("approver_public_keys"),
            executor_signing_key=config.get("executor_signing_key"),
            executor_key_id=config.get("executor_key_id"),
        )

    def header_json(request: Request, name: str):
        """One header's JSON value, or None when absent, duplicated or
        unparseable: duplicates are ambiguous and count as absent."""
        if len(request.headers.getlist(name)) > 1:
            return None
        raw = request.headers.get(name)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None

    @app.post("/target")
    async def target(request: Request):
        config = config_provider()
        if config is None:
            raise _refuse(REF_TARGET_NOT_CONFIGURED)

        # Who is calling, as this target authenticated them. A resolver that
        # raises or returns anything but a non-empty string authenticates
        # nobody, and nobody gets nothing.
        try:
            principal = resolve_principal(request, config)
        except Exception:
            principal = None
        if not isinstance(principal, str) or not principal:
            raise _refuse(REF_TARGET_NO_PRINCIPAL)

        # The body carries the tool and arguments the receipt must bind; the
        # principal comes from above, never from the body. A non-JSON body or
        # a body that is not exactly {"tool", "args"} becomes None and is
        # refused by the verifier, never a 500.
        try:
            body = await request.json()
        except Exception:
            body = None
        call = _call_from_body(body, principal)

        envelope = header_json(request, ENVELOPE_HEADER)
        grant = header_json(request, GRANT_HEADER)

        skew = timedelta(seconds=_clock_skew_seconds())
        consumer = consumer_for(config, skew)
        # The fetchers block (requests), so keep them off the event loop.
        verdict = await run_in_threadpool(consumer.check, envelope, call, grant=grant)
        if not verdict.honored:
            raise _refuse(verdict.reason)

        app.state.received.append(call)  # the target acts only here
        outputs = {"executed": call["tool"], "args_sha256": envelope["request_context"]["args_sha256"]}
        response = {"honored": True, "reason": verdict.reason, "outputs": outputs}
        if consumer.attests:
            response["execution"] = consumer.attest(envelope, outputs)
        return response

    @app.get("/received")
    async def received():
        """Read-only count of calls the target has acted on, so a test over a
        real socket can confirm an honor without resending the receipt."""
        return {"count": len(app.state.received)}

    return app


# Module-level deployable app: resolves configuration from the environment per
# request. `uvicorn gargoyle.consumer:app` serves it.
app = build_reference_target_app(replay_cache=replay_cache_from_env())

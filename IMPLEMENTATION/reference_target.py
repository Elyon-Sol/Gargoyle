"""
Reference downstream enforcing target for Elyon-Sol
(docs/restructure/12_g5_transport_design.md step 4).

This is the standalone, deployable enforcing target that supersedes the
8-line IMPLEMENTATION/target.py stub. It promotes the embedded scaffolding -
the TARGET_DRIVER subprocess string in
EVIDENCE/proofs/g5_signed_cross_host_001_runner.py and the in-process
_build_cross_host_target_app / build_enforcing_target_app helpers in
TESTS/adversarial/test_cross_host.py and TESTS/adversarial/test_enforcement.py -
into one real service a deployer can run and an external attacker can point at.

==============================================================
What it does (the reference policy)
==============================================================

On every POST to /target the target, by its OWN policy, decides whether to
honor or refuse the call:

  1. Resolve out-of-band configuration (never from the repo): the URL this
     target serves (for the binding check), the publisher URL, the pinned
     published-record anchor, and the pinned gate signing public key.
     Incomplete / malformed configuration FAILS CLOSED
     (REF_TARGET_NOT_CONFIGURED) - the target refuses rather than act on an
     unconfigured trust base, the same per-request fail-closed posture pep.py
     takes when no signing key is configured.
  2. Read the X-Elyon-Sol-Envelope attestation header (absent / unparseable
     -> treated as no envelope). A direct, un-attested caller (adversary A1)
     therefore reaches step 4 with envelope=None and is refused there
     (REF_VERIFY_ENVELOPE_ABSENT). A1 is closed by THIS target's policy of
     requiring a valid attestation, NOT by the gate (verifier.py lines 67-72;
     artifact 08 section 4.4; artifact 12 step 4).
  3. Fetch the published record from the publisher and anchor-verify it
     against the pinned root (published_source.fetch_published_record). A
     transport failure, a non-200, or a record whose bytes do not hash to the
     pinned anchor returns None -> refuse (REF_TARGET_ANCHOR_MISMATCH) before
     any envelope currency claim is trusted (fail-closed, canon section 9).
  4. Call verifier.verify_envelope(envelope, interaction, target_url,
     record_source=<fetched record>, pinned_public_keys=<pinned gate key>).
     Because a pinned key is supplied, the issuer signature is REQUIRED and
     verified fail-closed BEFORE currency (the signed path; the production gate
     signs every default forward per VL-047). Currency is checked against the
     FETCHED record, not local disk (Decision C / D-b; VL-039). The interaction
     binding (request_context + target_url) closes same-state replay (A3).
     Honor (200, act) iff verify_envelope accepts; otherwise refuse (403) and
     do not act.

==============================================================
Reference policy, NOT authored-to-pass (the finish-line-(B) requirement)
==============================================================

The acceptance criterion is exactly "verify_envelope accepts against the
anchor-verified fetched record AND the pinned gate signature verifies." It is
not tuned to any author happy-path test vector: the target consults only its
out-of-band pins and the production verifier. This is the load-bearing property
for finish line (B) - a target an EXTERNAL attacker can point at must not be
calibrated to the author's vectors (artifact 12 sections 2, 4). Per GR-3, any
attack run in-loop against this target is characterization, not certification;
G5 CLOSED requires the external attacker (artifact 12 section 1).

==============================================================
No new canonical invariant (canon section 14)
==============================================================

The target verifies and acts or refuses; it does not decide admissibility and
it does not execute the gate's logic. Fetching a record and verifying an
envelope are verification I/O - the same posture published_source.py and
verifier.py already hold (artifact 08 section 5; transport.py header).

==============================================================
Out-of-band configuration (custody parallel to pep._get_signing_key and
transport.py's ELYON_TLS_* and the published-record anchor)
==============================================================

Resolved from the environment, never from the repo:

  ELYON_TARGET_URL          - the URL this target serves; the envelope's
                              target_url must equal it (binding).
  ELYON_PUBLISHER_URL       - where the published record is fetched.
  ELYON_PINNED_ROOT_SHA256  - the out-of-band published-record anchor (sha256
                              of the authentic published-record bytes),
                              distributed out-of-band, NEVER fetched alongside
                              the record (that would be circular;
                              published_source.py header lines 22-27).
  ELYON_GATE_KEY_ID         - the pinned gate signing key id.
  ELYON_GATE_PUBLIC_KEY_HEX - the pinned gate signing public key, raw Ed25519
                              public bytes as hex.

Secure distribution of the anchor and the public-key pin is itself the named G5
floor (Decision F; external_verification_readiness gate 5): acknowledged, not
defended here.

Build-then-wire (the project discipline since VL-025): this module adds a real
service with NO change to the gate's default path. pep.py does not import it;
the gate only POSTs to a target_url. Wiring the two-node harness to run THIS
target as node B (replacing the stub) is artifact 12 step 2.

Deploy:  uvicorn IMPLEMENTATION.reference_target:app --host 0.0.0.0 --port 9000
(with the ELYON_* environment configured out-of-band).

Ledger: VL-061 (T-G5-transport; artifact 12 step 4 reference enforcing target).
"""

import json
import os
import threading
from typing import Any, Callable, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from datetime import datetime, timezone, timedelta

from fastapi.concurrency import run_in_threadpool

from IMPLEMENTATION.published_source import fetch_published_record
from IMPLEMENTATION.verifier import verify_envelope, REF_VERIFY_REPLAY
from IMPLEMENTATION.published_record_source import fetch_signed_record
from IMPLEMENTATION.key_record_source import fetch_key_record
from IMPLEMENTATION.replay_cache import InMemoryReplayCache, replay_cache_from_env


# Target-layer reason vocabulary (REF_TARGET_*; parallels the REF_VERIFY_* layer
# owned by verifier.py and the REF_SCHEMA_* layer owned by
# request_validator.py). Two codes the target itself emits; every other refusal
# reason is the REF_VERIFY_* code verify_envelope returns, surfaced unchanged.
# REF_TARGET_ANCHOR_MISMATCH matches the name used by the scaffolding this module
# promotes (TESTS/adversarial/test_cross_host.py;
# EVIDENCE/proofs/g5_signed_cross_host_001_runner.py).
REF_TARGET_NOT_CONFIGURED = "REF_TARGET_NOT_CONFIGURED"
REF_TARGET_ANCHOR_MISMATCH = "REF_TARGET_ANCHOR_MISMATCH"
# F2 fix: forwarded envelope without a decision_id cannot be single-use-enforced.
REF_TARGET_NO_DECISION_ID = "REF_TARGET_NO_DECISION_ID"

# The attestation header the gate pushes on its ELIGIBLE forward
# (pep.py line 280; canonical_json of the signed envelope).
ENVELOPE_HEADER = "X-Elyon-Sol-Envelope"

# Out-of-band configuration environment variable names.
ENV_TARGET_URL = "ELYON_TARGET_URL"
ENV_PUBLISHER_URL = "ELYON_PUBLISHER_URL"
ENV_PINNED_ROOT = "ELYON_PINNED_ROOT_SHA256"
ENV_GATE_KEY_ID = "ELYON_GATE_KEY_ID"
ENV_GATE_PUBLIC_KEY_HEX = "ELYON_GATE_PUBLIC_KEY_HEX"
# Optional signed-record (freshness) mode (VL-091, wiring B1). When a pinned publisher
# key is present the target consults the SIGNED record (freshness-checked) instead of
# the byte-anchor record. Absent, the byte-anchor path is unchanged.
ENV_PUBLISHER_KEY_ID = "ELYON_PUBLISHER_KEY_ID"
ENV_PUBLISHER_KEY_HEX = "ELYON_PUBLISHER_KEY_HEX"
ENV_SIGNED_RECORD_URL = "ELYON_SIGNED_RECORD_URL"
# Optional SIGNED KEY-RECORD mode (SES-9a / K-01, VL-110; parity with the
# ELYON_PUBLISHER_* signed-hash-record block above). When ALL THREE are present
# the target resolves the GATE issuer key from the publisher-signed key record
# (fetched + validated per request; issuer-key revocation + validity window are
# then ENFORCED via the verifier's record-exclusive key_record_view branch,
# VL-042) instead of the static ELYON_GATE_* pin. The ROOT public key is the
# out-of-band pin (never fetched alongside the record - that would be
# circular). Absent -> the static-pin path, byte-behavior-unchanged. A
# PARTIALLY-set trio is a configuration error -> fail closed
# (REF_TARGET_NOT_CONFIGURED).
ENV_KEY_RECORD_URL = "ELYON_KEY_RECORD_URL"
ENV_KEY_RECORD_ROOT_ID = "ELYON_KEY_RECORD_ROOT_ID"
ENV_KEY_RECORD_ROOT_HEX = "ELYON_KEY_RECORD_ROOT_HEX"


def config_from_env() -> Optional[Dict[str, Any]]:
    """
    Resolve the target's out-of-band configuration from the environment.

    Returns a config dict on success:
        {"target_url", "publisher_url", "pinned_root_sha256",
         "pinned_public_keys": {key_id: Ed25519PublicKey}}
    or None if any required value is absent or the pinned public-key material is
    malformed. None is the caller's signal to fail closed
    (REF_TARGET_NOT_CONFIGURED): an unconfigured or mis-keyed target must not
    act. cryptography is imported lazily so this module stays import-clean
    (matching pep._get_signing_key and the envelope / verifier duck-typing).
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
    # Optional signed-record (freshness) mode: pin a publisher key + a signed-record URL.
    pub_key_id = os.environ.get(ENV_PUBLISHER_KEY_ID)
    pub_key_hex = os.environ.get(ENV_PUBLISHER_KEY_HEX)
    if pub_key_id and pub_key_hex:
        try:
            publisher_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_key_hex))
        except Exception:
            return None
        config["pinned_publisher_keys"] = {pub_key_id: publisher_key}
        config["signed_record_url"] = os.environ.get(ENV_SIGNED_RECORD_URL) or \
            publisher_url.replace("published_hashes.json", "published_hashes_signed.json")
    # Optional SIGNED KEY-RECORD mode (SES-9a): pin a key-record ROOT public key
    # + a key-record URL. ALL THREE or NONE: a partially-set trio, like a
    # malformed root key, is a configuration error -> None (fail closed,
    # REF_TARGET_NOT_CONFIGURED) - never a silent downgrade to the static pin.
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


def _refuse(reason: str) -> HTTPException:
    return HTTPException(
        status_code=403,
        detail={"honored": False, "reason": reason},
    )


def _clock_skew_seconds() -> float:
    """Configured clock-skew tolerance in seconds (default 0). F3 fix: widens BOTH
    the freshness window AND replay-cache retention together."""
    try:
        return float(os.environ.get("ELYON_CLOCK_SKEW_SECONDS", "0") or "0")
    except ValueError:
        return 0.0


def build_reference_target_app(
    config_provider: Callable[[], Optional[Dict[str, Any]]] = config_from_env,
    fetch: Callable[..., Optional[Dict[str, Any]]] = fetch_published_record,
    signed_fetch: Callable[..., Dict[str, Any]] = fetch_signed_record,
    replay_cache=None,
    key_record_fetch: Callable[..., Dict[str, Any]] = fetch_key_record,
) -> FastAPI:
    """
    Build the reference enforcing-target ASGI app.

    config_provider is called per request, so configuration (and tests that
    inject it) resolve at request time and a misconfigured deployment fails
    closed per request (REF_TARGET_NOT_CONFIGURED) rather than failing to boot -
    the same per-request fail-closed posture pep.py takes when no signing key is
    configured. fetch is injectable so tests can drive the published-record hop
    through a TestClient publisher; the default is the production cross-host
    fetch_published_record over a real socket.

    The acted-upon interactions are recorded on app.state.received (a list); a
    refused call never appends to it. This mirrors the `received` list the
    scaffolding targets expose, so a runner / test can assert the target acted
    exactly once on honor and never on refuse.
    """
    app = FastAPI(title="Elyon-Sol reference enforcing target")
    app.state.received = []
    # Replay defense via the VL-076 ReplayCache seam (wired VL-094): InMemoryReplayCache by
    # default (per-instance, byte-behaviour-identical to the prior inline seen-dict), or an
    # injected shared cache (e.g. Redis-backed) for cross-instance exactly-once.
    app.state.replay_cache = replay_cache if replay_cache is not None else InMemoryReplayCache()
    # SES-8: monotonic serial high-water mark for the SIGNED published record, so a
    # rolled-back but still-fresh record is refused (REF_VERIFY_PUBLISHED_RECORD_STALE)
    # instead of honored inside its not_after window. In-process (single instance); a
    # horizontally-scaled deployment shares it the same way it shares the replay cache.
    app.state.serial_lock = threading.Lock()
    app.state.last_seen_serial = None
    # SES-9a: separate monotonic high-water mark for the SIGNED KEY RECORD's
    # serial (parity with the SES-8 hash-record mark above), so a rolled-back
    # but still-fresh key record - one that could resurrect a since-revoked
    # gate key - is refused (REF_VERIFY_KEY_RECORD_STALE) instead of honored
    # inside its not_after window. Guarded by the same serial_lock.
    app.state.last_seen_key_record_serial = None

    @app.post("/target")
    async def target(request: Request):
        config = config_provider()
        if config is None:
            raise _refuse(REF_TARGET_NOT_CONFIGURED)

        # Body (the normalized interaction the gate forwards). A non-JSON body
        # from an adversary is tolerated as None: a present envelope is then
        # refused at the binding check, an absent one at the presence guard -
        # never a 500.
        try:
            interaction = await request.json()
        except Exception:
            interaction = None

        # P-01: a duplicate envelope header is ambiguous -> treat as absent (A1).
        raw = (None if len(request.headers.getlist(ENVELOPE_HEADER)) > 1
               else request.headers.get(ENVELOPE_HEADER))
        envelope = None
        if raw is not None:
            try:
                envelope = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                envelope = None  # unparseable header -> treated as absent (A1)

        # Published-record fetch, off the event loop (blocking requests.get).
        # SIGNED mode (VL-091, wiring B1): a pinned publisher key is configured, so
        # fetch the SIGNED record and validate publisher signature + FRESHNESS +
        # serial; a stale/invalid record fails closed with the reader's reason
        # (REF_VERIFY_PUBLISHED_RECORD_STALE / _INVALID) - this closes A3b sub-case
        # (b). BYTE-ANCHOR mode (no publisher key, every existing runner/test): the
        # unchanged anchor-verified fetch (no temporal dimension). The validated
        # signed record carries the three currency pins, so it is a drop-in
        # record_source for verify_envelope either way.
        if config.get("pinned_publisher_keys"):
            # SES-8: pass the highest serial seen so a lower-serial (rolled-back)
            # record is refused as STALE even while still inside its not_after window.
            with app.state.serial_lock:
                _lss = app.state.last_seen_serial
            res = await run_in_threadpool(
                signed_fetch, config["signed_record_url"],
                config["pinned_publisher_keys"], None, _lss,
            )
            if res["reason"] is not None:
                raise _refuse(res["reason"])
            record = res["record"]
            _s = record.get("serial") if isinstance(record, dict) else None
            if isinstance(_s, int) and not isinstance(_s, bool):
                with app.state.serial_lock:
                    if (app.state.last_seen_serial is None
                            or _s > app.state.last_seen_serial):
                        app.state.last_seen_serial = _s
        else:
            record = await run_in_threadpool(
                fetch, config["publisher_url"], config["pinned_root_sha256"]
            )
            if record is None:
                raise _refuse(REF_TARGET_ANCHOR_MISMATCH)

        skew = timedelta(seconds=_clock_skew_seconds())

        # SIGNED KEY-RECORD mode (SES-9a / K-01): a key-record root is pinned,
        # so fetch + validate the publisher-signed KEY record per request (the
        # same cadence as the signed hash record above) and hand the validated
        # trust view to the verifier, which then enforces issuer-key
        # revocation + validity window (record-exclusive, VL-042) before the
        # signature check - a compromised gate key is revoked IN-BAND by
        # flipping `revoked` in one signed record instead of re-pinning every
        # consumer out-of-band. A stale/invalid/transport-failed key record
        # fails CLOSED with the reader's REF_VERIFY_KEY_RECORD_* reason - never
        # a downgrade to the static pin. Absent (default), key_record_view
        # stays None and the static-pin path is byte-behavior-unchanged.
        key_record_view = None
        if config.get("pinned_key_record_roots"):
            with app.state.serial_lock:
                _klss = app.state.last_seen_key_record_serial
            kres = await run_in_threadpool(
                key_record_fetch, config["key_record_url"],
                config["pinned_key_record_roots"],
                last_seen_serial=_klss, clock_skew=skew,
            )
            if kres.get("trust_view") is None:
                raise _refuse(kres["reason"])
            key_record_view = kres["trust_view"]
            _ks = kres.get("serial")
            if isinstance(_ks, int) and not isinstance(_ks, bool):
                with app.state.serial_lock:
                    if (app.state.last_seen_key_record_serial is None
                            or _ks > app.state.last_seen_key_record_serial):
                        app.state.last_seen_key_record_serial = _ks

        # The production verifier is the SOLE acceptance authority. A pinned
        # gate key is supplied, so the issuer signature is required and checked
        # fail-closed before currency (the signed path); in signed key-record
        # mode the key_record_view SUPERSEDES the static pin (record-exclusive).
        # Currency is checked against the FETCHED record; the binding closes
        # same-state replay.
        result = verify_envelope(
            envelope,
            interaction,
            config["target_url"],
            record_source=record,
            pinned_public_keys=config["pinned_public_keys"],
            key_record_view=key_record_view,
            clock_skew=skew,
        )
        if not result["accepted"]:
            raise _refuse(result["reason"])

        # Replay defense (exactly-once over the freshness window): refuse a decision_id
        # already honored. decision_id is in the signed region (tamper-proof) and is
        # stamped by the default gate forward. The cache is the VL-076 seam (wired VL-094):
        # InMemoryReplayCache per-instance by default, or a SHARED store (e.g. Redis) for
        # cross-instance exactly-once on a horizontally-scaled executor. check_and_claim
        # prunes expired entries, refuses an already-claimed id, and claims a fresh one.
        decision_id = envelope.get("decision_id")
        if decision_id is None:
            # F2 fix: no decision_id -> single-use cannot be enforced -> fail closed.
            raise _refuse(REF_TARGET_NO_DECISION_ID)
        exp = None
        na = envelope.get("not_after")
        if isinstance(na, str):
            try:
                exp = datetime.fromisoformat(na) + skew  # F3: retain through honored window
            except ValueError:
                exp = None
        if not app.state.replay_cache.check_and_claim(decision_id, exp):
            raise _refuse(REF_VERIFY_REPLAY)

        app.state.received.append(interaction)  # the target acts only here
        return {"honored": True, "reason": result["reason"]}

    @app.get("/received")
    async def received():
        """Observability (read-only): how many calls the target has acted on.

        Lets a multi-process / real-transport runner confirm an honor verdict over
        a real socket without redelivering the envelope. Not part of the admission
        policy and not a trust surface; it discloses only an integer count.
        """
        return {"count": len(app.state.received)}

    return app


# Module-level deployable app: resolves configuration from the environment per
# request. `uvicorn IMPLEMENTATION.reference_target:app` serves it.
app = build_reference_target_app(replay_cache=replay_cache_from_env())

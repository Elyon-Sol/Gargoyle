"""A reference target that only acts on calls carrying a valid receipt.

On every POST /target it:

  1. Resolves its configuration from the environment, per request. Missing
     or malformed configuration refuses (REF_TARGET_NOT_CONFIGURED) rather
     than acting on an unconfigured trust base.
  2. Reads the receipt from the X-Gargoyle-Envelope header. An absent,
     duplicated or unparseable header means no receipt, so an unattested
     caller is refused by verify_envelope (REF_VERIFY_ENVELOPE_ABSENT). This
     target's policy of requiring a receipt is what stops a caller who skips
     the issuer; the issuer cannot.
  3. Fetches the published record (the live policy pin) and checks it
     against a pinned anchor, or, in signed-record mode, checks the
     publisher's signature, freshness and serial. Any failure refuses before
     a receipt is trusted.
  4. Calls verify_envelope with the fetched record and the pinned issuer key
     (or the signed key record), so the signature is required and checked
     first, currency is checked against the record rather than local files,
     and the receipt must bind exactly this call.
  5. Claims the receipt's decision_id in the replay cache, so it acts at
     most once per receipt.

Acceptance depends only on the out-of-band pins and the verifier, never on
anything tuned to particular test inputs.

Configuration (environment, never the repository):

  GARGOYLE_TARGET_URL          the URL this target serves; a receipt's
                               target_url must equal it.
  GARGOYLE_PUBLISHER_URL       where the published record is fetched.
  GARGOYLE_PINNED_ROOT_SHA256  sha256 of the authentic published-record
                               bytes, distributed out of band and never
                               fetched with the record (that would be
                               circular).
  GARGOYLE_GATE_KEY_ID         the pinned issuer key id.
  GARGOYLE_GATE_PUBLIC_KEY_HEX the pinned issuer public key, raw Ed25519
                               bytes as hex.

Optional: GARGOYLE_PUBLISHER_KEY_ID / _KEY_HEX / GARGOYLE_SIGNED_RECORD_URL
for signed-record mode, GARGOYLE_KEY_RECORD_URL / _ROOT_ID / _ROOT_HEX for
signed key-record mode, GARGOYLE_CLOCK_SKEW_SECONDS for cross-host skew.
Distributing the anchor and key pins securely is the deployer's problem and
is not addressed here.

Run: uvicorn gargoyle.reference_target:app --host 0.0.0.0 --port 9000
"""

import json
import os
import threading
from typing import Any, Callable, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from datetime import datetime, timezone, timedelta

from fastapi.concurrency import run_in_threadpool

from gargoyle.published_source import fetch_published_record
from gargoyle.verifier import verify_envelope, REF_VERIFY_REPLAY
from gargoyle.published_record_source import fetch_signed_record
from gargoyle.key_record_source import fetch_key_record
from gargoyle.replay_cache import InMemoryReplayCache, replay_cache_from_env


# Refusals the target emits itself. Every other refusal is the REF_VERIFY_*
# code verify_envelope returned, passed through unchanged.
REF_TARGET_NOT_CONFIGURED = "REF_TARGET_NOT_CONFIGURED"
REF_TARGET_ANCHOR_MISMATCH = "REF_TARGET_ANCHOR_MISMATCH"
# A receipt without a decision_id cannot be held to single use.
REF_TARGET_NO_DECISION_ID = "REF_TARGET_NO_DECISION_ID"

# The header carrying the receipt as JSON (see gargoyle.issuer).
ENVELOPE_HEADER = "X-Gargoyle-Envelope"

# Out-of-band configuration environment variable names.
ENV_TARGET_URL = "GARGOYLE_TARGET_URL"
ENV_PUBLISHER_URL = "GARGOYLE_PUBLISHER_URL"
ENV_PINNED_ROOT = "GARGOYLE_PINNED_ROOT_SHA256"
ENV_GATE_KEY_ID = "GARGOYLE_GATE_KEY_ID"
ENV_GATE_PUBLIC_KEY_HEX = "GARGOYLE_GATE_PUBLIC_KEY_HEX"
# Optional signed-record mode: with a pinned publisher key, the target uses the
# publisher-signed record, which carries freshness and a serial, instead of the
# byte-anchored record.
ENV_PUBLISHER_KEY_ID = "GARGOYLE_PUBLISHER_KEY_ID"
ENV_PUBLISHER_KEY_HEX = "GARGOYLE_PUBLISHER_KEY_HEX"
ENV_SIGNED_RECORD_URL = "GARGOYLE_SIGNED_RECORD_URL"
# Optional signed key-record mode: when all three are set, the issuer key comes
# from a root-signed key record fetched and checked per request, so revocation
# and validity windows are enforced, instead of the static GARGOYLE_GATE_* pin.
# The root public key is the out-of-band pin (never fetched with the record).
# Setting only some of the three is a configuration error and refuses.
ENV_KEY_RECORD_URL = "GARGOYLE_KEY_RECORD_URL"
ENV_KEY_RECORD_ROOT_ID = "GARGOYLE_KEY_RECORD_ROOT_ID"
ENV_KEY_RECORD_ROOT_HEX = "GARGOYLE_KEY_RECORD_ROOT_HEX"


def config_from_env() -> Optional[Dict[str, Any]]:
    """Resolve the target's configuration from the environment.

    Returns {"target_url", "publisher_url", "pinned_root_sha256",
    "pinned_public_keys": {key_id: Ed25519PublicKey}, ...optional modes}, or
    None when a required value is missing or any key material is malformed.
    None makes every request refuse with REF_TARGET_NOT_CONFIGURED.
    cryptography is imported lazily so importing this module does not need it.
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
    # Optional signed key-record mode: all three settings or none. A partial
    # set or a malformed root key refuses; it never silently falls back to the
    # static pin.
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
    """Configured clock-skew tolerance in seconds (default 0). It widens the
    freshness window and replay-cache retention together, so a receipt cannot
    outlive its replay record."""
    try:
        return float(os.environ.get("GARGOYLE_CLOCK_SKEW_SECONDS", "0") or "0")
    except ValueError:
        return 0.0


def build_reference_target_app(
    config_provider: Callable[[], Optional[Dict[str, Any]]] = config_from_env,
    fetch: Callable[..., Optional[Dict[str, Any]]] = fetch_published_record,
    signed_fetch: Callable[..., Dict[str, Any]] = fetch_signed_record,
    replay_cache=None,
    key_record_fetch: Callable[..., Dict[str, Any]] = fetch_key_record,
) -> FastAPI:
    """Build the reference target ASGI app.

    config_provider runs per request, so a misconfigured deployment refuses
    each request (REF_TARGET_NOT_CONFIGURED) instead of failing to boot. The
    fetchers and the replay cache are injectable for tests and for shared
    deployments.

    Every call the target acts on is appended to app.state.received; a
    refused call never is, so tests can assert it acted exactly once.
    """
    app = FastAPI(title="Gargoyle reference enforcing target")
    app.state.received = []
    # Replay defense: per-process InMemoryReplayCache by default, or an injected
    # shared cache (e.g. Redis) for exactly-once across replicas.
    app.state.replay_cache = replay_cache if replay_cache is not None else InMemoryReplayCache()
    # Highest serial seen on the signed published record, so a rolled-back but
    # still-fresh record is refused (REF_VERIFY_PUBLISHED_RECORD_STALE). Per
    # process; replicas would need to share it like the replay cache.
    app.state.serial_lock = threading.Lock()
    app.state.last_seen_serial = None
    # Highest serial seen on the signed key record, so a rolled-back record that
    # would resurrect a revoked issuer key is refused (REF_VERIFY_KEY_RECORD_STALE).
    app.state.last_seen_key_record_serial = None

    @app.post("/target")
    async def target(request: Request):
        config = config_provider()
        if config is None:
            raise _refuse(REF_TARGET_NOT_CONFIGURED)

        # The body is the call the receipt must bind. A non-JSON body becomes
        # None and is refused by the verifier, never a 500.
        try:
            interaction = await request.json()
        except Exception:
            interaction = None

        # Duplicate receipt headers are ambiguous: treat as no receipt.
        raw = (None if len(request.headers.getlist(ENVELOPE_HEADER)) > 1
               else request.headers.get(ENVELOPE_HEADER))
        envelope = None
        if raw is not None:
            try:
                envelope = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                envelope = None  # unparseable header: no receipt

        # Fetch the published record off the event loop (requests blocks).
        # Signed mode checks the publisher signature, freshness and serial and
        # refuses with the reader's reason. Anchor mode only checks the bytes
        # against the pinned hash, which says nothing about age. Either way the
        # record carries the policy pin verify_envelope checks against.
        if config.get("pinned_publisher_keys"):
            # Pass the highest serial seen so a rolled-back record is refused as
            # stale even inside its not_after window.
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

        # Signed key-record mode: fetch and check the key record per request and
        # hand its trust view to the verifier, which then enforces revocation and
        # validity windows. A compromised issuer key is revoked by publishing one
        # signed record instead of re-pinning every target. A stale, invalid or
        # unreachable key record refuses; it never falls back to the static pin.
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

        # The verifier is the only acceptance authority. A pinned key is always
        # supplied, so the signature is required; in key-record mode the
        # record's trust view replaces the static pin.
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

        # Single use: refuse a decision_id already honored. decision_id is signed,
        # so it cannot be swapped. check_and_claim prunes expired entries,
        # refuses a claimed id, and claims a fresh one atomically.
        decision_id = envelope.get("decision_id")
        if decision_id is None:
            # Without a decision_id single use cannot be enforced: refuse.
            raise _refuse(REF_TARGET_NO_DECISION_ID)
        exp = None
        na = envelope.get("not_after")
        if isinstance(na, str):
            try:
                exp = datetime.fromisoformat(na) + skew  # keep the claim as long as the receipt is honored
            except ValueError:
                exp = None
        if not app.state.replay_cache.check_and_claim(decision_id, exp):
            raise _refuse(REF_VERIFY_REPLAY)

        app.state.received.append(interaction)  # the target acts only here
        return {"honored": True, "reason": result["reason"]}

    @app.get("/received")
    async def received():
        """Read-only count of calls the target has acted on, so a test over a
        real socket can confirm an honor without resending the receipt."""
        return {"count": len(app.state.received)}

    return app


# Module-level deployable app: resolves configuration from the environment per
# request. `uvicorn gargoyle.reference_target:app` serves it.
app = build_reference_target_app(replay_cache=replay_cache_from_env())

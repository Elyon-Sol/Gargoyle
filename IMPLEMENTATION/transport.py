"""
G5 transport-configuration seam (docs/restructure/12_g5_transport_design.md
step 1).

Purpose: let the two real HTTP hops of the gate - the gate-to-target push
(pep.py) and the published-record fetch (published_source.py) - run over either
loopback HTTP (dev / single box) or real socket + TLS (cross-host) with the ONLY
difference being CONFIGURATION (the TLS verification policy and an optional
client certificate), never code. This is the seam artifact 12 names so that the
same code path serves the single-box runner and the two-node harness.

Build-then-wire (the project discipline since VL-025): this module has NO callers
at the commit that introduces it. pep.py and published_source.py are NOT changed
here; wiring them to call post_to_target / get_published - with default arguments,
which produce byte-identical requests to the current direct requests.post /
requests.get calls - is the step that lands the two-node harness (artifact 12
steps 2-4). Introducing the seam first, with a runner that proves it, mirrors
VL-025 (envelope.py built with no caller) and VL-037 (verifier.py built with no
caller).

No new canonical invariant (canon section 14): transport is verification I/O.
This module only configures HOW bytes move; it never touches WHAT the gate
decides or WHAT the target verifies. The decision and the envelope contract are
unchanged.

Fail-closed (canon section 9): TLS verification defaults to ON. With no argument
and no environment override, _resolve_verify returns True, which is requests'
own default - so an unverifiable peer raises requests.exceptions.SSLError and the
caller's existing try/except (pep.governed_call's upstream catch;
published_source.fetch_published_record's `except Exception: return None`) maps
it to a fail-closed refusal, exactly as the un-TLS'd calls do today. The seam
never weakens verification by default; weakening requires an explicit caller
argument or an explicit environment value.

Custody (parallel to pep._get_signing_key and the out-of-band published-record
anchor): TLS material is resolved from the environment, never from the repo.
  ELYON_TLS_CA_BUNDLE   - path to a CA bundle the client trusts (the
                          cross-host case; a real-ish CA per artifact 12 step 3).
  ELYON_TLS_CLIENT_CERT  - "certfile" for a single combined cert, or
                          "certfile:keyfile" for mutual TLS. Absent = no client
                          cert (the default; one-way TLS).

Byte-identical default contract (the load-bearing property a wiring step relies
on): post_to_target(url, json_body, headers) with no TLS arguments and no
environment override issues exactly
    requests.post(url, json=json_body, headers=headers, verify=True, cert=None,
                  timeout=10)
which is behaviorally identical to pep.py's current
    requests.post(url, json=..., headers=..., timeout=10)
because requests already defaults verify=True and cert=None. Likewise
get_published(url) equals published_source.py's current
    requests.get(url, timeout=timeout).
The proof runner asserts this resolution explicitly.
"""

import ipaddress
import os
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter


# Environment variable names for out-of-band TLS material (never in the repo).
ENV_CA_BUNDLE = "ELYON_TLS_CA_BUNDLE"
ENV_CLIENT_CERT = "ELYON_TLS_CLIENT_CERT"


def _resolve_verify(verify: Optional[Union[bool, str]]) -> Union[bool, str]:
    """
    Resolve the requests `verify` argument, fail-closed by default.

    Precedence: an explicit caller argument wins; then the ELYON_TLS_CA_BUNDLE
    environment path; then True (requests' default, full verification). The
    function never returns False on its own - disabling verification requires a
    caller to pass verify=False explicitly, which is a deliberate, visible act.
    """
    if verify is not None:
        return verify
    ca = os.environ.get(ENV_CA_BUNDLE)
    if ca:
        return ca
    return True


def _resolve_cert(
    client_cert: Optional[Union[str, Tuple[str, str]]],
) -> Optional[Union[str, Tuple[str, str]]]:
    """
    Resolve the requests `cert` argument (client certificate for mutual TLS).

    Precedence: an explicit caller argument wins; then ELYON_TLS_CLIENT_CERT
    ("certfile" or "certfile:keyfile"); then None (no client cert). None is the
    requests default, so the byte-identical default contract holds.
    """
    if client_cert is not None:
        return client_cert
    cc = os.environ.get(ENV_CLIENT_CERT)
    if not cc:
        return None
    if ":" in cc:
        certfile, keyfile = cc.split(":", 1)
        return (certfile, keyfile)
    return cc


class _PinnedHostAdapter(HTTPAdapter):
    """HTTPS adapter for a URL whose host has been rewritten to a pinned IP
    address. TLS still presents `server_hostname` as the SNI name and verifies
    the peer certificate against it, so pinning the connection address never
    weakens certificate verification: the peer must still prove it is the name
    the caller asked for."""

    def __init__(self, server_hostname: str, **kwargs: Any) -> None:
        self._server_hostname = server_hostname
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["server_hostname"] = self._server_hostname
        pool_kwargs["assert_hostname"] = self._server_hostname
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


def _pin_url(url: str, pinned_ip: str) -> Tuple[str, str, str]:
    """Rewrite `url` so the connection goes to `pinned_ip` (port preserved).
    Returns (pinned_url, hostname, host_header): `hostname` is the name the URL
    carried (for SNI / certificate matching) and `host_header` is the Host
    header a client would have sent for that name (port included only when it
    is explicit and not the scheme default, as http.client does)."""
    parts = urlsplit(url)
    hostname = parts.hostname
    if not hostname:
        raise ValueError("url has no host")
    ip = ipaddress.ip_address(pinned_ip)
    ip_literal = f"[{ip}]" if ip.version == 6 else str(ip)
    port = parts.port
    default_port = 443 if parts.scheme == "https" else 80
    port_suffix = f":{port}" if port is not None else ""
    host_header = hostname if port in (None, default_port) else f"{hostname}:{port}"
    userinfo = parts.netloc.rsplit("@", 1)[0] + "@" if "@" in parts.netloc else ""
    pinned_url = parts._replace(netloc=f"{userinfo}{ip_literal}{port_suffix}").geturl()
    return pinned_url, hostname, host_header


def post_to_target(
    url: str,
    json_body: Any,
    headers: Dict[str, str],
    *,
    verify: Optional[Union[bool, str]] = None,
    client_cert: Optional[Union[str, Tuple[str, str]]] = None,
    timeout: int = 10,
    pinned_ip: Optional[str] = None,
) -> requests.Response:
    """
    The gate-to-target push hop, transport-configured.

    Equivalent to pep.governed_call's current
        requests.post(target_url, json=normalized_interaction,
                      headers={"X-Elyon-Sol-Envelope": ...}, timeout=10)
    when called with default TLS arguments and no environment override. The body
    and header contract are unchanged; only the TLS verification policy and an
    optional client certificate are added, resolved fail-closed.

    Redirects are NOT followed: the SSRF guard vetted only `url`, and following a
    3xx would carry the signed envelope to a host it never checked (e.g. a public
    host answering 307 -> 127.0.0.1). A 3xx is returned as-is, unfollowed.

    `pinned_ip` closes the other guard/forward seam, DNS rebinding: the guard
    resolved the URL's name to an address it vetted, and a second resolution
    here could be answered differently (a public address for the guard, an
    internal one for the forward). When `pinned_ip` is given the connection is
    made to THAT address - the name is never resolved again - while the Host
    header, the TLS SNI name and the certificate check all still use the name
    from `url`. With `pinned_ip=None` (the default) the request is byte-identical
    to the un-pinned call above.
    """
    kwargs: Dict[str, Any] = dict(
        json=json_body,
        verify=_resolve_verify(verify),
        cert=_resolve_cert(client_cert),
        timeout=timeout,
        allow_redirects=False,
    )
    if pinned_ip is None:
        return requests.post(url, headers=headers, **kwargs)

    pinned_url, hostname, host_header = _pin_url(url, pinned_ip)
    pinned_headers = dict(headers)
    pinned_headers.setdefault("Host", host_header)
    with requests.Session() as session:
        if pinned_url.startswith("https://"):
            session.mount("https://", _PinnedHostAdapter(hostname))
        return session.post(pinned_url, headers=pinned_headers, **kwargs)


def get_published(
    url: str,
    *,
    verify: Optional[Union[bool, str]] = None,
    timeout: int = 10,
) -> requests.Response:
    """
    The published-record fetch hop, transport-configured.

    Equivalent to published_source.fetch_published_record's current
        requests.get(publisher_url, timeout=timeout)
    when called with default TLS arguments and no environment override. The
    anchor-verification of the returned bytes is NOT done here (it stays in
    published_source.load_record_from_bytes per that module's separation of
    concerns); this function only performs the transport-configured GET.
    """
    return requests.get(
        url,
        verify=_resolve_verify(verify),
        timeout=timeout,
    )

"""HTTP transport for the two network hops: forwarding a call with its
receipt to a target, and fetching a published record.

Both hops run over plain HTTP on a single box or TLS across hosts, and the
difference is configuration only (CA bundle, optional client certificate),
never code. This module decides how bytes move, never what is allowed.

TLS verification is on by default. With no argument and no environment
override, verify resolves to True (requests' own default), so an
unverifiable peer raises SSLError and the caller's handler turns that into
a refusal. Weakening verification takes an explicit verify=False from the
caller; nothing here turns it off on its own.

TLS material comes from the environment, never from the repository:
  GARGOYLE_TLS_CA_BUNDLE   path to a CA bundle the client trusts.
  GARGOYLE_TLS_CLIENT_CERT "certfile" or "certfile:keyfile" for mutual TLS;
                           absent means no client certificate.
"""

import ipaddress
import os
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter


# Environment variable names for out-of-band TLS material (never in the repo).
ENV_CA_BUNDLE = "GARGOYLE_TLS_CA_BUNDLE"
ENV_CLIENT_CERT = "GARGOYLE_TLS_CLIENT_CERT"


def _resolve_verify(verify: Optional[Union[bool, str]]) -> Union[bool, str]:
    """The requests `verify` argument: the caller's value, else
    GARGOYLE_TLS_CA_BUNDLE, else True. Never returns False on its own."""
    if verify is not None:
        return verify
    ca = os.environ.get(ENV_CA_BUNDLE)
    if ca:
        return ca
    return True


def _resolve_cert(
    client_cert: Optional[Union[str, Tuple[str, str]]],
) -> Optional[Union[str, Tuple[str, str]]]:
    """The requests `cert` argument for mutual TLS: the caller's value, else
    GARGOYLE_TLS_CLIENT_CERT ("certfile" or "certfile:keyfile"), else None."""
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
    """POST a call and its receipt header to a target.

    Redirects are not followed: whoever vetted `url` vetted only that URL,
    and following a 3xx would carry the signed receipt to a host nobody
    checked (for example a public host answering 307 -> 127.0.0.1). A 3xx
    is returned as-is.

    `pinned_ip` defends against DNS rebinding. If the caller resolved the
    name and vetted the address, a second resolution here could answer
    differently. With `pinned_ip` the connection goes to that address and
    the name is never resolved again, while the Host header, TLS SNI and
    certificate check still use the name from `url`.
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
    """GET a published record. Only the transfer happens here; verifying the
    returned bytes is the record reader's job."""
    return requests.get(
        url,
        verify=_resolve_verify(verify),
        timeout=timeout,
    )

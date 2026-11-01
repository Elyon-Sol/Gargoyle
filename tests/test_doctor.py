"""`gargoyle doctor`: each check names the real cause and the one fix, with
the network, the clock and the client's files replaced (the first tenant's
four blockers of 2026-11-01 are the fixtures)."""

import json
import datetime as dt
import os

import pytest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
import ipaddress

from gargoyle import doctor
from gargoyle.doctor import (FAIL, PASS, SKIP, WARN, Context, check_ca_bundle, check_claude_code, check_clock,
                             check_env_file, check_issuer, check_rules_pin, check_state_root, check_submitter,
                             format_report, run)
from gargoyle.cli import main


def _cert(tmp_path, names=("192.168.56.101",), days=365, filename="gate.crt"):
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gate")])
    now = dt.datetime.now(dt.timezone.utc)
    san = [x509.IPAddress(ipaddress.ip_address(n)) if n[0].isdigit() else x509.DNSName(n) for n in names]
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(san), critical=False).sign(key, None))
    from cryptography.hazmat.primitives.serialization import Encoding
    p = tmp_path / filename; p.write_bytes(cert.public_bytes(Encoding.PEM)); return p


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status; self._body = body if body is not None else {}; self.headers = headers or {}
    def json(self): return self._body


class Http:
    """A requests-like double: url -> Resp, or an exception to raise."""
    def __init__(self, routes): self.routes = routes; self.calls = []
    def get(self, url, **kw):
        self.calls.append((url, kw))
        hit = self.routes.get(url)
        if isinstance(hit, Exception): raise hit
        if hit is None: raise ConnectionError("no route for " + url)
        return hit


ISSUER = "https://192.168.56.101:8443"
HEALTH = {"ok": True, "policy": {"policy_id": "gargoyle.rules/1", "policy_sha256": "71145c21" + "0" * 56}, "entra": True,
          "persistent": True, "pending_receipts": 0, "enrolled_approvers": 1, "witness_head": {"seq": 533, "entry_sha256": "ab" * 32}}


def _env(tmp_path, **over):
    ca = _cert(tmp_path)
    root = tmp_path / "share"; root.mkdir(exist_ok=True)
    env = {"GARGOYLE_MCP_ISSUER_URL": ISSUER, "GARGOYLE_MCP_TARGET_ID": "mcp://filesystem/" + str(root),
           "GARGOYLE_MCP_GATE_KEY_ID": "issuer-1", "GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX": "00" * 32,
           "GARGOYLE_MCP_EXECUTOR_KEY_ID": "executor-win", "GARGOYLE_MCP_EXECUTOR_KEY_HEX": "11" * 32,
           "GARGOYLE_MCP_RECORD_URL": ISSUER + "/record", "GARGOYLE_MCP_STATE_ROOT": str(root),
           "GARGOYLE_MCP_AUDIT_LOG": str(tmp_path / "audit.jsonl"), "REQUESTS_CA_BUNDLE": str(ca),
           "GARGOYLE_MCP_ENTRA_TENANT": "t", "GARGOYLE_MCP_ENTRA_CLIENT_ID": "c", "GARGOYLE_MCP_ENTRA_SCOPE": "api://x/access",
           "GARGOYLE_MCP_ENTRA_TOKEN_CACHE": str(tmp_path / "entra-token-cache.json"), "GARGOYLE_MCP_PRINCIPAL": "claude@contoso.com"}
    env.update(over)
    return env


def _write_env(tmp_path, env):
    p = tmp_path / "middleware.env"
    p.write_text("".join("%s=%s\n" % kv for kv in env.items())); p.chmod(0o600); return p


def _ctx(tmp_path, http=None, **kw):
    home = tmp_path / "home"; home.mkdir(exist_ok=True)
    kw.setdefault("which", lambda name: None)
    return Context(http=http or Http({}), home=home, system="Linux", **kw)


# ---- env file -----------------------------------------------------------------

def test_env_file_names_missing_keys(tmp_path):
    env = _env(tmp_path); del env["GARGOYLE_MCP_EXECUTOR_KEY_HEX"]
    p = _write_env(tmp_path, env)
    c = check_env_file(str(p), env)
    assert c.status == FAIL and "GARGOYLE_MCP_EXECUTOR_KEY_HEX" in c.detail


def test_env_file_needs_an_identity(tmp_path):
    env = _env(tmp_path)
    for k in doctor.ENTRA_KEYS: env.pop(k)
    c = check_env_file(str(_write_env(tmp_path, env)), env)
    assert c.status == FAIL and "gargoyle login" in c.fix


@pytest.mark.skipif(os.name != "posix", reason="file modes are a POSIX concern; Windows ACLs are not read")
def test_env_file_warns_when_world_readable(tmp_path):
    env = _env(tmp_path); p = _write_env(tmp_path, env); p.chmod(0o644)
    c = check_env_file(str(p), env)
    assert c.status == WARN and "chmod 600" in c.fix


# ---- trust ----------------------------------------------------------------------

def test_ca_bundle_must_name_the_issuer_host(tmp_path):
    env = _env(tmp_path, REQUESTS_CA_BUNDLE=str(_cert(tmp_path, names=("gate.lab",), filename="other.crt")))
    c = check_ca_bundle(env, _ctx(tmp_path))
    assert c.status == FAIL and "192.168.56.101" in c.detail and "SAN" in c.fix


def test_ca_bundle_passes_and_reports_names(tmp_path):
    c = check_ca_bundle(_env(tmp_path), _ctx(tmp_path))
    assert c.status == PASS and "192.168.56.101" in c.detail


def test_ca_bundle_expired(tmp_path):
    env = _env(tmp_path, REQUESTS_CA_BUNDLE=str(_cert(tmp_path, days=-1, filename="old.crt")))
    c = check_ca_bundle(env, _ctx(tmp_path, now=lambda: dt.datetime.now(dt.timezone.utc).timestamp()))
    assert c.status == FAIL and "expired" in c.detail


def test_issuer_tls_failure_points_at_requests_ca_bundle(tmp_path):
    class SSLError(Exception): pass
    http = Http({ISSUER + "/health": SSLError("[SSL: CERTIFICATE_VERIFY_FAILED] self signed certificate")})
    r = check_issuer(_env(tmp_path), _ctx(tmp_path, http))
    assert r["check"].status == FAIL and "REQUESTS_CA_BUNDLE" in r["check"].fix


def test_issuer_health_detail_and_date(tmp_path):
    http = Http({ISSUER + "/health": Resp(200, HEALTH, {"Date": "Sun, 01 Nov 2026 20:35:12 GMT"})})
    r = check_issuer(_env(tmp_path), _ctx(tmp_path, http))
    assert r["check"].status == PASS and "rules 71145c21" in r["check"].detail and "witness seq 533" in r["check"].detail
    assert r["date"].startswith("Sun")


def test_clock_skew_levels(tmp_path):
    remote = "Sun, 01 Nov 2026 20:35:12 GMT"
    base = dt.datetime(2026, 11, 1, 20, 35, 12, tzinfo=dt.timezone.utc).timestamp()
    assert check_clock(remote, _ctx(tmp_path, now=lambda: base + 5)).status == PASS
    assert check_clock(remote, _ctx(tmp_path, now=lambda: base + 90)).status == WARN
    assert check_clock(remote, _ctx(tmp_path, now=lambda: base - 600)).status == FAIL
    assert check_clock(None, _ctx(tmp_path)).status == SKIP


# ---- rules pin ------------------------------------------------------------------

def test_rules_pin_static_file_mismatch_is_fatal(tmp_path):
    rec = tmp_path / "record.json"; rec.write_text(json.dumps({"policy_sha256": "da8efbda" + "0" * 56}))
    env = _env(tmp_path, GARGOYLE_MCP_RECORD_PATH=str(rec)); env.pop("GARGOYLE_MCP_RECORD_URL")
    c = check_rules_pin(env, HEALTH, _ctx(tmp_path))
    assert c.status == FAIL and "da8efbda" in c.detail and "71145c21" in c.detail and "refused" in c.detail


def test_rules_pin_followed_record_passes(tmp_path):
    http = Http({ISSUER + "/record": Resp(200, {"policy_sha256": HEALTH["policy"]["policy_sha256"], "publisher_key_id": "issuer-1"})})
    c = check_rules_pin(_env(tmp_path), HEALTH, _ctx(tmp_path, http))
    assert c.status == PASS and "followed" in c.detail


# ---- submitter ------------------------------------------------------------------

def test_submitter_without_cache_says_login(tmp_path):
    c = check_submitter(_env(tmp_path), _ctx(tmp_path))
    assert c.status == FAIL and "-Relogin" in c.fix


def test_submitter_assignment_required_is_named(tmp_path):
    env = _env(tmp_path); Path(env["GARGOYLE_MCP_ENTRA_TOKEN_CACHE"]).write_text("{}")
    class Src:
        principal = "claude@contoso.com"
        def token(self):
            raise Exception("Entra token could not be refreshed (AADSTS50105: Your administrator has configured the application "
                                                 "Gargoyle-Issuer-API to block users unless they are specifically granted access); run: gargoyle login")
    c = check_submitter(env, _ctx(tmp_path, token_source_factory=lambda e: Src()))
    assert c.status == FAIL and "Assignment required" in c.fix and "enterprise application" in c.fix


def test_submitter_silent_refresh_passes_and_names_the_user(tmp_path):
    env = _env(tmp_path); Path(env["GARGOYLE_MCP_ENTRA_TOKEN_CACHE"]).write_text("{}")
    class Src:
        principal = "claude@contoso.com"
        def token(self): return "t"
    c = check_submitter(env, _ctx(tmp_path, token_source_factory=lambda e: Src()))
    assert c.status == PASS and "claude@contoso.com" in c.detail


def test_submitter_principal_drift_warns(tmp_path):
    env = _env(tmp_path, GARGOYLE_MCP_PRINCIPAL="someone@else"); Path(env["GARGOYLE_MCP_ENTRA_TOKEN_CACHE"]).write_text("{}")
    class Src:
        principal = "claude@contoso.com"
        def token(self): return "t"
    c = check_submitter(env, _ctx(tmp_path, token_source_factory=lambda e: Src()))
    assert c.status == WARN and "someone@else" in c.detail


def test_submitter_static_token_is_a_warning_until_login(tmp_path):
    env = _env(tmp_path, GARGOYLE_MCP_CLIENT_TOKEN="x", GARGOYLE_MCP_PRINCIPAL="pending-entra-login")
    c = check_submitter(env, _ctx(tmp_path))
    assert c.status == WARN and "gargoyle login" in c.fix


# ---- local state ----------------------------------------------------------------

def test_state_root_client_state_inside_root_warns(tmp_path):
    env = _env(tmp_path); (Path(env["GARGOYLE_MCP_STATE_ROOT"]) / ".claude").mkdir()
    c = check_state_root(env)
    assert c.status == WARN and "CLIENT_STATE_IN_ROOT" in c.fix


# ---- Claude Code layers ---------------------------------------------------------

def _claude_host(ctx, *, managed=None, settings=None, servers=None, system="Linux"):
    ctx.system = system
    if settings is not None:
        (ctx.home / ".claude").mkdir(exist_ok=True)
        (ctx.home / ".claude" / "settings.json").write_text(json.dumps(settings))
    if servers is not None:
        (ctx.home / ".claude.json").write_text(json.dumps({"mcpServers": servers}))
    return managed


def test_claude_code_neither_denied_nor_hooked_fails(tmp_path):
    ctx = _ctx(tmp_path); _claude_host(ctx, settings={}, servers={"filesystem-gargoyle": {"command": "python"}})
    checks = {c.name: c for c in check_claude_code(_env(tmp_path), ctx)}
    assert checks["claude code deny"].status == FAIL
    assert checks["claude code allow"].status == WARN and "auto-mode" in checks["claude code allow"].fix


def test_claude_code_hook_host_passes_and_skips_allow(tmp_path):
    ctx = _ctx(tmp_path)
    hook = {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "python -m gargoyle hook --env /x/middleware.env"}]}]}}
    _claude_host(ctx, settings=hook)
    env = _env(tmp_path); env["_GARGOYLE_DOCTOR_ENV_PATH"] = "/x/middleware.env"
    checks = {c.name: c for c in check_claude_code(env, ctx)}
    assert checks["claude code deny"].status == PASS and "hook" in checks["claude code deny"].detail
    assert checks["claude code hook"].status == PASS
    assert checks["claude code allow"].status == SKIP


def test_claude_code_hook_binds_a_windows_path(tmp_path):
    ctx = _ctx(tmp_path)
    hook = {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "python -m gargoyle hook --env C:\\gargoyle\\middleware.env"}]}]}}
    _claude_host(ctx, settings=hook)
    env = _env(tmp_path); env["_GARGOYLE_DOCTOR_ENV_PATH"] = "C:\\gargoyle\\middleware.env"
    checks = {c.name: c for c in check_claude_code(env, ctx)}
    assert checks["claude code hook"].status == PASS


def test_claude_code_hook_with_other_env_warns(tmp_path):
    ctx = _ctx(tmp_path)
    hook = {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "python -m gargoyle hook --env /other.env"}]}]}}
    _claude_host(ctx, settings=hook)
    env = _env(tmp_path); env["_GARGOYLE_DOCTOR_ENV_PATH"] = "/x/middleware.env"
    checks = {c.name: c for c in check_claude_code(env, ctx)}
    assert checks["claude code hook"].status == WARN


def test_claude_code_managed_deny_and_allow_pass(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    managed_dir = tmp_path / "etc-claude-code"; managed_dir.mkdir()
    (managed_dir / "managed-settings.json").write_text(json.dumps(
        {"permissions": {"deny": ["Edit", "Write", "MultiEdit", "NotebookEdit", "Bash"], "allow": ["mcp__filesystem-gargoyle"]}}))
    (managed_dir / "managed-mcp.json").write_text(json.dumps({"mcpServers": {"filesystem-gargoyle": {"command": "python"}}}))
    import gargoyle.sidedoors as sd
    real = sd.client_config_paths
    def paths(home, system, env=None):
        out = real(home, system, env); out["managed_dir"] = [managed_dir]; return out
    monkeypatch.setattr(sd, "client_config_paths", paths)
    checks = {c.name: c for c in check_claude_code(_env(tmp_path), ctx)}
    assert checks["claude code deny"].status == PASS and "Bash" in checks["claude code deny"].detail
    assert checks["claude code allow"].status == PASS


# ---- the suite and the command --------------------------------------------------

def test_run_stops_at_a_broken_env_file(tmp_path):
    result = run(str(tmp_path / "missing.env"), ctx=_ctx(tmp_path), environ={})
    assert result["ok"] is False and len(result["checks"]) == 1 and result["edr_note"]


def test_run_all_green_and_report_shape(tmp_path):
    env = _env(tmp_path); Path(env["GARGOYLE_MCP_ENTRA_TOKEN_CACHE"]).write_text("{}")
    p = _write_env(tmp_path, env)
    http = Http({ISSUER + "/health": Resp(200, HEALTH, {"Date": "Sun, 01 Nov 2026 20:35:12 GMT"}),
                 ISSUER + "/record": Resp(200, {"policy_sha256": HEALTH["policy"]["policy_sha256"], "publisher_key_id": "issuer-1"})})
    class Src:
        principal = "claude@contoso.com"
        def token(self): return "t"
    base = dt.datetime(2026, 11, 1, 20, 35, 12, tzinfo=dt.timezone.utc).timestamp()
    ctx = _ctx(tmp_path, http, now=lambda: base + 1, token_source_factory=lambda e: Src())
    hook = {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "gargoyle hook --env " + str(p)}]}]}}
    _claude_host(ctx, settings=hook)
    result = run(str(p), ctx=ctx, environ={})
    names = [c["name"] for c in result["checks"]]
    assert names[:8] == ["env file", "CA bundle", "issuer", "clock", "rules pin", "submitter", "state root", "evidence log"]
    assert all(c["status"] in (PASS, SKIP) for c in result["checks"]), result["checks"]
    text = format_report(result)
    assert "ready: 0 fail, 0 warn" in text and "Anthropic, PBC" in text
    # the CA bundle check is Python's trust; the doctor reads the file's own keys, not the process environment
    assert any(c["name"] == "env file" and "15 keys" in c["detail"] for c in result["checks"])


def test_cli_exit_codes(tmp_path, capsys, monkeypatch):
    env = _env(tmp_path); p = _write_env(tmp_path, env)
    monkeypatch.setattr(doctor, "Context", lambda **kw: _ctx(tmp_path, Http({})))
    rc = main(["doctor", "--env", str(p), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and out["ok"] is False
    assert any(c["name"] == "issuer" and c["status"] == FAIL for c in out["checks"])

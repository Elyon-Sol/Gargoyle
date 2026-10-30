"""`python -m gargoyle.mcp_server --env FILE`: the gate's settings from a
file the managed MCP entry can name instead of carrying the executor key."""
import pytest

from gargoyle.mcp_server import load_env_file, main_args


def test_env_file_fills_what_the_environment_lacks(tmp_path):
    f = tmp_path / "middleware.env"
    f.write_text("\ufeffGARGOYLE_MCP_PRINCIPAL=dana@example.com\n# a comment\n\nGARGOYLE_MCP_ISSUER_URL = https://gate.example \nbad line\n", encoding="utf-8")
    env = {"GARGOYLE_MCP_PRINCIPAL": "operator-override"}
    applied = load_env_file(str(f), env)
    assert applied == {"GARGOYLE_MCP_ISSUER_URL": "https://gate.example"}        # BOM stripped, spaces trimmed, comment and bad line skipped
    assert env == {"GARGOYLE_MCP_PRINCIPAL": "operator-override", "GARGOYLE_MCP_ISSUER_URL": "https://gate.example"}


def test_main_args_take_env_before_the_upstream_command():
    assert main_args(["--env", "C:\\gargoyle\\middleware.env", "--", "python", "-m", "gargoyle.fs_server", "C:\\share"]) \
        == ("C:\\gargoyle\\middleware.env", ["--", "python", "-m", "gargoyle.fs_server", "C:\\share"])
    assert main_args(["--env=/opt/g/middleware.env", "--", "npx", "x"]) == ("/opt/g/middleware.env", ["--", "npx", "x"])
    assert main_args(["--", "npx", "x"]) == (None, ["--", "npx", "x"])
    assert main_args([]) == (None, [])
    with pytest.raises(SystemExit):
        main_args(["--bogus", "--", "npx"])

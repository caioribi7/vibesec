import subprocess

import pytest

from vibesec import offline, runner
from vibesec.scanners.external import OsvScanner, SemgrepScanner, TrivyScanner


@pytest.fixture
def fake_docker(monkeypatch):
    """Finge que só existe Docker e grava os comandos executados."""
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout='{"results": [], "Results": []}', stderr="")

    monkeypatch.setattr(runner, "resolve", lambda tool, allow_docker=True: "docker")
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    return calls


def test_offline_containers_have_no_network(fake_docker, ctx):
    ctx.offline = True
    TrivyScanner().run(ctx)
    cmd = fake_docker[-1]
    assert cmd[cmd.index("--network") + 1] == "none"
    assert "--skip-db-update" in cmd and "--offline-scan" in cmd
    assert cmd[-1] == "/src"


def test_online_containers_keep_network(fake_docker, ctx):
    TrivyScanner().run(ctx)
    assert "--network" not in fake_docker[-1]


def test_semgrep_offline_uses_local_rules(fake_docker, ctx, tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "semgrep-default.yml").write_text("rules: []\n")
    monkeypatch.setattr(offline, "RULES_DIR", rules)
    ctx.offline = True
    SemgrepScanner().run(ctx)
    cmd = fake_docker[-1]
    configs = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--config"]
    assert configs == ["/out/semgrep-rules/semgrep-default.yml"]
    assert not any(c.startswith("p/") for c in configs)


def test_semgrep_offline_without_rules_is_skipped(fake_docker, ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(offline, "RULES_DIR", tmp_path / "vazio")
    ctx.offline = True
    with pytest.raises(runner.ToolUnavailable):
        SemgrepScanner().run(ctx)


def test_osv_needs_internet(ctx):
    assert OsvScanner().applicable(ctx)
    ctx.offline = True
    assert not OsvScanner().applicable(ctx)


def test_sandbox_tool_networks():
    from vibesec.dynamic.sandbox import Sandbox

    sb = Sandbox(root=None, stack={})
    sb.net_int, sb.net_pub = "int", "pub"
    assert sb.tool_networks == ["pub", "int"]
    sb.offline = True
    assert sb.tool_networks == ["int"]  # offline: ferramentas não têm rota para a internet


def test_bundle_manifest_is_validated(tmp_path):
    (tmp_path / "manifest.json").write_text('{"outro": 1}')
    with pytest.raises(RuntimeError, match="não é um pacote"):
        offline.import_bundle(tmp_path, lambda *a: None)

import json

import pytest
from typer.testing import CliRunner

from vibesec.models import Category, Finding, ScanResult, Severity
from vibesec.repo import parse_github
from vibesec.report import to_html, to_markdown, to_sarif, write_all


@pytest.mark.parametrize("value,expected", [
    ("https://github.com/caioribi7/masterbase", ("caioribi7", "masterbase", None)),
    ("https://github.com/caioribi7/masterbase.git", ("caioribi7", "masterbase", None)),
    ("github.com/a/b", None),
    ("caioribi7/curso-on", ("caioribi7", "curso-on", None)),
    ("https://github.com/o/r/tree/dev", ("o", "r", "dev")),
    ("git@github.com:o/r.git", ("o", "r", None)),
    ("não é repo", None),
])
def test_parse_github(value, expected):
    assert parse_github(value) == expected


def test_severity_parse():
    assert Severity.parse("ERROR") == Severity.HIGH
    assert Severity.parse("moderate") == Severity.MEDIUM
    assert Severity.parse("???", Severity.LOW) == Severity.LOW


def _f(**kw):
    base = dict(title="SQLi", severity=Severity.HIGH, category=Category.CODE, tool="a", file="app.py", line=3,
                rule_id="sqli")
    return Finding(**{**base, **kw})


def test_dedupe_keeps_highest_severity_and_merges_tools():
    r = ScanResult(target="x")
    r.add([_f(), _f(tool="b", severity=Severity.CRITICAL), _f(line=9, severity=Severity.LOW)])
    r.dedupe()
    assert len(r.findings) == 2
    assert r.findings[0].severity == Severity.CRITICAL and r.findings[0].tool == "a+b"


def test_dedupe_merges_same_line_same_cwe_across_tools():
    r = ScanResult(target="x")
    r.add([_f(title="SQL montado com f-string", cwe=["CWE-89"], tool="vibesec-sast"),
           _f(title="Avoid SQL concat", rule_id="semgrep.x", cwe=["CWE-89"], tool="semgrep"),
           _f(title="Possible SQLi", rule_id="B608", cwe=["CWE-89"], tool="bandit", severity=Severity.MEDIUM),
           _f(title="Outro", rule_id="other", cwe=["CWE-78"], tool="bandit")])
    r.dedupe()
    assert len(r.findings) == 2
    sqli = next(f for f in r.findings if f.cwe == ["CWE-89"])
    assert sqli.title == "SQL montado com f-string" and sqli.tool == "vibesec-sast+semgrep+bandit"


def test_score_and_grade():
    r = ScanResult(target="x")
    assert (r.score, r.grade) == (100, "A")
    r.add([_f(severity=Severity.CRITICAL, line=i) for i in range(4)])
    assert r.score == 0 and r.grade == "F"
    for f in r.findings:
        f.false_positive = True
    assert r.score == 100


def test_roundtrip_and_reports(tmp_path):
    r = ScanResult(target="o/r", commit="abc")
    r.add([_f(evidence="<script>alert(1)</script>", cwe=["CWE-89"]), _f(file=None, line=None, url="/x",
                                                                       category=Category.WEB, rule_id="xss")])
    back = ScanResult.from_dict(json.loads(json.dumps(r.to_dict())))
    assert [f.fingerprint for f in back.findings] == [f.fingerprint for f in r.findings]

    html = to_html(r)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    sarif = json.loads(to_sarif(r))
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert "SQLi" in to_markdown(r)
    paths = write_all(r, tmp_path / "out")
    assert set(paths) == {"json", "md", "html", "sarif"} and all(p.exists() for p in paths.values())


def test_cli_static_scan(vulnapp, tmp_path, monkeypatch):
    from vibesec.cli import app

    monkeypatch.setenv("VIBESEC_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import vibesec.config as cfg

    monkeypatch.setattr(cfg, "HOME", tmp_path / "home")
    monkeypatch.setattr(cfg, "HISTORY", tmp_path / "home" / "history.jsonl")
    monkeypatch.setattr(cfg, "CONFIG", tmp_path / "home" / "config.json")
    out = tmp_path / "reports"
    res = CliRunner().invoke(app, ["scan", str(vulnapp), "--mode", "static", "-y", "-q",
                                   "--no-docker", "--out", str(out), "--fail-on", "critical"])
    assert res.exit_code == 1, res.output  # o fixture tem achados críticos
    report = next(out.rglob("report.json"))
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["counts"]["critical"] >= 1 and data["grade"] == "F"
    assert cfg.history()[0]["target"] == "vulnapp"


def test_dedupe_same_line_shared_cwe_and_same_title():
    from vibesec.models import Category, Finding, ScanResult, Severity

    r = ScanResult(target="t")
    r.add([
        Finding("SQL montado", Severity.HIGH, Category.CODE, "vibesec-sast", file="a.py", line=5, cwe=["CWE-89"]),
        Finding("SQL string", Severity.HIGH, Category.CODE, "semgrep", file="a.py", line=5, cwe=["CWE-915", "CWE-89"]),
        Finding("Debug on", Severity.MEDIUM, Category.CODE, "semgrep", file="a.py", line=9, rule_id="x"),
        Finding("Debug on", Severity.MEDIUM, Category.CODE, "semgrep", file="a.py", line=9, rule_id="y"),
    ])
    r.dedupe()
    assert len(r.findings) == 2


def test_summary_fix_keeps_ellipsis_and_falls_back_to_cwe():
    from vibesec.triage import FIX_BY_CWE, first_sentence

    assert first_sentence("Use cursor.execute('... WHERE id = %s', (id,)). Depois teste.").endswith("(id,))")
    assert "parametrizadas" in FIX_BY_CWE["CWE-89"]


def test_banner_has_shield_and_wordmark():
    from vibesec.brand import banner

    text = banner("9.9.9").plain
    assert "█████▄   ▄█████" in text and "v9.9.9" in text and "╚═══╝" in text

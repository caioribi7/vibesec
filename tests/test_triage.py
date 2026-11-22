from pathlib import Path

from vibesec.models import Category, Finding, ScanResult, Severity
from vibesec.scanners.builtin_code import BuiltinCodeScanner
from vibesec.scanners.builtin_secrets import BuiltinSecretsScanner
from vibesec.triage import SourceCache, assess, attack_chains, correlate_runtime, triage


def _code(tmp_path: Path, name: str, text: str) -> SourceCache:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return SourceCache(tmp_path)


def _sqli(file="app.py", line=3, **kw) -> Finding:
    return Finding(title="SQLi", severity=Severity.MEDIUM, category=Category.CODE, tool="semgrep", file=file,
                   line=line, rule_id="sqli", cwe=["CWE-89"], **kw)


def test_tainted_sink_is_high_confidence_and_raised(tmp_path):
    src = _code(tmp_path, "app.py",
                "@app.route('/u')\ndef u():\n    db.execute(f\"SELECT * FROM u WHERE id = {request.args['id']}\")\n")
    v = assess(_sqli(), src)
    assert v.confidence == "high" and v.severity_shift == 1 and not v.false_positive
    assert "request.args" in " ".join(v.notes)


def test_constant_query_is_false_positive(tmp_path):
    src = _code(tmp_path, "app.py", "def stats():\n    x = 1\n    db.execute(\"SELECT count(*) FROM users\")\n")
    assert assess(_sqli(), src).false_positive


def test_sanitized_sink_is_downgraded(tmp_path):
    src = _code(tmp_path, "app.py",
                "def u():\n    uid = request.args['id']\n    db.execute(\"SELECT * FROM u WHERE id = \" + str(int(uid)))\n")
    v = assess(_sqli(), src)
    assert v.confidence == "low" and v.severity_shift == -1


def test_untainted_sink_is_medium(tmp_path):
    src = _code(tmp_path, "repo.py", "def by_id(uid):\n    q = 1\n    db.execute(f\"SELECT * FROM u WHERE id = {uid}\")\n")
    v = assess(_sqli(file="repo.py"), src)
    assert v.confidence == "medium" and not v.false_positive


def test_test_files_are_downgraded(tmp_path):
    src = _code(tmp_path, "tests/test_x.py", "x = 1\n")
    v = assess(_sqli(file="tests/test_x.py", line=1), src)
    assert v.confidence == "low" and v.severity_shift == -2


def test_vendor_is_false_positive(tmp_path):
    src = _code(tmp_path, "static/vendor/jquery.min.js", "x\n")
    assert assess(_sqli(file="static/vendor/jquery.min.js", line=1), src).false_positive


def test_runtime_correlation_links_static_to_exploited_route(tmp_path):
    src = _code(tmp_path, "app.py", "\n".join([
        "@app.route('/user')", "def user():", "    uid = request.args.get('id')",
        "    return db.execute(f'SELECT * FROM users WHERE id = {uid}')",
        "", "@app.route('/other')", "def other():", "    return db.execute(f'SELECT {x}')",
    ]))
    r = ScanResult(target="t")
    static_hit = _sqli(line=4)
    static_other = Finding(title="SQLi", severity=Severity.MEDIUM, category=Category.CODE, tool="semgrep",
                           file="app.py", line=8, rule_id="sqli-other", cwe=["CWE-89"])
    dyn = Finding(title="SQLi", severity=Severity.CRITICAL, category=Category.WEB, tool="vibesec-probe",
                  url="GET /user", rule_id="sqli-error-id", cwe=["CWE-89"], confirmed=True)
    r.add([static_hit, static_other, dyn])
    assert correlate_runtime(r, src) == 1
    assert static_hit.confirmed and "GET /user" in static_hit.notes
    assert not static_other.confirmed  # outra rota: não confirma por tabela


def test_attack_chain_supabase():
    fs = [Finding(title="k", severity=Severity.CRITICAL, category=Category.SECRET, tool="x", file="src/a.ts",
                  line=1, rule_id="supabase-service-role"),
          Finding(title="r", severity=Severity.HIGH, category=Category.CONFIG, tool="x", file="m.sql", line=2,
                  rule_id="rls-disabled")]
    chains = attack_chains(fs)
    assert len(chains) == 1 and "Banco aberto" in chains[0]


def test_full_triage_on_fixture(ctx, vulnapp):
    r = ScanResult(target="vulnapp")
    r.add(BuiltinSecretsScanner().run(ctx) + BuiltinCodeScanner().run(ctx))
    r.dedupe()
    stats = triage(r, vulnapp)
    sqli = next(f for f in r.findings if f.rule_id == "sqli-fstring")
    assert sqli.confidence == "high" and "request.args" in sqli.notes
    assert r.summary and "Corrija primeiro" in r.summary and "Banco aberto" in r.summary
    assert stats["fp"] >= 0
    # ordem: mais grave primeiro
    ranks = [f.severity.rank for f in r.active]
    assert ranks == sorted(ranks, reverse=True)

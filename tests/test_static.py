import base64
import json

from vibesec.models import Category, Severity
from vibesec.scanners.builtin_code import BuiltinCodeScanner
from vibesec.scanners.builtin_secrets import BuiltinSecretsScanner, mask
from vibesec.stack import detect


def _ids(findings):
    return {f.rule_id for f in findings}


def test_stack_detection(vulnapp):
    st = detect(vulnapp)
    assert st["primary"] == "Python"
    assert "Flask" in st["frameworks"]
    assert st["dockerfile"] and st["port"] == 5000


def test_builtin_sast_finds_the_planted_bugs(ctx):
    found = BuiltinCodeScanner().run(ctx)
    ids = _ids(found)
    expected = {
        "sqli-fstring", "ssti-flask", "cmd-injection-py", "pickle-load", "yaml-load", "weak-hash",
        "debug-on", "bind-all", "xss-innerhtml", "code-eval-js", "insecure-random", "sqli-concat-js",
        "next-public-secret", "supabase-service-client", "rls-disabled", "rls-permissive", "docker-root",
    }
    assert expected <= ids, f"faltando: {expected - ids}"
    sqli = next(f for f in found if f.rule_id == "sqli-fstring")
    assert sqli.file == "app.py" and sqli.line == 17 and sqli.severity == Severity.HIGH


def test_sast_ignores_safe_code(tmp_path):
    (tmp_path / "ok.py").write_text(
        'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
        "data = yaml.load(raw, Loader=yaml.SafeLoader)\n"
        "subprocess.run(['ls', '-l'])\n", encoding="utf-8")
    from vibesec.scanners.base import ScanContext

    found = BuiltinCodeScanner().run(ScanContext(root=tmp_path, work=tmp_path))
    assert not found, [f.rule_id for f in found]


def test_builtin_secrets(ctx):
    found = BuiltinSecretsScanner().run(ctx)
    ids = _ids(found)
    assert {"committed-env-file", "aws-access-key", "db-url"} <= ids
    for f in found:
        assert f.category == Category.SECRET
        if f.evidence:
            assert "Kq9vT2mWz7Lp" not in f.evidence  # nunca imprime o segredo inteiro


def _jwt(payload: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(payload)}.c2lnbmF0dXJlZmFrZWZvcnRlc3Rz"


def test_supabase_service_role_jwt(tmp_path):
    from vibesec.scanners.base import ScanContext

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "client.ts").write_text(
        f'const anon = "{_jwt({"role": "anon", "iss": "supabase", "exp": 9999999999})}";\n'
        f'const admin = "{_jwt({"role": "service_role", "iss": "supabase", "exp": 9999999999})}";\n',
        encoding="utf-8")
    found = BuiltinSecretsScanner().run(ScanContext(root=tmp_path, work=tmp_path))
    assert [f.rule_id for f in found] == ["supabase-service-role"]
    assert found[0].severity == Severity.CRITICAL and found[0].line == 2


def test_placeholders_are_ignored(tmp_path):
    from vibesec.scanners.base import ScanContext

    (tmp_path / "settings.py").write_text(
        'PASSWORD = "changeme"\nAPI_KEY = "your-api-key-here"\nDB = "postgres://user:password@localhost/db"\n'
        'access_key = "AKIAIOSFODNN7EXAMPLE"\nsecret = "env(SUPABASE_AUTH_EXTERNAL_APPLE_SECRET)"\n',
        encoding="utf-8")
    assert BuiltinSecretsScanner().run(ScanContext(root=tmp_path, work=tmp_path)) == []


def test_mask():
    assert mask("abcdefghijklmnop") == "abcd…mnop (16 chars)"
    assert mask("abc") == "***"

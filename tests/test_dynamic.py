"""Testes da parte dinâmica que não precisam de Docker."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from vibesec.dynamic.probes import Prober
from vibesec.dynamic.sandbox import Sandbox
from vibesec.dynamic.tools import analyze_traffic, parse_nmap, parse_zap
from vibesec.models import Severity
from vibesec.stack import detect


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "Express")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/":
            return self._send(200, '<a href="/search?q=a">busca</a><a href="/item?id=1">item</a>'
                                   '<a href="https://externo.example/x">fora</a>'
                                   '<form action="/login" method="post"><input name="user"></form>')
        if u.path == "/search":
            return self._send(200, f"<p>Resultados para {q.get('q', '')}</p>")
        if u.path == "/item":
            if "'" in q.get("id", ""):
                return self._send(500, "sqlite3.OperationalError: unrecognized token")
            return self._send(200, "<p>item</p>")
        if u.path == "/.env":
            return self._send(200, "SECRET_KEY=abc123456\nDB_PASS=xyz", "text/plain")
        if u.path == "/redirect-out":
            return self._send(302, "", extra={"Location": "https://externo.example/"})
        return self._send(404, "não achei")

    def do_POST(self):
        self._send(200, "ok")


@pytest.fixture
def vuln_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), VulnHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_prober_exploits_planted_bugs(vuln_server):
    found = Prober(vuln_server).run()
    ids = {f.rule_id for f in found}
    assert "xss-reflected-q" in ids
    assert "sqli-error-id" in ids
    assert "exposed/.env" in ids
    assert "cors-reflect" in ids
    assert "missing-content-security-policy" in ids
    sqli = next(f for f in found if f.rule_id == "sqli-error-id")
    assert sqli.severity == Severity.CRITICAL and sqli.confirmed
    env = next(f for f in found if f.rule_id == "exposed/.env")
    assert "abc123456" not in env.evidence


def test_prober_never_leaves_sandbox(vuln_server):
    p = Prober(vuln_server)
    assert p._get("https://externo.example/") is None
    assert p._get("/redirect-out") is None  # redirecionamento para fora é bloqueado


NMAP_XML = """<?xml version="1.0"?><nmaprun><host><ports>
<port protocol="tcp" portid="5000"><state state="open"/><service name="http" product="Werkzeug" version="3.0"/></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis" version="7.2"/></port>
<port protocol="tcp" portid="9229"><state state="open"/><service name="unknown"/>
<script id="http-vuln-x" output="VULNERABLE: CVE-2024-1234 bad thing"/></port>
</ports></host></nmaprun>"""


def test_parse_nmap():
    found = parse_nmap(NMAP_XML, app_port=5000)
    by = {f.rule_id: f for f in found}
    assert by["app-port"].severity == Severity.INFO
    assert by["open-port-redis"].severity == Severity.HIGH
    assert by["debug-port-9229"].severity == Severity.CRITICAL
    assert by["nmap.http-vuln-x"].cve == ["CVE-2024-1234"]


def test_parse_zap():
    data = {"site": [{"alerts": [{"pluginid": "40012", "alert": "Cross Site Scripting (Reflected)", "riskcode": "3",
                                  "confidence": "2", "cweid": "79", "desc": "<p>XSS</p>", "solution": "<p>Escape</p>",
                                  "instances": [{"uri": "http://target:5000/s?q=x", "method": "GET", "param": "q"}]}]}]}
    f = parse_zap(data)[0]
    assert f.severity == Severity.HIGH and f.cwe == ["CWE-79"] and f.url == "/s?q=x" and f.confirmed
    assert f.description == "XSS"


def test_analyze_traffic():
    found = analyze_traffic(
        dns="target\napi.telemetry.example.com\napi.telemetry.example.com\n",
        cookies="session=abc; Path=/\ntheme=dark",
        auth="/admin\tBasic YWRtaW46YWRtaW4=",
        forms="/login\tuser,password",
        convs="",
    )
    ids = {f.rule_id for f in found}
    assert {"egress-dns", "cookie-flags-session", "basic-auth", "password-form"} <= ids
    assert "cookie-flags-theme" not in ids
    egress = next(f for f in found if f.rule_id == "egress-dns")
    assert egress.evidence == "api.telemetry.example.com"


def test_sandbox_generates_dockerfile_for_flask(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    sb = Sandbox(tmp_path, detect(tmp_path))
    df = sb._generate()
    assert "gunicorn -b 0.0.0.0:8000 app:app" in df and sb.port == 8000


def test_sandbox_generates_dockerfile_for_node(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"start": "node server.js", "build": "tsc"}, '
                                           '"dependencies": {"express": "4"}}')
    sb = Sandbox(tmp_path, detect(tmp_path))
    df = sb._generate()
    assert "FROM node:20-alpine" in df and "npm run build" in df and '["npm", "run", "start"]' in df

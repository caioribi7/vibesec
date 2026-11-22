"""Sondas HTTP próprias do VibeSec. Só falam com a URL local da sandbox."""

from __future__ import annotations

import re
import uuid
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from vibesec.models import Category, Finding, Severity

EXPOSED = [
    # caminho, verificação do conteúdo, título, severidade
    ("/.env", r"(?m)^[A-Z_][A-Z0-9_]*\s*=", "Arquivo .env acessível pela web", Severity.CRITICAL),
    ("/.git/HEAD", r"^ref: refs/", "Repositório .git exposto", Severity.HIGH),
    ("/.git/config", r"\[core\]", "Configuração .git exposta", Severity.HIGH),
    ("/config.json", r"(?i)(secret|password|api[_-]?key|token)", "config.json com segredos acessível", Severity.HIGH),
    ("/docker-compose.yml", r"(?m)^\s*services:", "docker-compose.yml acessível", Severity.MEDIUM),
    ("/package.json", r'"dependencies"', "package.json servido publicamente", Severity.LOW),
    ("/.DS_Store", r"Bud1", ".DS_Store exposto (lista arquivos)", Severity.LOW),
    ("/phpinfo.php", r"PHP Version", "phpinfo() exposto", Severity.MEDIUM),
    ("/server-status", r"Apache Server Status", "Apache server-status exposto", Severity.MEDIUM),
    ("/actuator/env", r"(propertySources|activeProfiles)", "Spring actuator /env exposto", Severity.HIGH),
    ("/actuator/heapdump", None, "Spring actuator heapdump exposto", Severity.CRITICAL),
    ("/console", r"(?i)werkzeug.*debugger|interactive console", "Console do Werkzeug exposto", Severity.CRITICAL),
    ("/__debug__/", r"(?i)djdt|django debug toolbar", "Django debug toolbar exposto", Severity.MEDIUM),
    ("/debug/pprof/", r"(?i)profiles", "Go pprof exposto", Severity.MEDIUM),
    ("/backup.sql", r"(?i)(create table|insert into)", "Dump SQL acessível", Severity.CRITICAL),
    ("/db.sqlite3", r"SQLite format 3", "Banco SQLite acessível", Severity.CRITICAL),
    ("/database.sqlite", r"SQLite format 3", "Banco SQLite acessível", Severity.CRITICAL),
    ("/.vscode/sftp.json", r"(?i)password|host", "Credenciais de deploy (.vscode/sftp.json)", Severity.HIGH),
    ("/swagger.json", r'"(swagger|openapi)"', "Especificação OpenAPI pública", Severity.INFO),
    ("/openapi.json", r'"openapi"', "Especificação OpenAPI pública", Severity.INFO),
    ("/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D", r"__schema", "GraphQL introspection habilitado", Severity.LOW),
]

SECURITY_HEADERS = {
    "content-security-policy": ("Sem Content-Security-Policy", "CWE-693",
                                "Sem CSP, um XSS consegue carregar e executar qualquer script."),
    "x-content-type-options": ("Sem X-Content-Type-Options: nosniff", "CWE-693",
                               "O navegador pode interpretar arquivos como script (MIME sniffing)."),
    "x-frame-options": ("Sem proteção contra clickjacking", "CWE-1021",
                        "A página pode ser embutida num iframe malicioso."),
    "referrer-policy": ("Sem Referrer-Policy", "CWE-200", "URLs internas podem vazar para outros sites."),
}

ERROR_SIGNS = re.compile(
    r"(Traceback \(most recent call last\)|at [\w.$<>]+ \([^)]*:\d+:\d+\)|Exception in thread|"
    r"Stack trace:|Fatal error:|Warning: .* on line \d+|django\.core\.exceptions|"
    r"Whitelabel Error Page|NoMethodError|ActiveRecord::|PrismaClient\w*Error)"
)
SQL_ERRORS = re.compile(
    r"(?i)(SQL syntax.*MySQL|syntax error at or near|unterminated quoted string|SQLSTATE\[|"
    r"sqlite3\.OperationalError|SQLITE_ERROR|ORA-\d{5}|Microsoft OLE DB|PG::SyntaxError|"
    r"quoted string not properly terminated|psycopg2?\.errors|unrecognized token)"
)


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "link") and a.get("href"):
            self.urls.append(a["href"])
        elif tag in ("script", "iframe") and a.get("src"):
            self.urls.append(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action") or "", "method": (a.get("method") or "get").lower(), "fields": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            if (a.get("type") or "").lower() not in ("submit", "button", "file", "hidden"):
                self._form["fields"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


class Prober:
    def __init__(self, base: str, max_pages: int = 40):
        self.base = base.rstrip("/")
        self.host = urlparse(self.base).netloc
        self.max_pages = max_pages
        # redirecionamentos são seguidos à mão em _get, só dentro da sandbox
        self.client = httpx.Client(timeout=10, follow_redirects=False, verify=False,
                                   headers={"User-Agent": "VibeSec/0.1 (sandbox scan)"})
        self.out: list[Finding] = []

    def _f(self, **kw) -> None:
        kw.setdefault("tool", "vibesec-probe")
        kw.setdefault("confirmed", True)
        self.out.append(Finding(**kw))

    def _get(self, path_or_url: str, **kw) -> httpx.Response | None:
        url = path_or_url if path_or_url.startswith("http") else self.base + path_or_url
        for _ in range(6):
            if urlparse(url).netloc != self.host:  # trava: nunca sai da sandbox
                return None
            try:
                r = self.client.get(url, **kw)
            except httpx.HTTPError:
                return None
            if not r.is_redirect:
                return r
            url = urljoin(url, r.headers.get("location", "/"))
        return None

    def run(self) -> list[Finding]:
        home = self._get("/")
        if home is None:
            return self.out
        self.headers(home)
        self.cors()
        self.exposed_files()
        pages, forms = self.crawl(home)
        self.injection(pages, forms)
        self.errors()
        self.client.close()
        return self.out

    # ---------------------------------------------------------------- checks
    def headers(self, r: httpx.Response) -> None:
        h = {k.lower(): v for k, v in r.headers.items()}
        csp = h.get("content-security-policy", "")
        for name, (title, cwe, desc) in SECURITY_HEADERS.items():
            if name == "x-frame-options" and "frame-ancestors" in csp:
                continue
            if name not in h:
                self._f(title=title, severity=Severity.LOW, category=Category.WEB, url="/",
                        rule_id=f"missing-{name}", cwe=[cwe], description=desc,
                        remediation=f"Envie o cabeçalho {name} em todas as respostas.")
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            self._f(title="CSP permite unsafe-inline/unsafe-eval", severity=Severity.LOW, category=Category.WEB,
                    url="/", rule_id="weak-csp", cwe=["CWE-693"], evidence=csp[:200],
                    description="Esses valores anulam boa parte da proteção da CSP contra XSS.",
                    remediation="Use nonces ou hashes em vez de unsafe-inline.")
        for name in ("server", "x-powered-by", "x-aspnet-version"):
            v = h.get(name, "")
            if re.search(r"\d", v) or name == "x-powered-by" and v:
                self._f(title=f"Tecnologia/versão revelada no cabeçalho {name}", severity=Severity.LOW,
                        category=Category.WEB, url="/", rule_id=f"disclosure-{name}", cwe=["CWE-200"],
                        evidence=f"{name}: {v}", description="Ajuda o atacante a escolher exploits.",
                        remediation=f"Remova ou genericize o cabeçalho {name}.")

    def cors(self) -> None:
        evil = "https://evil.vibesec.test"
        r = self._get("/", headers={"Origin": evil})
        if r is None:
            return
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"
        if acao == evil:
            self._f(title="CORS reflete qualquer origem" + (" com credenciais" if acac else ""),
                    severity=Severity.HIGH if acac else Severity.MEDIUM, category=Category.WEB, url="/",
                    rule_id="cors-reflect", cwe=["CWE-942"], evidence=f"Origin: {evil} → ACAO: {acao}, ACAC: {acac}",
                    description="Qualquer site pode ler respostas da API usando a sessão do usuário logado."
                    if acac else "Qualquer site pode ler as respostas da API.",
                    remediation="Valide a origem contra uma lista fixa.")
        elif acao == "*" and acac:
            self._f(title="CORS * com credenciais", severity=Severity.MEDIUM, category=Category.WEB, url="/",
                    rule_id="cors-star-cred", cwe=["CWE-942"], evidence="ACAO: * / ACAC: true",
                    remediation="Liste as origens permitidas.")

    def exposed_files(self) -> None:
        baseline = self._get(f"/{uuid.uuid4().hex}")
        base_body = baseline.text if baseline is not None and baseline.status_code == 200 else None
        for path, check, title, sev in EXPOSED:
            r = self._get(path)
            if r is None or r.status_code != 200 or not r.content:
                continue
            if base_body is not None and r.text == base_body:  # SPA que devolve index.html para tudo
                continue
            if check and not re.search(check, r.text[:20000]):
                continue
            if check is None and "html" in r.headers.get("content-type", ""):
                continue
            self._f(title=title, severity=sev, category=Category.WEB, url=path, rule_id=f"exposed{path}",
                    cwe=["CWE-538"], evidence=_redact(r.text[:160]),
                    description=f"GET {path} respondeu 200 com conteúdo sensível.",
                    remediation="Bloqueie o caminho no servidor e tire o arquivo da pasta pública/da imagem.")

    def crawl(self, home: httpx.Response) -> tuple[list[str], list[dict]]:
        seen, queue, forms = {"/"}, [home], []
        pages: list[str] = []
        while queue and len(seen) < self.max_pages:
            r = queue.pop(0)
            if "html" not in r.headers.get("content-type", ""):
                continue
            p = _Links()
            try:
                p.feed(r.text)
            except Exception:  # HTML quebrado não pode derrubar o scan
                continue
            for f in p.forms:
                f["url"] = urljoin(str(r.url), f["action"])
                forms.append(f)
            for href in p.urls:
                u = urljoin(str(r.url), href).split("#")[0]
                pu = urlparse(u)
                if pu.netloc != self.host or re.search(r"\.(png|jpe?g|gif|svg|css|woff2?|ico|webp|mp4)$", pu.path):
                    continue
                key = pu.path + ("?" + "&".join(sorted(k for k, _ in parse_qsl(pu.query))) if pu.query else "")
                if key in seen:
                    continue
                seen.add(key)
                if pu.query:
                    pages.append(u)
                nr = self._get(u)
                if nr is not None:
                    queue.append(nr)
        return pages, forms

    def injection(self, pages: list[str], forms: list[dict]) -> None:
        marker = "vbs" + uuid.uuid4().hex[:6]
        xss = f'{marker}"><svg/onload={marker}>'
        targets: list[tuple[str, str, dict[str, str]]] = []
        for u in pages[:25]:
            pu = urlparse(u)
            params = dict(parse_qsl(pu.query))
            targets.append(("get", urlunparse(pu._replace(query="")), params))
        for f in forms[:15]:
            if f["fields"]:
                targets.append((f["method"], f["url"], {k: "1" for k in f["fields"]}))
        done: set[tuple[str, str]] = set()
        for method, url, params in targets:
            for name in params:
                if (url, name) in done:
                    continue
                done.add((url, name))
                path = urlparse(url).path or "/"
                for payload, kind in ((xss, "xss"), ("1'\"", "sqli")):
                    data = {**params, name: payload}
                    try:
                        if method == "post":
                            if urlparse(url).netloc != self.host:
                                continue
                            r = self.client.post(url, data=data)
                        else:
                            r = self._get(url + "?" + urlencode(data))
                    except httpx.HTTPError:
                        continue
                    if r is None:
                        continue
                    body = r.text[:200000]
                    if kind == "xss" and f"<svg/onload={marker}>" in body:
                        self._f(title=f"XSS refletido no parâmetro '{name}'", severity=Severity.HIGH,
                                category=Category.WEB, url=f"{method.upper()} {path}", rule_id=f"xss-reflected-{name}",
                                cwe=["CWE-79"], evidence=f"{name}={payload}",
                                description="O valor enviado volta na página sem escape: dá para executar "
                                            "JavaScript no navegador de quem clicar num link malicioso.",
                                remediation="Escape a saída no template e adicione uma CSP.")
                    if kind == "sqli" and (m := SQL_ERRORS.search(body)):
                        self._f(title=f"SQL injection (erro do banco) no parâmetro '{name}'",
                                severity=Severity.CRITICAL, category=Category.WEB, url=f"{method.upper()} {path}",
                                rule_id=f"sqli-error-{name}", cwe=["CWE-89"],
                                evidence=f"{name}=1'\" → {m.group(0)[:120]}",
                                description="Uma aspa no parâmetro quebrou a consulta SQL: a entrada vai direto "
                                            "para o banco. Dá para ler/alterar dados.",
                                remediation="Use consultas parametrizadas.")

    def errors(self) -> None:
        for path in (f"/{uuid.uuid4().hex}'\"<%", "/api/%ff", "/?id[]=1&id=%00"):
            r = self._get(path)
            if r is not None and (m := ERROR_SIGNS.search(r.text[:100000])):
                self._f(title="Stack trace / erro detalhado exposto", severity=Severity.MEDIUM,
                        category=Category.WEB, url=path.split("?")[0][:60], rule_id="verbose-errors",
                        cwe=["CWE-209"], evidence=m.group(0)[:160],
                        description="Erros mostram caminhos, código e versões para o visitante.",
                        remediation="Mostre uma página de erro genérica e registre os detalhes só no log.")
                return


def _redact(s: str) -> str:
    s = re.sub(r"(?m)^([A-Z_][A-Z0-9_]*\s*=\s*)(.{4})(.*)$", r"\1\2…", s)
    return " ".join(s.split())[:160]

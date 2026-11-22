"""Ataques reais contra a sandbox: nmap, nuclei, OWASP ZAP e captura de tráfego."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from vibesec.dynamic.sandbox import Sandbox
from vibesec.models import Category, Finding, Severity
from vibesec.runner import TOOLS, docker, run_container

RISKY_SERVICES = {
    # porta/serviço: (severidade, motivo)
    "redis": (Severity.HIGH, "Redis exposto costuma aceitar comandos sem senha (leitura de dados e RCE)."),
    "mongodb": (Severity.HIGH, "MongoDB exposto pode estar sem autenticação."),
    "mysql": (Severity.MEDIUM, "Banco MySQL acessível pela rede da aplicação."),
    "postgresql": (Severity.MEDIUM, "Banco Postgres acessível pela rede da aplicação."),
    "memcache": (Severity.HIGH, "Memcached sem autenticação."),
    "elasticsearch": (Severity.HIGH, "Elasticsearch sem autenticação expõe todos os índices."),
    "ftp": (Severity.MEDIUM, "FTP trafega senha em texto puro."),
    "telnet": (Severity.HIGH, "Telnet trafega tudo em texto puro."),
    "ssh": (Severity.LOW, "SSH dentro do container da aplicação aumenta a superfície de ataque."),
    "docker": (Severity.CRITICAL, "API do Docker exposta = controle total do host."),
}
DEBUG_PORTS = {
    9229: "Node.js inspector (--inspect) aberto: qualquer um na rede executa código no processo.",
    5678: "debugpy aberto: execução remota de código.",
    5005: "JDWP (debug Java) aberto: execução remota de código.",
    2375: "API do Docker sem TLS.",
}


# ---------------------------------------------------------------------- nmap
def nmap(sb: Sandbox, work: Path, depth: str) -> list[Finding]:
    ports = ["-p-"] if depth != "quick" else ["--top-ports", "1000"]
    args = ["-sV", "-Pn", "-T4", "--min-rate", "1500", "--open", "-oX", "-", *ports]
    if depth != "quick":
        args += ["-sC", "--script", "default,vuln,http-enum,http-headers,http-methods"]
    args.append("target")
    r = run_container(TOOLS["nmap"].image, args, [sb.net_int], timeout=1800)
    (work / "nmap.xml").write_text(r.stdout or "", encoding="utf-8")
    if "<nmaprun" not in (r.stdout or ""):
        raise RuntimeError((r.stderr or "nmap sem saída").strip()[-400:])
    return parse_nmap(r.stdout, sb.port)


def parse_nmap(xml: str, app_port: int | None) -> list[Finding]:
    out: list[Finding] = []
    root = ET.fromstring(xml[xml.find("<?xml") if "<?xml" in xml else xml.find("<nmaprun"):])
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        num = int(port.get("portid"))
        svc = port.find("service")
        name = svc.get("name", "?") if svc is not None else "?"
        product = " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else ""
        where = f"tcp/{num}"
        if num in DEBUG_PORTS:
            out.append(Finding(title=f"Porta de debug aberta ({num})", severity=Severity.CRITICAL,
                               category=Category.NETWORK, tool="nmap", url=where, rule_id=f"debug-port-{num}",
                               cwe=["CWE-489"], description=DEBUG_PORTS[num], confirmed=True,
                               remediation="Remova a flag de debug do comando de produção."))
        elif num != app_port:
            sev, why = RISKY_SERVICES.get(name, (Severity.LOW, "Porta extra além da porta da aplicação."))
            out.append(Finding(title=f"Serviço {name} exposto na porta {num}", severity=sev,
                               category=Category.NETWORK, tool="nmap", url=where, rule_id=f"open-port-{name}",
                               cwe=["CWE-668"], description=f"{why} {product}".strip(), confirmed=True,
                               remediation="Exponha só a porta da aplicação; serviços internos ficam em rede privada."))
        else:
            out.append(Finding(title=f"Porta da aplicação: {name} {product}".strip(), severity=Severity.INFO,
                               category=Category.NETWORK, tool="nmap", url=where, rule_id="app-port",
                               description="Serviço principal identificado.", confirmed=True))
        for script in port.findall("script"):
            text = script.get("output", "")
            if "VULNERABLE" in text and "NOT VULNERABLE" not in text:
                out.append(Finding(title=f"nmap {script.get('id')}: vulnerável", severity=Severity.HIGH,
                                   category=Category.NETWORK, tool="nmap", url=where,
                                   rule_id=f"nmap.{script.get('id')}", evidence=text.strip()[:600],
                                   confirmed=True, cve=re.findall(r"CVE-\d{4}-\d+", text)))
            elif script.get("id") == "http-methods" and re.search(r"\b(PUT|DELETE|TRACE)\b", text):
                out.append(Finding(title="Métodos HTTP perigosos habilitados", severity=Severity.LOW,
                                   category=Category.WEB, tool="nmap", url=where, rule_id="http-methods",
                                   evidence=text.strip()[:300], cwe=["CWE-650"], confirmed=True))
            elif script.get("id") == "http-enum" and text.strip():
                out.append(Finding(title="Caminhos interessantes encontrados (http-enum)", severity=Severity.INFO,
                                   category=Category.WEB, tool="nmap", url=where, rule_id="http-enum",
                                   evidence=text.strip()[:600], confirmed=True))
    return out


# -------------------------------------------------------------------- nuclei
def nuclei(sb: Sandbox, work: Path, depth: str) -> list[Finding]:
    args = ["-u", sb.internal_url, "-jsonl", "-silent", "-nc", "-ni", "-duc", "-rl", "100", "-timeout", "8"]
    if depth == "quick":
        args += ["-severity", "medium,high,critical", "-as"]
    elif depth == "standard":
        args += ["-severity", "low,medium,high,critical", "-as"]
    else:
        args += ["-severity", "info,low,medium,high,critical"]
    # pub: baixar templates na 1ª execução; int: alcançar o alvo
    r = run_container(TOOLS["nuclei"].image, args, [sb.net_pub, sb.net_int], timeout=3600,
                      extra=["-v", "vibesec-nuclei:/root"])
    (work / "nuclei.jsonl").write_text(r.stdout or "", encoding="utf-8")
    out = []
    for line in (r.stdout or "").splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get("info", {})
        cls = info.get("classification") or {}
        out.append(Finding(
            title=info.get("name", d.get("template-id")), severity=Severity.parse(info.get("severity")),
            category=Category.WEB, tool="nuclei", url=_internal_path(d.get("matched-at")),
            rule_id=f"nuclei.{d.get('template-id')}", description=(info.get("description") or "").strip(),
            remediation=info.get("remediation"), cwe=[c.upper() for c in cls.get("cwe-id") or []],
            cve=[c.upper() for c in cls.get("cve-id") or []],
            evidence=", ".join(d.get("extracted-results") or [])[:300] or d.get("matcher-name"),
            references=(info.get("reference") or [])[:3] if isinstance(info.get("reference"), list) else [],
            confirmed=True,
        ))
    return out


# ----------------------------------------------------------------------- zap
ZAP_RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}


def zap(sb: Sandbox, work: Path, depth: str) -> list[Finding]:
    zdir = work / "zap"
    zdir.mkdir(parents=True, exist_ok=True)
    script = "zap-full-scan.py" if depth == "deep" else "zap-baseline.py"
    minutes = {"quick": "1", "standard": "3", "deep": "10"}[depth]
    args = [script, "-t", sb.internal_url, "-J", "zap.json", "-I", "-m", minutes]
    if depth == "deep":
        args += ["-j"]  # spider AJAX também
    r = run_container(TOOLS["zap"].image, args, [sb.net_pub, sb.net_int], mounts={zdir: "/zap/wrk"},
                      timeout=7200, extra=["-u", "0"])
    report = zdir / "zap.json"
    if not report.exists():
        raise RuntimeError((r.stderr or r.stdout or "ZAP não gerou relatório").strip()[-400:])
    return parse_zap(json.loads(report.read_text(encoding="utf-8")))


def parse_zap(data: dict) -> list[Finding]:
    out = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            inst = (a.get("instances") or [{}])[0]
            cwe = a.get("cweid")
            out.append(Finding(
                title=a.get("alert") or a.get("name"), severity=ZAP_RISK.get(str(a.get("riskcode")), Severity.INFO),
                category=Category.WEB, tool="zap", url=_internal_path(inst.get("uri")),
                rule_id=f"zap.{a.get('pluginid')}", cwe=[f"CWE-{cwe}"] if cwe and cwe not in ("-1", "0") else [],
                description=_strip_html(a.get("desc")), remediation=_strip_html(a.get("solution")),
                evidence=" ".join(filter(None, [inst.get("method"), inst.get("param") and f"param={inst['param']}",
                                                inst.get("evidence")]))[:300] or None,
                references=[u for u in _strip_html(a.get("reference")).split() if u.startswith("http")][:3],
                confirmed=str(a.get("riskcode")) in ("2", "3") and str(a.get("confidence")) in ("2", "3", "4"),
            ))
    return out


# ------------------------------------------------------------------- tráfego
class Capture:
    """tcpdump no namespace de rede do alvo enquanto os ataques rodam."""

    def __init__(self, sb: Sandbox, work: Path):
        self.sb, self.work = sb, work
        self.name = f"vibesec-cap-{sb.id}"
        self.dir = work / "pcap"

    def start(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        docker("run", "-d", "--name", self.name, "--network", f"container:{self.sb.target}",
               "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN", "-v", f"{self.dir.resolve()}:/out",
               TOOLS["tshark"].image, "tcpdump", "-i", "any", "-U", "-s", "0", "-w", "/out/traffic.pcap",
               check=True)

    def stop_and_analyze(self) -> list[Finding]:
        docker("stop", "-t", "3", self.name)
        docker("rm", "-f", self.name)
        if not (self.dir / "traffic.pcap").exists():
            raise RuntimeError("captura vazia")
        sep = "@@VIBESEC@@"
        q = [
            "tshark -r /out/traffic.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name",
            "tshark -r /out/traffic.pcap -Y http.set_cookie -T fields -e http.set_cookie",
            "tshark -r /out/traffic.pcap -Y 'http.authorization' -T fields -e http.request.uri -e http.authorization",
            "tshark -r /out/traffic.pcap -Y 'urlencoded-form.key' -T fields -e http.request.uri -e urlencoded-form.key",
            "tshark -r /out/traffic.pcap -q -z conv,tcp",
        ]
        cmd = f" ; echo {sep} ; ".join(q)
        r = docker("run", "--rm", "-v", f"{self.dir.resolve()}:/out", TOOLS["tshark"].image, "sh", "-c", cmd,
                   timeout=600)
        parts = (r.stdout or "").split(sep)
        parts += [""] * (5 - len(parts))
        return analyze_traffic(*[p.strip() for p in parts[:5]])


def analyze_traffic(dns: str, cookies: str, auth: str, forms: str, convs: str) -> list[Finding]:
    out: list[Finding] = []
    domains = sorted({d.strip().rstrip(".") for d in dns.splitlines()
                      if d.strip() and not re.search(r"(^target$|\.internal$|^localhost$|^vibesec-)", d.strip())})
    if domains:
        out.append(Finding(
            title=f"A aplicação tentou acessar {len(domains)} domínio(s) externo(s)", severity=Severity.LOW,
            category=Category.TRAFFIC, tool="tshark", rule_id="egress-dns", confirmed=True,
            evidence=", ".join(domains[:25]),
            description="Na sandbox sem internet, o app tentou resolver estes domínios. Confira se são esperados "
                        "(APIs, telemetria) ou se algum pacote está mandando dados para fora.",
            remediation="Revise dependências que fazem chamadas de rede e bloqueie telemetria desnecessária.",
        ))
    for raw in sorted(set(cookies.splitlines())):
        for c in raw.split(","):
            c = c.strip()
            if not c or "=" not in c:
                continue
            name = c.split("=", 1)[0]
            flags = c.lower()
            missing = [f for f in ("httponly", "samesite") if f not in flags]
            if missing and re.search(r"(?i)(sess|auth|token|jwt|sid|login)", name):
                out.append(Finding(
                    title=f"Cookie de sessão '{name}' sem {', '.join(missing)}", severity=Severity.MEDIUM,
                    category=Category.TRAFFIC, tool="tshark", rule_id=f"cookie-flags-{name}", confirmed=True,
                    cwe=["CWE-1004"], evidence=c[:200],
                    description="Sem HttpOnly o JavaScript (e um XSS) lê o cookie; sem SameSite ele vai junto em "
                                "requisições de outros sites (CSRF).",
                    remediation="Defina HttpOnly; Secure; SameSite=Lax (ou Strict) nos cookies de sessão.",
                ))
    if auth.strip():
        basic = [line for line in auth.splitlines() if "Basic " in line]
        if basic:
            out.append(Finding(
                title="Credenciais HTTP Basic trafegando", severity=Severity.MEDIUM, category=Category.TRAFFIC,
                tool="tshark", rule_id="basic-auth", confirmed=True, cwe=["CWE-319"],
                evidence=basic[0].split("\t")[0],
                description="Basic auth é só base64: sem HTTPS a senha é lida por quem estiver na rede.",
                remediation="Garanta HTTPS obrigatório (HSTS) e prefira tokens de sessão.",
            ))
    pw_forms = [line for line in forms.splitlines() if re.search(r"(?i)pass|senha|pwd", line)]
    if pw_forms:
        out.append(Finding(
            title="Formulário de senha enviado (capturado no tráfego)", severity=Severity.INFO,
            category=Category.TRAFFIC, tool="tshark", rule_id="password-form", confirmed=True,
            evidence=pw_forms[0][:200],
            description="Senhas enviadas por formulário: em produção isso só pode acontecer sobre HTTPS.",
            remediation="Force HTTPS e ative HSTS.",
        ))
    return out


def _internal_path(url: str | None) -> str | None:
    if not url:
        return None
    return re.sub(r"^https?://target(:\d+)?", "", url) or "/"


def _strip_html(s: str | None) -> str:
    return " ".join(re.sub(r"<[^>]+>", " ", s or "").split())

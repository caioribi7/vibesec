"""Detector de segredos embutido (funciona sem nenhuma ferramenta instalada)."""

from __future__ import annotations

import base64
import json
import math
import re

from vibesec.models import Category, Finding, Severity
from vibesec.repo import iter_files, read_text
from vibesec.scanners.base import ScanContext, Scanner

C, H, M = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM

# (id, título, regex, severidade)
PATTERNS: list[tuple[str, str, re.Pattern, Severity]] = [
    ("aws-access-key", "Chave de acesso AWS", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), C),
    ("aws-secret-key", "Secret key AWS",
     re.compile(r"(?i)aws.{0,20}?(secret|private).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"), C),
    ("github-token", "Token do GitHub", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"), C),
    ("github-pat", "Token fine-grained do GitHub", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), C),
    ("anthropic-key", "Chave da API Anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{30,}\b"), C),
    ("openai-key", "Chave da API OpenAI", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{32,}\b"), C),
    ("stripe-live", "Chave secreta Stripe (live)", re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b"), C),
    ("google-api-key", "Chave de API Google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), H),
    ("slack-token", "Token do Slack", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), H),
    ("slack-webhook", "Webhook do Slack",
     re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), H),
    ("discord-webhook", "Webhook do Discord",
     re.compile(r"https://(?:canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"), H),
    ("telegram-bot", "Token de bot do Telegram", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b"), H),
    ("sendgrid", "Chave SendGrid", re.compile(r"\bSG\.[\w\-]{22}\.[\w\-]{43}\b"), H),
    ("twilio", "Chave Twilio", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), M),
    ("mercadopago", "Access token Mercado Pago", re.compile(r"\bAPP_USR-\d{10,}-\d{6}-[0-9a-f]{32}-\d+\b"), C),
    ("private-key", "Chave privada", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"), C),
    ("db-url", "URL de banco com senha",
     re.compile(r"\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:'\"/@]+:([^\s'\"@]{3,})@[^\s'\"]+"), H),
    ("hardcoded-password", "Senha escrita no código",
     re.compile(r"(?i)\b(password|passwd|senha|pwd|secret|api_?key|token)\b\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]"), M),
]

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

PLACEHOLDERS = re.compile(
    r"(?i)(example|exemplo|placeholder|changeme|your[_-]?|seu[_-]?|sua[_-]?|xxx|\*\*\*|<[^>]+>|\$\{|"
    r"process\.env|os\.environ|getenv|env\(|\{\{|dummy|fake|test(?:ing)?|sample|redacted|password123|localhost)"
)

TRIVIAL = {"password", "postgres", "root", "admin", "secret", "senha", "pass", "123456", "12345678", "mysql",
            "supersecret", "qwerty"}

SKIP_SUFFIX ={".lock", ".min.js", ".map", ".svg", ".snap"}
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "go.sum"}
ENV_FILE = re.compile(r"^\.env(\..+)?$")
ENV_SAFE = re.compile(r"(?i)\.(example|sample|template|dist|defaults?)$")


def mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    return f"{v[:4]}…{v[-4:]} ({len(v)} chars)"


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def jwt_payload(token: str) -> dict | None:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except (ValueError, IndexError):
        return None


def is_client_side(rel: str) -> bool:
    r = rel.lower()
    return any(x in r for x in ("public/", "static/", "client", "components/", "app/", "pages/", "src/"))  \
        and r.endswith((".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html"))


class BuiltinSecretsScanner(Scanner):
    name = "vibesec-secrets"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_files(ctx.root):
            rel = path.relative_to(ctx.root).as_posix()
            if path.name in SKIP_NAMES or any(rel.endswith(s) for s in SKIP_SUFFIX):
                continue

            if ENV_FILE.match(path.name) and not ENV_SAFE.search(path.name):
                findings.append(Finding(
                    title=f"Arquivo {path.name} versionado no repositório",
                    severity=H, category=Category.SECRET, tool=self.name, file=rel,
                    rule_id="committed-env-file", cwe=["CWE-538"],
                    description="Arquivos .env guardam credenciais e não devem ir para o git: qualquer "
                                "pessoa com acesso ao repositório (ou ao histórico) lê as chaves.",
                    remediation="Remova o arquivo do git (`git rm --cached`), adicione `.env*` ao .gitignore, "
                                "troque TODAS as chaves que estavam nele e limpe o histórico (git filter-repo).",
                ))

            text = read_text(path)
            if not text:
                continue
            findings += self._scan_text(rel, text)
        return findings

    def _scan_text(self, rel: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        test_file = bool(re.search(r"(?i)(^|/)(tests?|__tests__|spec|fixtures?|mocks?)/|\.(test|spec)\.", rel))
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 2000:
                continue
            for rid, title, rx, sev in PATTERNS:
                for m in rx.finditer(line):
                    secret = m.group(m.lastindex or 0) if rid in ("hardcoded-password", "db-url", "aws-secret-key") \
                        else m.group(0)
                    if "EXAMPLE" in secret or "example" in secret:  # chaves de exemplo da documentação
                        continue
                    if rid in ("hardcoded-password", "db-url"):
                        if PLACEHOLDERS.search(secret) or entropy(secret) < 2.5 or secret.lower() in TRIVIAL:
                            continue
                    if rid == "db-url" and re.search(r"@(localhost|127\.0\.0\.1|0\.0\.0\.0)[:/]", m.group(0)):
                        continue  # banco local de desenvolvimento
                    if PLACEHOLDERS.search(line) and rid in ("hardcoded-password",):
                        continue
                    s = Severity.LOW if test_file else sev
                    out.append(Finding(
                        title=title, severity=s, category=Category.SECRET, tool=self.name, file=rel,
                        line=lineno, rule_id=rid, cwe=["CWE-798"], evidence=mask(secret),
                        description=f"{title} encontrada em texto puro no código.",
                        remediation="Revogue/troque a credencial agora, mova para variável de ambiente ou "
                                    "cofre de segredos e remova do histórico do git.",
                    ))
            for m in JWT_RE.finditer(line):
                payload = jwt_payload(m.group(0)) or {}
                role = payload.get("role")
                if role == "service_role":
                    out.append(Finding(
                        title="Chave service_role do Supabase exposta",
                        severity=Severity.LOW if test_file else C, category=Category.SECRET, tool=self.name,
                        file=rel, line=lineno, rule_id="supabase-service-role", cwe=["CWE-798", "CWE-284"],
                        evidence=mask(m.group(0)),
                        description="A service_role ignora todas as políticas RLS: quem tiver essa chave lê, "
                                    "altera e apaga qualquer dado do banco."
                                    + (" O arquivo parece ir para o navegador." if is_client_side(rel) else ""),
                        remediation="Gere uma nova service_role no painel do Supabase, use-a só no servidor "
                                    "(variável sem prefixo NEXT_PUBLIC_/VITE_) e use a anon key no cliente.",
                    ))
                elif role not in ("anon", None) or (payload and "exp" not in payload and not test_file):
                    out.append(Finding(
                        title="Token JWT fixo no código", severity=M, category=Category.SECRET,
                        tool=self.name, file=rel, line=lineno, rule_id="hardcoded-jwt", cwe=["CWE-798"],
                        evidence=mask(m.group(0)),
                        description=f"JWT com payload {json.dumps(payload)[:120]} escrito no código.",
                        remediation="Não versionar tokens; gere-os em tempo de execução.",
                    ))
        return out

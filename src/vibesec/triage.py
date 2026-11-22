"""Triagem determinística: o que a IA fazia, com regras auditáveis e sem enviar código para fora.

Para cada achado, decide:
  * se é falso positivo (código de teste, string constante, valor já validado);
  * a confiança (high/medium/low) de que é explorável, olhando o fluxo de dados no trecho;
  * a severidade final;
  * uma explicação curta em português.
Depois cruza o código com o que foi explorado na sandbox, monta cadeias de ataque
e escreve o resumo executivo com as correções mais urgentes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from vibesec.models import Category, Finding, ScanResult, Severity

# ------------------------------------------------------------------ vocabulário

# De onde vem dado controlado pelo usuário, por framework
SOURCES = re.compile(
    r"(request\.(args|form|json|values|data|get_json|files|cookies|headers|GET|POST|body|query_params|path_params)"
    r"|req\.(query|body|params|headers|cookies)|\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)"
    r"|searchParams|useSearchParams|formData\.get|params\.\w+|params\[|ctx\.(query|params|request)"
    r"|c\.(Query|Param|PostForm|FormValue)|r\.(URL\.Query|FormValue|PostFormValue)|getParameter\("
    r"|@RequestParam|@PathVariable|@RequestBody|event\.(body|queryStringParameters|pathParameters)"
    r"|sys\.argv|\binput\(|Query\(|Body\(|Form\(|Path\()"
)
# Funções que neutralizam o dado para aquele tipo de falha
SANITIZERS = {
    "CWE-89": re.compile(r"(\?\s*[,)]|%s\s*['\"]\s*,|\$\d|:\w+\b.*,\s*\{|bindparam|escape_string|quote_ident|\bint\(|parseInt|Number\()"),
    "CWE-78": re.compile(r"(shlex\.quote|escapeshellarg|execFile|spawn\(\s*['\"][\w./-]+['\"]\s*,\s*\[)"),
    "CWE-79": re.compile(r"(DOMPurify|sanitize|bleach\.clean|escape\(|escapeHtml|he\.encode|textContent)"),
    "CWE-22": re.compile(r"(secure_filename|path\.basename|os\.path\.basename|realpath.*startswith|normalize.*startsWith)"),
    "CWE-918": re.compile(r"(allowlist|whitelist|ALLOWED_HOSTS|allowedHosts|isAllowedUrl)"),
    "CWE-601": re.compile(r"(url_has_allowed_host|is_safe_url|startsWith\(['\"]/['\"]\)|startswith\(['\"]/['\"]\))"),
}
VALIDATION = re.compile(r"(\.parse\(|safeParse|zod|z\.object|pydantic|BaseModel|Joi\.|yup\.|validator\.|class-validator|isUUID|isInt)")

# Falhas cuja exploração depende de dado externo chegar até o ponto vulnerável
TAINT_CWES = {"CWE-89", "CWE-78", "CWE-94", "CWE-95", "CWE-79", "CWE-22", "CWE-918", "CWE-601", "CWE-1336", "CWE-502"}
INTERPOLATION = re.compile(r"(\{[^}]*\}|\$\{|%\s*\(|%s|\+\s*\w|\w\s*\+|\.format\(|\bconcat\()")

TEST_PATH = re.compile(r"(?i)(^|/)(tests?|__tests__|spec|specs|fixtures?|mocks?|examples?|samples?|docs?|demo)/|"
                       r"\.(test|spec|stories)\.|_test\.(py|go)$|test_\w+\.py$")
VENDOR_PATH = re.compile(r"(?i)(^|/)(vendor|third_party|node_modules|dist|build|public/assets)/|\.min\.js$")

SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _shift(sev: Severity, steps: int, floor: Severity = Severity.INFO, ceil: Severity = Severity.CRITICAL) -> Severity:
    i = max(SEV_ORDER.index(floor), min(SEV_ORDER.index(ceil), SEV_ORDER.index(sev) + steps))
    return SEV_ORDER[i]


def _conf(level: str, steps: int) -> str:
    order = ["low", "medium", "high"]
    return order[max(0, min(2, order.index(level) + steps))]


# ------------------------------------------------------------------ leitura de código

class SourceCache:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self._cache: dict[str, list[str] | None] = {}

    def lines(self, rel: str | None) -> list[str] | None:
        if not rel:
            return None
        if rel not in self._cache:
            p = (self.root / rel)
            try:
                p = p.resolve()
                if not p.is_relative_to(self.root):
                    raise ValueError
                self._cache[rel] = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except (OSError, ValueError):
                self._cache[rel] = None
        return self._cache[rel]

    def function_window(self, rel: str, line: int, up: int = 40) -> list[str]:
        """Trecho da função que contém a linha (heurística por indentação/def/function)."""
        src = self.lines(rel) or []
        if not src or line < 1 or line > len(src):
            return []
        start = line - 1
        target_indent = len(src[start]) - len(src[start].lstrip())
        for i in range(line - 2, max(-1, line - 2 - up), -1):
            s = src[i]
            stripped = s.lstrip()
            if not stripped:
                continue
            indent = len(s) - len(stripped)
            start = i
            if indent < target_indent and re.match(
                    r"(async\s+)?(def|function|func|fn|public|private|protected|export|const\s+\w+\s*=|router\.|app\.|@)",
                    stripped):
                break
        return src[start:line + 2]


# ------------------------------------------------------------------ regras por achado

@dataclass
class Verdict:
    false_positive: bool = False
    confidence: str = "medium"
    severity_shift: int = 0
    notes: list[str] | None = None

    def note(self, s: str) -> None:
        self.notes = (self.notes or []) + [s]


def assess(f: Finding, src: SourceCache) -> Verdict:
    v = Verdict(confidence="high" if f.confirmed else "medium")
    path = f.file or ""

    if f.confirmed:
        v.note("Explorado com sucesso na sandbox: não é teórico.")
        return v

    if path and VENDOR_PATH.search(path):
        v.false_positive = True
        v.note("Código de terceiros/gerado; corrija atualizando a dependência, não editando o arquivo.")
        return v

    if path and TEST_PATH.search(path) and f.category != Category.DEPENDENCY:
        v.confidence = "low"
        v.severity_shift = -2
        v.note("Está em teste/exemplo/documentação: não roda em produção, mas não deixe credencial real aqui.")
        return v

    if f.category == Category.SECRET:
        generic = f.rule_id in ("hardcoded-password", "hardcoded-jwt") or (f.rule_id or "").startswith("gitleaks.generic")
        v.confidence = "medium" if generic else "high"
        v.note("Trate como vazada: troque a credencial, tirar do código não basta (o git guarda o histórico).")
        return v

    if f.category == Category.DEPENDENCY:
        has_fix = bool(f.remediation and "Atualize" in f.remediation and " para " in f.remediation)
        v.confidence = "medium"
        if not has_fix:
            v.note("Ainda sem versão corrigida publicada.")
        if path.endswith(("package-lock.json", "yarn.lock", "pnpm-lock.yaml")) and f.severity.rank <= Severity.MEDIUM.rank:
            v.note("Dependência transitiva/indireta é comum aqui; confira se o código usa a parte vulnerável.")
        return v

    cwes = set(f.cwe)
    if not (cwes & TAINT_CWES) or not f.file or not f.line:
        return v

    lines = src.lines(f.file)
    if not lines or f.line > len(lines):
        return v
    sink = lines[f.line - 1]
    window = src.function_window(f.file, f.line)
    window_text = "\n".join(window)

    # 1) o ponto vulnerável recebe algo variável?
    if cwes & {"CWE-89", "CWE-78"} and not INTERPOLATION.search(sink) and not SOURCES.search(sink):
        v.false_positive = True
        v.note("O comando/consulta é uma string fixa, sem valor variável: não há como injetar.")
        return v

    # 2) a entrada do usuário chega até aqui?
    tainted = bool(SOURCES.search(window_text))
    # 3) existe neutralização específica para esse tipo de falha?
    sanitized = any(SANITIZERS[c].search(sink) or SANITIZERS[c].search("\n".join(window[-4:]))
                    for c in cwes if c in SANITIZERS)
    validated = bool(VALIDATION.search(window_text))

    if tainted and not sanitized:
        v.confidence = "high"
        v.severity_shift = 1 if f.severity == Severity.MEDIUM else 0
        src_name = SOURCES.search(window_text).group(0)
        v.note(f"Entrada do usuário ({src_name}) chega a este ponto sem tratamento.")
    elif sanitized:
        v.confidence = "low"
        v.severity_shift = -1
        v.note("Há tratamento específico para esse tipo de falha no trecho; confira se cobre todos os caminhos.")
    elif validated:
        v.confidence = "low"
        v.severity_shift = -1
        v.note("O dado passa por validação de esquema antes; o risco cai, mas a forma segura ainda é parametrizar.")
    else:
        v.confidence = "medium"
        v.note("Não achei a origem do dado nesta função; se vier do usuário por outro caminho, é explorável.")
    return v


# ------------------------------------------------------------------ correlação código x runtime

ROUTE_LITERAL = '["\'`]{path}["\'`/?]'
ROUTE_DECL = re.compile(
    r"(@\w+\.(route|get|post|put|patch|delete|api_route)\(|\b(app|router|server|api)\.(get|post|put|patch|delete|all|route)\("
    r"|@(Get|Post|Put|Patch|Delete|RequestMapping|GetMapping|PostMapping)\b|HandleFunc\(|export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b)"
)


def correlate_runtime(result: ScanResult, src: SourceCache) -> int:
    """Se a sandbox explorou SQLi em GET /user, o achado estático de SQLi no arquivo da rota /user vira confirmado."""
    confirmed = [f for f in result.findings if f.confirmed and f.cwe and f.url and f.category == Category.WEB]
    linked = 0
    for dyn in confirmed:
        path = re.sub(r"^(GET|POST|PUT|DELETE|PATCH)\s+", "", dyn.url).split("?")[0].rstrip("/")
        if not path or path == "/":
            continue
        rx = re.compile(ROUTE_LITERAL.format(path=re.escape(path)))
        for st in result.findings:
            if st.confirmed or not st.file or not st.line or not set(st.cwe) & set(dyn.cwe):
                continue
            lines = src.lines(st.file) or []
            # a falha precisa estar dentro do handler: entre a declaração da rota e a próxima rota declarada
            any_route = [i + 1 for i, line in enumerate(lines) if ROUTE_DECL.search(line)]
            routes = [i + 1 for i, line in enumerate(lines) if rx.search(line)]

            def handler_end(start: int) -> int:
                nxt = [r for r in any_route if r > start]
                return min(nxt[0] - 1 if nxt else len(lines), start + 80)

            if any(r <= st.line <= handler_end(r) for r in routes):
                st.confirmed = True
                st.false_positive = False
                st.confidence = "high"
                st.notes = f"Confirmado em runtime: a sandbox explorou esta falha em {dyn.url}. " + (st.notes or "")
                linked += 1
    return linked


# ------------------------------------------------------------------ cadeias de ataque

def _has(findings: list[Finding], *, rule: str | None = None, cwe: str | None = None, confirmed: bool | None = None,
         prefix: str | None = None) -> Finding | None:
    for f in findings:
        if rule and f.rule_id != rule:
            continue
        if prefix and not (f.rule_id or "").startswith(prefix):
            continue
        if cwe and cwe not in f.cwe:
            continue
        if confirmed is not None and f.confirmed != confirmed:
            continue
        return f
    return None


def attack_chains(findings: list[Finding]) -> list[str]:
    chains: list[str] = []
    service = _has(findings, rule="supabase-service-role") or _has(findings, rule="next-public-secret")
    rls = _has(findings, rule="rls-disabled") or _has(findings, rule="rls-permissive")
    if service and rls:
        chains.append(f"**Banco aberto pela internet:** a chave em `{service.location}` vai para o navegador e o RLS "
                      f"está desligado/permissivo (`{rls.location}`). Qualquer visitante lê e altera todas as tabelas.")
    elif rls:
        chains.append(f"**Tabela sem proteção:** com o RLS desligado (`{rls.location}`), a anon key, que é pública, "
                      "já basta para ler e escrever a tabela pela API REST do Supabase.")
    sqli = _has(findings, cwe="CWE-89", confirmed=True)
    if sqli:
        chains.append(f"**Vazamento do banco:** SQL injection confirmado em `{sqli.location}`. Com isso dá para ler "
                      "usuários e senhas, e às vezes escrever ou apagar dados.")
    rce = (_has(findings, rule="exposed/console") or _has(findings, prefix="debug-port-")
           or _has(findings, cwe="CWE-1336", confirmed=True) or _has(findings, cwe="CWE-94", confirmed=True))
    if rce:
        chains.append(f"**Controle do servidor:** `{rce.location}` permite executar código no servidor. A partir daí "
                      "o atacante lê as variáveis de ambiente (chaves de API, banco) e se move para outros serviços.")
    xss = _has(findings, cwe="CWE-79", confirmed=True)
    cookie = _has(findings, prefix="cookie-flags-")
    if xss and cookie:
        chains.append(f"**Sequestro de sessão:** XSS em `{xss.location}` + cookie `{cookie.rule_id[13:]}` sem HttpOnly "
                      "= um link malicioso rouba a sessão de quem clicar, inclusive admins.")
    elif xss:
        chains.append(f"**Ataque ao usuário:** XSS em `{xss.location}` executa JavaScript no navegador da vítima "
                      "(ações em nome dela, phishing dentro do seu domínio).")
    leak = _has(findings, rule="exposed/.env") or _has(findings, rule="exposed/.git/HEAD") or \
        _has(findings, rule="exposed/.git/config")
    if leak:
        chains.append(f"**Credenciais públicas:** `{leak.location}` está acessível pela web; quem baixar tem as "
                      "chaves e/ou o código-fonte inteiro.")
    cors = _has(findings, rule="cors-reflect")
    if cors and cors.severity.rank >= Severity.HIGH.rank:
        chains.append("**Leitura de dados entre sites:** o CORS aceita qualquer origem com credenciais; um site "
                      "malicioso lê as respostas da sua API usando a sessão do usuário logado.")
    egress = _has(findings, rule="egress-dns")
    if egress:
        chains.append(f"**Saída de dados:** o app tentou falar com domínios externos ({(egress.evidence or '')[:120]}). "
                      "Confira se algum é inesperado (telemetria, pacote comprometido).")
    return chains


# ------------------------------------------------------------------ resumo


# correção padrão quando a ferramenta não traz texto de remediação
FIX_BY_CWE = {
    "CWE-89": "Use consultas parametrizadas (placeholders) ou o ORM, nunca concatene entrada do usuário",
    "CWE-78": "Não use shell; passe uma lista de argumentos e valide a entrada contra uma lista permitida",
    "CWE-79": "Escape a saída (templates com autoescape) e não monte HTML com entrada do usuário",
    "CWE-94": "Nunca avalie ou renderize como template algo vindo do usuário",
    "CWE-1336": "Use render_template com arquivo fixo e passe a entrada só como variável",
    "CWE-502": "Não desserialize dados não confiáveis; use JSON",
    "CWE-489": "Desligue o modo debug em produção",
    "CWE-250": "Rode o container com um usuário sem privilégios (USER no Dockerfile)",
    "CWE-798": "Tire o segredo do código, revogue a credencial e use variável de ambiente ou cofre",
    "CWE-327": "Use um algoritmo forte (bcrypt/argon2 para senhas, SHA-256+ para integridade)",
    "CWE-22": "Normalize o caminho e confira que ele fica dentro da pasta permitida",
    "CWE-918": "Valide o destino contra uma lista permitida antes de fazer a requisição",
}


def first_sentence(s: str | None) -> str:
    """Primeira frase sem cortar reticências nem código ('... WHERE id = %s')."""
    s = " ".join((s or "").split())
    return re.split(r"(?<=[a-zà-ú0-9)\]])\.\s", s, maxsplit=1)[0].rstrip(".")


def summary(result: ScanResult) -> str:
    act = result.active
    c = result.counts()
    confirmed = [f for f in act if f.confirmed and f.severity.rank >= Severity.MEDIUM.rank]
    fps = sum(1 for f in result.findings if f.false_positive)
    serious = c["critical"] + c["high"]

    if not serious and not c["medium"]:
        status = "Nenhuma falha relevante encontrada nas verificações executadas."
    elif confirmed:
        status = (f"{len(confirmed)} falha(s) foram **exploradas de verdade** na sandbox e {serious} são de severidade "
                  "alta ou crítica. Não publique como está.")
    elif serious:
        status = f"{serious} achado(s) alto(s)/crítico(s) no código, ainda sem confirmação em runtime."
    else:
        status = f"Sem falhas graves; {c['medium']} ponto(s) de severidade média para endurecer."
    lines = [f"Nota **{result.score}/100 ({result.grade})**. {status}"]
    if fps:
        lines.append(f"A triagem descartou {fps} falso(s) positivo(s).")

    conf_rank = {"high": 2, "medium": 1, "low": 0}
    todo, seen = [], set()
    for f in sorted(act, key=lambda f: (-int(f.confirmed), -f.severity.rank, -conf_rank[f.confidence])):
        if f.severity.rank < Severity.MEDIUM.rank:
            continue
        key = (f.rule_id or f.title).split(".")[-1]
        if key in seen:
            continue
        seen.add(key)
        fix = first_sentence(f.remediation) or next((FIX_BY_CWE[c] for c in f.cwe if c in FIX_BY_CWE), "")
        tag = " (explorado)" if f.confirmed else ""
        todo.append(f"{len(todo) + 1}. **{f.title}**{tag} em `{f.location}`" + (f": {fix}." if fix else "."))
        if len(todo) == 5:
            break
    if todo:
        lines += ["", "**Corrija primeiro:**", *todo]

    chains = attack_chains(act)
    if chains:
        lines += ["", "**Cadeias de ataque possíveis:**", *[f"- {ch}" for ch in chains]]
    return "\n".join(lines)


# ------------------------------------------------------------------ entrada

def triage(result: ScanResult, root: Path) -> dict[str, int]:
    src = SourceCache(root)
    stats = {"fp": 0, "up": 0, "down": 0, "linked": 0}
    for f in result.findings:
        v = assess(f, src)
        old = f.severity
        f.false_positive = v.false_positive
        f.confidence = v.confidence
        f.severity = _shift(f.severity, v.severity_shift, floor=Severity.INFO)
        if "+" in f.tool and not f.false_positive:  # ferramentas diferentes concordam
            f.confidence = _conf(f.confidence, 1)
        if v.notes:
            f.notes = " ".join(v.notes)
        stats["fp"] += f.false_positive
        stats["up"] += f.severity.rank > old.rank
        stats["down"] += f.severity.rank < old.rank
    stats["linked"] = correlate_runtime(result, src)
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    result.findings.sort(key=lambda f: (f.false_positive, -f.severity.rank, not f.confirmed,
                                        conf_rank[f.confidence], f.category.value, f.location))
    result.summary = summary(result)
    return stats

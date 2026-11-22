"""Regras SAST embutidas, focadas nos erros mais comuns de apps feitos no embalo (vibe coding)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from vibesec.models import Category, Finding, Severity
from vibesec.repo import iter_files, read_text
from vibesec.scanners.base import ScanContext, Scanner

PY = (".py",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")
PHP = (".php",)
JAVA = (".java", ".kt")
GO = (".go",)
RB = (".rb",)
ANY_CODE = PY + JS + PHP + JAVA + GO + RB + (".cs",)
SQL = (".sql",)

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    exts: tuple[str, ...]
    pattern: re.Pattern
    severity: Severity
    cwe: str
    description: str
    remediation: str
    category: Category = Category.CODE


def r(rx: str, flags: int = 0) -> re.Pattern:
    return re.compile(rx, flags)


SQL_KW = r"(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|ORDER\s+BY)"

RULES: list[Rule] = [
    # ---------- Injeção ----------
    Rule("sqli-fstring", "SQL montado com f-string/format (SQL injection)", PY,
         r(rf"""(?i)(execute|executemany|raw|text)\s*\(\s*f?["'].*{SQL_KW}.*(\{{|%s?["']\s*%|["']\s*\+|\.format\()"""),
         H, "CWE-89", "A consulta concatena valores no texto do SQL; um usuário pode injetar comandos no banco.",
         "Use parâmetros: cursor.execute('... WHERE id = %s', (id,)) ou o ORM."),
    Rule("sqli-concat-js", "SQL montado com concatenação/template (SQL injection)", JS,
         r(rf"""(?i)(query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*[`"'].*{SQL_KW}.*(\$\{{|[`"']\s*\+)"""),
         H, "CWE-89", "Valores interpolados diretamente no SQL permitem SQL injection.",
         "Use placeholders ($1, ?) ou tagged templates seguros (Prisma $queryRaw``, sql``)."),
    Rule("sqli-php", "SQL com variável interpolada (SQL injection)", PHP,
         r(rf"""(?i)(mysqli_query|->query|->exec)\s*\(.*{SQL_KW}.*(\$_(GET|POST|REQUEST|COOKIE)|\.\s*\$)"""),
         C, "CWE-89", "Entrada do usuário vai direto para o SQL.", "Use prepared statements (PDO::prepare)."),
    Rule("cmd-injection-py", "Comando do sistema com shell=True / os.system", PY,
         r(r"(subprocess\.(run|call|Popen|check_output|check_call)\(.*shell\s*=\s*True|os\.system\(|os\.popen\()"),
         H, "CWE-78", "Executar comandos via shell com dados variáveis permite injeção de comandos no servidor.",
         "Passe a lista de argumentos sem shell=True e valide as entradas."),
    Rule("cmd-injection-js", "child_process.exec com dado dinâmico", JS,
         r(r"""(child_process\.)?\bexec(Sync)?\s*\(\s*(`[^`]*\$\{|[^,)]*\+)"""),
         H, "CWE-78", "exec() roda no shell; interpolar entrada do usuário permite executar comandos.",
         "Use execFile/spawn com array de argumentos e valide a entrada."),
    Rule("code-eval-js", "eval / new Function", JS, r(r"(?<![\w.])(eval|new\s+Function)\s*\("),
         H, "CWE-95", "Executa texto como código; com entrada externa vira execução remota.",
         "Remova eval; use JSON.parse ou um mapa de funções permitidas."),
    Rule("code-eval-py", "eval/exec em Python", PY, r(r"(?<![\w.])(eval|exec)\s*\((?!\s*\))"),
         H, "CWE-95", "eval/exec executam código arbitrário.", "Use ast.literal_eval ou parsing explícito."),
    Rule("php-rce", "Execução de código/comando em PHP", PHP,
         r(r"(?i)\b(eval|assert|system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$"),
         C, "CWE-94", "Função perigosa recebendo variável.", "Remova ou valide com lista de permitidos."),
    Rule("ssti-flask", "render_template_string com dado dinâmico (SSTI)", PY,
         r(r"render_template_string\s*\(\s*(f[\"']|[^)\"']*\+|.*\.format\(|request\.)"),
         C, "CWE-1336", "Template montado com entrada do usuário permite executar código no servidor (SSTI).",
         "Use render_template com arquivo fixo e passe variáveis como contexto."),
    # ---------- Desserialização ----------
    Rule("pickle-load", "Desserialização insegura (pickle/marshal)", PY,
         r(r"\b(pickle|cPickle|marshal|dill)\.loads?\("), H, "CWE-502",
         "pickle com dados externos executa código arbitrário.", "Use JSON ou assine/valide os dados."),
    Rule("yaml-load", "yaml.load sem SafeLoader", PY,
         r(r"yaml\.(load|load_all)\((?![^)]*Loader\s*=\s*(yaml\.)?(Safe|CSafe)Loader)"), H, "CWE-502",
         "yaml.load pode instanciar objetos Python arbitrários.", "Use yaml.safe_load."),
    Rule("node-serialize", "Desserialização insegura (node-serialize/unserialize)", JS + PHP,
         r(r"(unserialize\s*\(|require\(['\"]node-serialize['\"]\))"), H, "CWE-502",
         "Desserializar dados do usuário permite execução de código.", "Use JSON."),
    # ---------- XSS ----------
    Rule("xss-innerhtml", "innerHTML/outerHTML/document.write com dado dinâmico (XSS)", JS,
         r(r"\.(innerHTML|outerHTML)\s*\+?=\s*(?![\"'`][^\"'`$]*[\"'`]\s*;?\s*$)|document\.write\("),
         M, "CWE-79", "HTML montado com dados permite injetar scripts no navegador de outros usuários.",
         "Use textContent ou sanitize com DOMPurify."),
    Rule("xss-react", "dangerouslySetInnerHTML", JS, r(r"dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html\s*:\s*(?!DOMPurify)"),
         M, "CWE-79", "Renderiza HTML cru; se vier do usuário/banco é XSS.", "Sanitize com DOMPurify antes."),
    Rule("xss-vue", "v-html", (".vue", ".html"), r(r"\bv-html\s*="), M, "CWE-79",
         "v-html renderiza HTML sem escapar.", "Use interpolação {{ }} ou sanitize."),
    Rule("xss-safe-filter", "Template marcando conteúdo como seguro (|safe, mark_safe, Markup)",
         PY + (".html", ".jinja", ".j2"), r(r"(\|\s*safe\b|mark_safe\(|Markup\()"), M, "CWE-79",
         "Desliga o escape automático do template.", "Só marque como seguro conteúdo já sanitizado."),
    # ---------- Criptografia / auth ----------
    Rule("weak-hash", "Hash fraco (MD5/SHA1) para senha ou token", ANY_CODE,
         r(r"(?i)(md5|sha1)\s*\(.*(pass|senha|pwd|token|secret)|(pass|senha|pwd).*(md5|sha1)\s*\(|hashlib\.(md5|sha1)\("
           r"|createHash\(['\"](md5|sha1)['\"]\)"),
         M, "CWE-327", "MD5/SHA1 são quebrados e rápidos demais para senhas.",
         "Use bcrypt, scrypt ou argon2 para senhas; SHA-256+ para integridade."),
    Rule("insecure-random", "Math.random/random para token ou senha", ANY_CODE,
         r(r"(?i)(token|secret|senha|password|otp|code|session|nonce|salt)\w*\s*[:=].*\b(Math\.random|random\.(random|randint|choice))\("),
         M, "CWE-338", "Gerador previsível; tokens podem ser adivinhados.",
         "Use crypto.randomUUID/randomBytes ou secrets.token_urlsafe."),
    Rule("jwt-none", "JWT sem verificação de assinatura", ANY_CODE,
         r(r"(?i)(verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[\s*['\"]none['\"]|jwt\.decode\([^)]*verify\s*=\s*False"
           r"|ignoreExpiration\s*:\s*true|algorithms\s*:\s*\[\s*['\"]none['\"])"),
         H, "CWE-347", "Tokens forjados serão aceitos.", "Sempre verifique assinatura e expiração com algoritmo fixo."),
    Rule("jwt-decode-no-verify", "jwt.decode usado para autenticar (não valida assinatura)", JS,
         r(r"\bjwt\.decode\("), L, "CWE-347",
         "jwt.decode só lê o token, não verifica. Se for usado para autenticar, qualquer um forja.",
         "Use jwt.verify com o segredo/chave pública."),
    Rule("tls-verify-off", "Verificação TLS desligada", ANY_CODE,
         r(r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|InsecureSkipVerify\s*:\s*true"
           r"|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false))"),
         M, "CWE-295", "Aceita certificados falsos: abre espaço para man-in-the-middle.", "Mantenha a verificação ligada."),
    # ---------- Configuração ----------
    Rule("debug-on", "Modo debug ligado", PY + JS + PHP,
         r(r"(?i)(^\s*DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True|display_errors\s*,\s*['\"]?(1|on))"),
         M, "CWE-489", "Debug em produção expõe stack traces, variáveis e às vezes um console que executa código.",
         "Controle por variável de ambiente e desligue em produção.", Category.CONFIG),
    Rule("cors-wildcard", "CORS liberado para qualquer origem", ANY_CODE,
         r(r"(?i)(Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*|cors\(\s*\)|origin\s*:\s*(['\"]\*['\"]|true)"
           r"|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|allow_origins\s*=\s*\[\s*['\"]\*)"),
         M, "CWE-942", "Qualquer site consegue chamar sua API pelo navegador do usuário.",
         "Liste as origens permitidas explicitamente.", Category.CONFIG),
    Rule("bind-all", "Servidor ouvindo em 0.0.0.0 com debug", PY,
         r(r"app\.run\([^)]*host\s*=\s*['\"]0\.0\.0\.0['\"][^)]*debug\s*=\s*True"), H, "CWE-668",
         "Debugger do Werkzeug exposto na rede = execução remota de código.", "Nunca rode debug exposto.",
         Category.CONFIG),
    Rule("next-public-secret", "Segredo em variável pública do frontend", ANY_CODE + (".env", ".local"),
         r(r"\b(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC)_\w*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|STRIPE_SK|OPENAI|ANTHROPIC)\w*"),
         C, "CWE-200", "Variáveis com esse prefixo vão para o JavaScript do navegador: qualquer visitante lê o valor.",
         "Use o segredo só no servidor (sem prefixo público) e chame-o por uma rota de API.", Category.SECRET),
    Rule("supabase-service-client", "Cliente Supabase criado com service_role", JS,
         r(r"createClient\([^)]*(SERVICE_ROLE|service_role|serviceRole)"), H, "CWE-284",
         "Cliente com service_role ignora RLS. Se esse arquivo roda no navegador, o banco inteiro fica aberto.",
         "Garanta que esse código roda só no servidor (route handler, server action, edge function)."),
    Rule("firebase-open-rules", "Regras do Firebase abertas", (".rules", ".json"),
         r(r"(allow\s+read\s*,\s*write\s*:\s*if\s+true|['\"]\.(read|write)['\"]\s*:\s*(true|['\"]true['\"]))"),
         C, "CWE-284", "Qualquer pessoa na internet lê e escreve no banco.", "Exija request.auth != null e regras por usuário.",
         Category.CONFIG),
    Rule("rls-disabled", "RLS desligado em tabela", SQL,
         r(r"(?i)disable\s+row\s+level\s+security"), H, "CWE-284",
         "Sem RLS, a anon key (pública) consegue ler/escrever a tabela inteira pelo PostgREST.",
         "Ative RLS e crie políticas por usuário (auth.uid()).", Category.CONFIG),
    Rule("rls-permissive", "Política RLS que libera tudo (USING true)", SQL,
         r(r"(?i)create\s+policy.*(using|with\s+check)\s*\(\s*true\s*\)"), M, "CWE-284",
         "Política que aceita qualquer linha equivale a não ter RLS para aquela operação.",
         "Restrinja com auth.uid() = user_id ou papel específico.", Category.CONFIG),
    # ---------- Arquivos / redirecionamentos ----------
    Rule("path-traversal", "Caminho de arquivo vindo do usuário (path traversal)", PY + JS + PHP,
         r(r"(open|send_file|sendFile|readFile|readFileSync|createReadStream|file_get_contents|include|require)\s*\(\s*[^)]*"
           r"(request\.|req\.(query|params|body)|\$_(GET|POST|REQUEST)|params\[)"),
         H, "CWE-22", "Usuário pode pedir ../../etc/passwd ou arquivos do servidor.",
         "Normalize o caminho e confira que fica dentro da pasta permitida."),
    Rule("open-redirect", "Redirecionamento para URL do usuário (open redirect)", PY + JS + PHP,
         r(r"(redirect|res\.redirect|header\(['\"]Location:)\s*\(?\s*[^)]*(request\.(args|GET|query)|req\.query|\$_GET)"),
         M, "CWE-601", "Permite phishing usando seu domínio.", "Redirecione só para caminhos internos ou lista fixa."),
    Rule("ssrf", "Requisição HTTP para URL vinda do usuário (SSRF)", PY + JS,
         r(r"(requests\.(get|post)|fetch|axios\.(get|post)|urlopen|httpx\.(get|post))\s*\(\s*(req\.(query|body|params)|request\.(args|json|form|GET|POST))"),
         H, "CWE-918", "O servidor pode ser usado para acessar a rede interna ou metadados da nuvem.",
         "Valide o host contra uma lista permitida e bloqueie IPs internos."),
    # ---------- Docker ----------
    Rule("docker-root", "Container sem USER (roda como root)", ("Dockerfile",), r(r"^FROM\s", re.M), L, "CWE-250",
         "Se o app for invadido, o atacante já é root dentro do container.", "Adicione USER com usuário sem privilégio.",
         Category.CONFIG),
]


class BuiltinCodeScanner(Scanner):
    name = "vibesec-sast"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_files(ctx.root, max_size=500_000):
            rel = path.relative_to(ctx.root).as_posix()
            name = path.name
            ext = path.suffix.lower()
            if name.endswith((".min.js", ".bundle.js")) or "/vendor/" in rel:
                continue
            rules = [ru for ru in RULES if ext in ru.exts or name in ru.exts
                     or (name.startswith(".env") and ".env" in ru.exts)]
            if not rules:
                continue
            text = read_text(path)
            if not text:
                continue
            test_file = bool(re.search(r"(?i)(^|/)(tests?|__tests__|spec)/|\.(test|spec)\.|_test\.", rel))

            if name == "Dockerfile":
                if not re.search(r"^\s*USER\s+(?!root\b)", text, re.M):
                    ru = next(x for x in RULES if x.id == "docker-root")
                    findings.append(self._finding(ru, rel, None, None, test_file))
                continue

            lines = text.splitlines()
            for ru in rules:
                for i, line in enumerate(lines, 1):
                    if len(line) > 1500 or line.lstrip().startswith(("#", "//", "*", "--")):
                        continue
                    if ru.pattern.search(line):
                        findings.append(self._finding(ru, rel, i, line.strip()[:200], test_file))
        return findings

    def _finding(self, ru: Rule, rel: str, line: int | None, evidence: str | None, test_file: bool) -> Finding:
        sev = Severity.INFO if test_file else ru.severity
        return Finding(
            title=ru.title, severity=sev, category=ru.category, tool=self.name, file=rel, line=line,
            rule_id=ru.id, cwe=[ru.cwe], evidence=evidence, description=ru.description,
            remediation=ru.remediation,
        )

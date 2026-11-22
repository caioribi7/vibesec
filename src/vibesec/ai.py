"""Triagem com Claude: separa falso positivo, ajusta severidade, explica e sugere a correção."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from vibesec.models import ScanResult, Severity

DEFAULT_MODEL = "claude-opus-5-5"
CHUNK = 30
MAX_FINDINGS = 180

SYSTEM = """Você é um engenheiro de segurança de aplicações revisando achados de ferramentas automáticas \
(SAST, segredos, dependências e testes dinâmicos numa sandbox isolada) no repositório do próprio usuário. \
O objetivo é defensivo: ajudar o dono do código a corrigir as falhas.

Para cada achado:
- false_positive: true só quando o trecho de código mostra claramente que não é explorável \
(dado constante, código de teste, exemplo, valor já sanitizado). Na dúvida, false.
- severity: a severidade real considerando o contexto (critical, high, medium, low, info). \
Achados dinâmicos confirmados raramente são falso positivo.
- explanation: 1 a 3 frases em português do Brasil, simples, dizendo o risco concreto para esse app.
- fix: a correção concreta para esse código (pode incluir um trecho curto de código corrigido).

Responda apenas no formato pedido."""

SCHEMA = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "false_positive": {"type": "boolean"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "explanation": {"type": "string"},
                    "fix": {"type": "string"},
                },
                "required": ["id", "false_positive", "severity", "explanation", "fix"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["items"],
    "additionalProperties": False,
}


class AIUnavailable(RuntimeError):
    pass


def _client():
    try:
        import anthropic
    except ImportError as e:
        raise AIUnavailable("instale com: pip install \"vibesec[ai]\"") from e
    try:
        return anthropic, anthropic.Anthropic()
    except Exception as e:  # sem credencial configurada
        raise AIUnavailable(f"sem credencial da Anthropic ({e}). Defina ANTHROPIC_API_KEY.") from e


def _snippet(root: Path, file: str | None, line: int | None, ctx: int = 6) -> str | None:
    if not file or not line:
        return None
    p = (root / file)
    try:
        if not p.resolve().is_relative_to(root.resolve()):
            return None
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None
    a, b = max(0, line - 1 - ctx), min(len(lines), line + ctx)
    return "\n".join(f"{i + 1:>5}{'>' if i + 1 == line else ' '} {lines[i][:220]}" for i in range(a, b))


def _call(anthropic, client, model: str, effort: str, content: str, schema: dict | None, max_tokens: int):
    kwargs = dict(
        model=model,
        max_tokens=max_tokens,
        system=SYSTEM,
        messages=[{"role": "user", "content": content}],
        output_config={"effort": effort, **({"format": {"type": "json_schema", "schema": schema}} if schema else {})},
    )
    # fallbacks="default": se um classificador recusar, o servidor tenta outro modelo automaticamente
    with client.beta.messages.stream(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs) as s:
        msg = s.get_final_message()
    if msg.stop_reason == "refusal":
        return None
    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


def triage(result: ScanResult, root: Path, model: str = DEFAULT_MODEL, effort: str = "medium",
           log: Callable[[str], None] = print) -> None:
    anthropic, client = _client()
    candidates = [f for f in result.findings if f.severity != Severity.INFO][:MAX_FINDINGS]
    if not candidates:
        return
    index = {i: f for i, f in enumerate(candidates)}
    reviewed = 0
    for start in range(0, len(candidates), CHUNK):
        chunk = list(index.items())[start:start + CHUNK]
        payload = [{
            "id": i, "tool": f.tool, "category": f.category.value, "severity": f.severity.value,
            "title": f.title, "rule": f.rule_id, "location": f.location, "confirmed_in_sandbox": f.confirmed,
            "cwe": f.cwe, "cve": f.cve, "evidence": (f.evidence or "")[:300],
            "code": _snippet(root, f.file, f.line),
        } for i, f in chunk]
        content = (f"Stack do projeto: {json.dumps(result.stack, ensure_ascii=False)}\n\n"
                   f"Achados ({len(payload)}):\n{json.dumps(payload, ensure_ascii=False, indent=1)}")
        try:
            text = _call(anthropic, client, model, effort, content, SCHEMA, 16000)
        except anthropic.AuthenticationError as e:
            raise AIUnavailable("credencial da Anthropic inválida") from e
        except anthropic.RateLimitError:
            log("limite de requisições da API atingido; parando a triagem aqui")
            break
        except anthropic.APIStatusError as e:
            log(f"erro da API ({e.status_code}); pulando {len(chunk)} achados")
            continue
        except anthropic.APIConnectionError:
            log("sem conexão com a API da Anthropic; parando a triagem")
            break
        if text is None:
            log(f"o modelo recusou revisar {len(chunk)} achados; mantidos como estão")
            continue
        try:
            items = json.loads(text)["items"]
        except (json.JSONDecodeError, KeyError, TypeError):
            log("resposta da IA fora do formato; pulando bloco")
            continue
        for it in items:
            f = index.get(it.get("id"))
            if not f:
                continue
            f.false_positive = bool(it["false_positive"]) and not f.confirmed
            f.severity = Severity.parse(it["severity"], f.severity)
            f.ai_notes = it["explanation"].strip()
            if it["fix"].strip():
                f.remediation = it["fix"].strip()
            reviewed += 1
    log(f"{reviewed} achados revisados pela IA")
    result.findings.sort(key=lambda f: (-f.severity.rank, not f.confirmed, f.category.value, f.location))
    result.ai_summary = summarize(anthropic, client, result, model, effort)


def summarize(anthropic, client, result: ScanResult, model: str, effort: str) -> str | None:
    top = [{"sev": f.severity.value, "title": f.title, "where": f.location, "confirmed": f.confirmed,
            "notes": f.ai_notes} for f in result.active if f.severity.rank >= Severity.MEDIUM.rank][:60]
    content = (
        "Escreva o resumo executivo deste pentest em português do Brasil, em Markdown, com no máximo 250 "
        "palavras: (1) situação geral em 2 frases, (2) as 3 a 5 correções mais urgentes em ordem, "
        "(3) se houver, uma cadeia de ataque realista combinando achados. Sem títulos de nível 1.\n\n"
        f"Alvo: {result.target}\nStack: {json.dumps(result.stack, ensure_ascii=False)}\n"
        f"Nota: {result.score}/100 ({result.grade})\nContagem: {result.counts()}\n"
        f"Principais achados:\n{json.dumps(top, ensure_ascii=False, indent=1)}"
    )
    try:
        return _call(anthropic, client, model, effort, content, None, 8000)
    except anthropic.APIError:
        return None

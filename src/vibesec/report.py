"""Relatórios: terminal, JSON, Markdown, HTML e SARIF (GitHub Code Scanning)."""

from __future__ import annotations

import html
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vibesec import __version__
from vibesec.models import ScanResult, Severity

FORMATS = ("json", "md", "html", "sarif")
GRADE_COLOR = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}


# ------------------------------------------------------------------ terminal
def print_summary(result: ScanResult, console: Console, limit: int = 25) -> None:
    counts = result.counts()
    head = Text()
    head.append(f" {result.grade} ", style=f"bold reverse {GRADE_COLOR[result.grade]}")
    head.append(f"  nota {result.score}/100   ", style="bold")
    for s in Severity:
        if counts[s.value]:
            head.append(f" {counts[s.value]} {s.label} ", style=s.color)
            head.append(" ")
    fp = sum(1 for f in result.findings if f.false_positive)
    confirmed = sum(1 for f in result.active if f.confirmed)
    sub = f"{len(result.active)} achados · {confirmed} confirmados na sandbox"
    if fp:
        sub += f" · {fp} falsos positivos descartados pela IA"
    console.print(Panel(Text.assemble(head, "\n", Text(sub, style="dim")), title=f"VibeSec · {result.target}",
                        border_style=GRADE_COLOR[result.grade]))

    tools = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    tools.add_column("Ferramenta")
    tools.add_column("Status")
    tools.add_column("Achados", justify="right")
    tools.add_column("Tempo", justify="right")
    for t in result.tools:
        st = {"ok": "[green]ok[/]", "skipped": "[dim]pulado[/]", "error": "[red]erro[/]"}[t.status]
        tools.add_row(t.name, f"{st} [dim]{t.detail[:60]}[/]" if t.detail else st, str(t.findings), f"{t.seconds:.0f}s")
    console.print(tools)

    active = [f for f in result.active if f.severity != Severity.INFO]
    if not active:
        console.print("\n[bold green]Nenhuma vulnerabilidade relevante encontrada.[/]")
        return
    t = Table(show_header=True, header_style="bold", expand=True, show_lines=False)
    t.add_column("Sev.", width=8)
    t.add_column("Achado", ratio=3)
    t.add_column("Onde", ratio=2, overflow="fold")
    t.add_column("Fonte", ratio=1)
    for f in active[:limit]:
        title = f.title + (" [bold green]✔ explorado[/]" if f.confirmed and f.category.value in ("web", "network") else "")
        t.add_row(Text(f.severity.label, style=f.severity.color), title, f.location, f.tool)
    console.print(t)
    if len(active) > limit:
        console.print(f"[dim]… e mais {len(active) - limit}. Veja o relatório completo.[/]")
    if result.summary:
        from rich.markdown import Markdown

        console.print(Panel(Markdown(result.summary), title="Resumo do VibeSec", border_style="magenta"))


# ---------------------------------------------------------------- arquivos
def write_all(result: ScanResult, out_dir: Path, formats: tuple[str, ...] = FORMATS) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    writers = {"json": to_json, "md": to_markdown, "html": to_html, "sarif": to_sarif}
    paths = {}
    for fmt in formats:
        p = out_dir / ("report." + fmt if fmt != "sarif" else "report.sarif")
        p.write_text(writers[fmt](result), encoding="utf-8")
        paths[fmt] = p
    return paths


def to_json(r: ScanResult) -> str:
    return json.dumps(r.to_dict(), ensure_ascii=False, indent=2)


def to_markdown(r: ScanResult) -> str:
    c = r.counts()
    lines = [
        f"# Relatório VibeSec: {r.target}", "",
        f"**Nota:** {r.score}/100 ({r.grade}) · **Commit:** `{(r.commit or '-')[:12]}` · **Data:** {r.started_at[:19]}Z", "",
        "| Crítica | Alta | Média | Baixa | Info |", "|---|---|---|---|---|",
        f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} |", "",
    ]
    if r.summary:
        lines += ["## Resumo", "", r.summary.strip(), ""]
    lines += ["## Stack", "", f"- Linguagens: {', '.join(r.stack.get('languages', {})) or '-'}",
              f"- Frameworks: {', '.join(r.stack.get('frameworks', [])) or '-'}", ""]
    lines += ["## Ferramentas", "", "| Ferramenta | Status | Achados |", "|---|---|---|"]
    lines += [f"| {t.name} | {t.status} {t.detail} | {t.findings} |" for t in r.tools]
    lines += ["", "## Achados", ""]
    for i, f in enumerate(r.active, 1):
        lines.append(f"### {i}. [{f.severity.label}] {f.title}")
        meta = [f"`{f.location}`", f"fonte: {f.tool}"]
        if f.confirmed:
            meta.append("**confirmado na sandbox**")
        if f.cwe:
            meta.append(", ".join(f.cwe))
        if f.cve:
            meta.append(", ".join(f.cve))
        lines += [" · ".join(meta), ""]
        for label, val in (("Descrição", f.description), ("Análise do VibeSec", f.notes),
                           ("Evidência", f.evidence and f"`{f.evidence}`"), ("Como corrigir", f.remediation)):
            if val:
                lines += [f"**{label}:** {val}", ""]
    fps = [f for f in r.findings if f.false_positive]
    if fps:
        lines += ["## Descartados como falso positivo", ""]
        lines += [f"- {f.title} (`{f.location}`): {f.notes or ''}" for f in fps]
    lines += ["", f"_Gerado por VibeSec {__version__}_"]
    return "\n".join(lines)


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(r: ScanResult) -> str:
    rules, results = {}, []
    for f in r.active:
        rid = f.rule_id or f.title
        rules.setdefault(rid, {
            "id": rid, "name": f.title[:100], "shortDescription": {"text": f.title[:200]},
            "fullDescription": {"text": (f.description or f.title)[:1000]},
            "help": {"text": f.remediation or ""},
            "properties": {"tags": ["security", f.category.value, *f.cwe],
                           "security-severity": {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0",
                                                 "info": "0.0"}[f.severity.value]},
        })
        res = {"ruleId": rid, "level": SARIF_LEVEL[f.severity.value],
               "message": {"text": (f.notes or f.description or f.title)[:1000]},
               "partialFingerprints": {"vibesec/v1": f.fingerprint}}
        if f.file:
            loc = {"physicalLocation": {"artifactLocation": {"uri": f.file}}}
            if f.line:
                loc["physicalLocation"]["region"] = {"startLine": int(f.line)}
            res["locations"] = [loc]
        results.append(res)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "VibeSec", "version": __version__,
                                      "informationUri": "https://github.com/caioribi7/vibesec",
                                      "rules": list(rules.values())}},
                  "results": results}],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


def to_html(r: ScanResult) -> str:
    e = html.escape
    c = r.counts()
    cards = "".join(
        f'<div class="stat s-{s.value}"><b>{c[s.value]}</b><span>{s.label}</span></div>' for s in Severity)
    rows = []
    for f in r.active:
        badges = f'<span class="sev s-{f.severity.value}">{f.severity.label}</span>'
        if f.confirmed:
            badges += '<span class="tag ok">confirmado</span>'
        details = "".join(
            f"<dt>{label}</dt><dd>{e(str(val))}</dd>" for label, val in (
                ("Descrição", f.description), ("Análise do VibeSec", f.notes), ("Evidência", f.evidence),
                ("Como corrigir", f.remediation), ("CWE/CVE", ", ".join(f.cwe + f.cve)),
                ("Referências", " ".join(f.references))) if val)
        rows.append(
            f'<details class="f" data-sev="{f.severity.value}" data-cat="{f.category.value}">'
            f'<summary>{badges}<span class="t">{e(f.title)}</span>'
            f'<code>{e(f.location)}</code><span class="tool">{e(f.tool)}</span></summary>'
            f"<dl>{details}</dl></details>")
    tools = "".join(
        f"<tr><td>{e(t.name)}</td><td class='st-{t.status}'>{e(t.status)}</td><td>{e(t.detail)}</td>"
        f"<td>{t.findings}</td><td>{t.seconds:.0f}s</td></tr>" for t in r.tools)
    summary = ""
    if r.summary:
        summary = f'<section class="ai"><h2>Resumo</h2><pre>{e(r.summary)}</pre></section>'
    cats = sorted({f.category.value for f in r.active})
    filters = "".join(f'<button data-cat="{c_}">{c_}</button>' for c_ in cats)
    return HTML_TEMPLATE.format(
        title=e(r.target), grade=r.grade, score=r.score, cards=cards, rows="".join(rows) or "<p>Nada encontrado.</p>",
        tools=tools, summary=summary, filters=filters, commit=e((r.commit or "-")[:12]),
        date=e(r.started_at[:19].replace("T", " ")), version=__version__,
        stack=e(", ".join(list(r.stack.get("languages", {}))[:6] + r.stack.get("frameworks", []))),
    )


HTML_TEMPLATE = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VibeSec · {title}</title>
<style>
:root{{--bg:#0b0d12;--panel:#12151d;--line:#232836;--fg:#e6e8ee;--dim:#8b93a7;--acc:#7c5cff;
--critical:#ff3b5c;--high:#ff7a45;--medium:#ffc53d;--low:#36cfc9;--info:#6b7280}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:32px 16px}}
header{{display:flex;gap:24px;align-items:center;flex-wrap:wrap}}
.grade{{width:96px;height:96px;border-radius:20px;display:grid;place-items:center;font-size:48px;font-weight:800;
background:linear-gradient(135deg,var(--acc),#2dd4bf)}}
.g-A,.g-B{{background:linear-gradient(135deg,#22c55e,#2dd4bf)}}.g-C{{background:linear-gradient(135deg,#eab308,#f97316)}}
.g-D,.g-F{{background:linear-gradient(135deg,#ef4444,#be123c)}}
h1{{margin:0;font-size:24px}}h2{{font-size:18px;margin:32px 0 12px}}.dim{{color:var(--dim)}}
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:24px}}
.stat{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px;border-top:3px solid}}
.stat b{{font-size:26px;display:block}}.stat span{{color:var(--dim);font-size:12px;letter-spacing:.06em}}
.s-critical{{border-color:var(--critical)}}.s-high{{border-color:var(--high)}}.s-medium{{border-color:var(--medium)}}
.s-low{{border-color:var(--low)}}.s-info{{border-color:var(--info)}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}}
.filters button{{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:999px;padding:4px 12px;cursor:pointer}}
.filters button.on{{background:var(--acc);border-color:var(--acc)}}
.f{{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:8px}}
.f summary{{display:flex;gap:10px;align-items:center;padding:12px 14px;cursor:pointer;flex-wrap:wrap}}
.f summary .t{{flex:1;min-width:200px;font-weight:600}}.f code{{color:var(--dim);font-size:12px;word-break:break-all}}
.tool{{color:var(--dim);font-size:12px}}
.sev{{font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;color:#000;background:var(--info)}}
.sev.s-critical{{background:var(--critical);color:#fff}}.sev.s-high{{background:var(--high)}}
.sev.s-medium{{background:var(--medium)}}.sev.s-low{{background:var(--low)}}
.tag{{font-size:11px;padding:2px 8px;border-radius:6px;border:1px solid #3ddc97;color:#3ddc97}}
dl{{margin:0;padding:0 14px 14px;display:grid;grid-template-columns:140px 1fr;gap:6px 14px}}
dt{{color:var(--dim)}}dd{{margin:0;white-space:pre-wrap;word-break:break-word}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border-radius:10px;overflow:hidden}}
td{{padding:8px 12px;border-bottom:1px solid var(--line);font-size:13px}}
.st-ok{{color:#3ddc97}}.st-error{{color:var(--critical)}}.st-skipped{{color:var(--dim)}}
.ai pre{{white-space:pre-wrap;background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--acc);
border-radius:10px;padding:16px;font:inherit}}
footer{{margin-top:40px;color:var(--dim);font-size:12px}}
@media (max-width:640px){{.stats{{grid-template-columns:repeat(3,1fr)}}dl{{grid-template-columns:1fr}}}}
</style></head><body><main>
<header><div class="grade g-{grade}">{grade}</div><div><h1>{title}</h1>
<div class="dim">Nota {score}/100 · commit {commit} · {date} UTC</div><div class="dim">{stack}</div></div></header>
<div class="stats">{cards}</div>
{summary}
<h2>Achados</h2>
<div class="filters"><button class="on" data-cat="">todos</button>{filters}</div>
<div id="list">{rows}</div>
<h2>Ferramentas</h2><table>{tools}</table>
<footer>Gerado por VibeSec {version}. Testes dinâmicos executados apenas contra a sandbox isolada.</footer>
</main>
<script>
document.querySelectorAll('.filters button').forEach(b=>b.onclick=()=>{{
document.querySelectorAll('.filters button').forEach(x=>x.classList.remove('on'));b.classList.add('on');
document.querySelectorAll('.f').forEach(f=>f.style.display=!b.dataset.cat||f.dataset.cat===b.dataset.cat?'':'none');}});
</script></body></html>"""

"""Interface de linha de comando do VibeSec."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from vibesec import __version__, config
from vibesec.models import ScanResult, Severity

if sys.platform == "win32":  # acentos e símbolos no console do Windows
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

console = Console(highlight=False)
app = typer.Typer(
    name="vibesec",
    help="VibeSec: pentest de ponta a ponta para repositórios do GitHub.",
    no_args_is_help=False,
    rich_markup_mode="rich",
    add_completion=False,
)

BANNER = r"""[bold magenta]
 __   __ _  _                ___
 \ \ / /(_)| |__  ___  ___  / __| ___  __
  \ V / | || '_ \/ -_)|___| \__ \/ -_)/ _|
   \_/  |_||_.__/\___|      |___/\___|\__|[/][dim]  v{v}[/]
[dim]  pentest de ponta a ponta para repositórios[/]
"""


class Mode(str, Enum):
    auto = "auto"
    static = "static"
    full = "full"


class Depth(str, Enum):
    quick = "quick"
    standard = "standard"
    deep = "deep"


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", s).strip("-")[:60]


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Mostra a versão."),
):
    if version:
        console.print(f"vibesec {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        menu()


@app.command()
def scan(
    target: str = typer.Argument(..., help="URL do GitHub, dono/repo ou pasta local."),
    mode: Mode = typer.Option(Mode.auto, "--mode", "-m",
                              help="static: só código. full: código + ataques na sandbox. auto: full se tiver Docker."),
    depth: Depth = typer.Option(Depth.standard, "--depth", "-d", help="quick, standard ou deep (mais lento e completo)."),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="Branch a analisar."),
    offline: bool = typer.Option(False, "--offline",
                                 help="Máquina sem internet: nenhuma ferramenta acessa a rede (bases de `vibesec update`)."),
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Porta em que a aplicação escuta."),
    run_cmd: Optional[str] = typer.Option(None, "--run-cmd", help="Comando para iniciar a aplicação na sandbox."),
    out: Path = typer.Option(Path("vibesec-reports"), "--out", "-o", help="Pasta dos relatórios."),
    formats: str = typer.Option("html,md,json,sarif", "--format", "-f", help="Formatos separados por vírgula."),
    skip: str = typer.Option("", "--skip", help="Ferramentas a pular, ex: zap,nuclei"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on",
                                          help="Sai com código 1 se houver achado com essa severidade ou maior (CI)."),
    keep_sandbox: bool = typer.Option(False, "--keep-sandbox", help="Não destrói a sandbox no fim."),
    no_docker: bool = typer.Option(False, "--no-docker", help="Nunca usa Docker (só binários locais)."),
    save_db: Optional[bool] = typer.Option(None, "--save-db/--no-save-db",
                                           help="Grava no Postgres configurado (integração Masterbase)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Não pede confirmação."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Sem banner."),
):
    """Analisa um repositório de ponta a ponta."""
    from vibesec.engine import Engine, ScanOptions
    from vibesec.report import FORMATS, print_summary, write_all

    fmts = tuple(f.strip() for f in formats.split(",") if f.strip())
    bad = [f for f in fmts if f not in FORMATS]
    if bad:
        console.print(f"[red]Formato inválido:[/] {', '.join(bad)}. Use: {', '.join(FORMATS)}")
        raise typer.Exit(2)
    if fail_on and fail_on.lower() not in {s.value for s in Severity}:
        raise typer.BadParameter("use critical, high, medium, low ou info", param_hint="--fail-on")

    if offline and not Path(target).exists():
        console.print("[red]No modo offline o alvo precisa ser uma pasta local[/] (clone o repositório antes).")
        raise typer.Exit(2)

    if not quiet:
        console.print(BANNER.format(v=__version__))

    if mode != Mode.static and not no_docker and not yes and sys.stdin.isatty():
        console.print(
            "[yellow]![/] No modo completo o código do repositório é [bold]construído e executado[/] num container "
            "Docker isolado (sem internet) e atacado com nmap, nuclei e ZAP. Os ataques só miram essa cópia local.")
        if not Confirm.ask("Continuar?", default=True):
            raise typer.Exit()

    opts = ScanOptions(
        target=target, mode=mode.value, depth=depth.value, branch=branch, offline=offline,
        port=port, run_cmd=run_cmd, keep_sandbox=keep_sandbox,
        skip=tuple(s.strip() for s in skip.split(",") if s.strip()), allow_docker=not no_docker,
    )
    try:
        result = Engine(opts, console).run()
    except (ValueError, RuntimeError) as e:
        console.print(f"[red]Erro:[/] {e}")
        raise typer.Exit(2)
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelado.[/]")
        raise typer.Exit(130)

    console.print()
    print_summary(result, console)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = out / f"{_slug(result.target)}-{stamp}"
    paths = write_all(result, dest, fmts)
    console.print("\n[bold]Relatórios:[/]")
    for fmt, p in paths.items():
        console.print(f"  {fmt:<6} {p}")

    config.add_history({"target": result.target, "commit": result.commit, "score": result.score,
                        "grade": result.grade, "counts": result.counts(), "date": result.started_at,
                        "report": str((dest / "report.json").resolve()) if "json" in paths else None})

    dsn = config.database_url()
    if save_db or (save_db is None and dsn):
        _save_db(result, dsn)

    if fail_on:
        limit = Severity.parse(fail_on)
        if any(f.severity.rank >= limit.rank for f in result.active):
            raise typer.Exit(1)


def _save_db(result: ScanResult, dsn: str | None) -> None:
    from vibesec.integrations.masterbase import IntegrationError, save_scan

    if not dsn:
        console.print("[yellow]Nenhum banco configurado.[/] Rode: vibesec masterbase setup")
        return
    try:
        sid = save_scan(result, dsn)
        console.print(f"[green]✔[/] Scan #{sid} salvo no Postgres (tabelas vibesec_*). "
                      "Abra no painel: [bold]vibesec masterbase open[/]")
    except IntegrationError as e:
        console.print(f"[yellow]Não salvei no banco:[/] {e}")
    except Exception as e:  # erro do driver/conexão
        console.print(f"[yellow]Não salvei no banco:[/] {' '.join(str(e).split())[:200]}")


@app.command()
def doctor(no_docker: bool = typer.Option(False, "--no-docker")):
    """Mostra quais ferramentas estão disponíveis."""
    from vibesec.engine import tool_matrix
    from vibesec.runner import docker_available

    console.print(BANNER.format(v=__version__))
    t = Table(header_style="bold", box=None, padding=(0, 2))
    for col in ("Ferramenta", "Fase", "Via", "Para que serve / como instalar"):
        t.add_column(col)
    for name, phase, mode, info in tool_matrix(not no_docker):
        via = {"local": "[green]local[/]", "docker": "[cyan]docker[/]"}.get(mode, "[red]ausente[/]")
        t.add_row(name, phase, via, info)
    t.add_row("vibesec-secrets", "static", "[green]embutido[/]", "Detector de segredos próprio")
    t.add_row("vibesec-sast", "static", "[green]embutido[/]", "Regras SAST próprias (Supabase, Firebase, Next…)")
    t.add_row("vibesec-probe", "dynamic", "[green]embutido[/]", "XSS, SQLi, CORS, arquivos expostos, cabeçalhos")
    console.print(t)

    dock = docker_available()
    console.print(f"\nDocker: {'[green]rodando[/]' if dock else '[red]indisponível[/] (testes dinâmicos desligados)'}")
    from vibesec import offline

    age = offline.last_update_age_days()
    console.print("Bases offline: " + (f"[green]atualizadas há {age} dia(s)[/]" if age is not None and age < 8 else
                                       f"[yellow]atualizadas há {age} dias (rode vibesec update)[/]" if age is not None
                                       else "[dim]nunca baixadas (rode vibesec update para usar --offline)[/]"))
    from vibesec.integrations.masterbase import masterbase_binary

    dsn = config.database_url()
    console.print(f"Masterbase: {'[green]instalado[/]' if masterbase_binary() else '[dim]não instalado (opcional)[/]'}"
                  f" · banco: {'[green]configurado[/]' if dsn else '[dim]não configurado[/]'}")
    if not dock:
        console.print("\n[dim]Para os ataques reais (nmap, nuclei, ZAP, tráfego) instale o Docker Desktop: "
                      "https://docs.docker.com/desktop/[/]")


def _step_log(step: str, ok: bool, detail: str) -> None:
    mark = "[green]✔[/]" if ok else "[red]✘[/]"
    console.print(f"  {mark} {step:<34} [dim]{detail}[/]")


@app.command()
def update():
    """[com internet] Baixa imagens, base de CVEs, templates e regras para usar depois com --offline."""
    from vibesec import offline

    console.print("[bold]Atualizando bases do VibeSec…[/]")
    ok = offline.update(_step_log)
    console.print("[green]Pronto.[/] Agora dá para rodar com --offline." if ok else
                  "[yellow]Terminou com falhas[/] (veja acima). O que baixou continua valendo.")


bundle = typer.Typer(help="Pacote para levar o VibeSec a uma máquina sem internet.")
app.add_typer(bundle, name="bundle")


@bundle.command("export")
def bundle_export(dest: Path = typer.Argument(Path("vibesec-bundle"), help="Pasta de destino.")):
    """[com internet] Exporta imagens, bases e regras para uma pasta (pendrive, rede interna)."""
    from vibesec import offline

    try:
        offline.export_bundle(dest, _step_log)
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    console.print(f"[green]Pacote em {dest.resolve()}[/]. Na máquina offline: vibesec bundle import {dest.name}")


@bundle.command("import")
def bundle_import(src: Path = typer.Argument(..., exists=True, file_okay=False, help="Pasta do pacote.")):
    """[sem internet] Carrega um pacote exportado por `vibesec bundle export`."""
    from vibesec import offline

    try:
        offline.import_bundle(src, _step_log)
    except (RuntimeError, OSError, ValueError) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    console.print("[green]Pacote importado.[/] Rode: vibesec scan ./pasta-do-repo --offline")


@app.command()
def history(limit: int = typer.Option(20, "--limit", "-n")):
    """Lista os últimos scans."""
    items = config.history(limit)
    if not items:
        console.print("[dim]Nenhum scan ainda. Rode: vibesec scan dono/repo[/]")
        return
    t = Table(header_style="bold", box=None, padding=(0, 2))
    for col in ("Data", "Alvo", "Nota", "Crít.", "Alta", "Média", "Relatório"):
        t.add_column(col)
    for h in items:
        c = h.get("counts", {})
        t.add_row(h.get("date", "")[:16].replace("T", " "), h.get("target", ""),
                  f"{h.get('grade')} {h.get('score')}", str(c.get("critical", 0)), str(c.get("high", 0)),
                  str(c.get("medium", 0)), h.get("report") or "-")
    console.print(t)


@app.command()
def report(
    file: Path = typer.Argument(..., exists=True, help="report.json de um scan anterior."),
    formats: str = typer.Option("html,md,sarif", "--format", "-f"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
):
    """Gera de novo os relatórios a partir de um report.json."""
    from vibesec.report import print_summary, write_all

    result = ScanResult.from_dict(json.loads(file.read_text(encoding="utf-8")))
    print_summary(result, console)
    paths = write_all(result, out or file.parent, tuple(f.strip() for f in formats.split(",") if f.strip()))
    for fmt, p in paths.items():
        console.print(f"  {fmt:<6} {p}")


mb = typer.Typer(help="Integração opcional com o Masterbase (Postgres com painel visual).")
app.add_typer(mb, name="masterbase")


@mb.command("setup")
def mb_setup(database_url: Optional[str] = typer.Option(None, "--database-url", help="postgresql://…")):
    """Define o Postgres onde os scans serão gravados."""
    from vibesec.integrations.masterbase import SCHEMA_SQL, IntegrationError, _psycopg

    dsn = database_url or Prompt.ask("DATABASE_URL do Postgres",
                                     default="postgresql://postgres:postgres@127.0.0.1:5432/postgres")
    try:
        psycopg = _psycopg()
        with psycopg.connect(dsn, connect_timeout=10) as conn:
            conn.execute(SCHEMA_SQL)
    except IntegrationError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Não conectei:[/] {' '.join(str(e).split())[:200]}")
        raise typer.Exit(1)
    config.set_value("database_url", dsn)
    console.print("[green]✔[/] Banco configurado e tabelas vibesec_scans / vibesec_findings criadas.\n"
                  "  Todo scan novo será salvo lá (desligue com --no-save-db). Abra o painel: vibesec masterbase open")


@mb.command("open")
def mb_open(addr: str = typer.Option("127.0.0.1:8090", "--addr", help="Endereço do painel.")):
    """Abre o painel do Masterbase com os resultados dos scans."""
    from vibesec.integrations.masterbase import IntegrationError, open_panel

    dsn = config.database_url()
    if not dsn:
        console.print("[yellow]Configure o banco antes:[/] vibesec masterbase setup")
        raise typer.Exit(1)
    try:
        proc = open_panel(dsn, addr)
    except IntegrationError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    console.print(f"[green]Masterbase em http://{addr}[/]  (Ctrl+C para fechar)\n"
                  "[dim]A primeira conta criada vira administradora. Com o usuário postgres o painel ignora RLS "
                  "(visão de administrador); em produção use um papel com menos poder.[/]")
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()


@mb.command("off")
def mb_off():
    """Desliga a integração (não apaga nada do banco)."""
    config.set_value("database_url", None)
    console.print("Integração com o Masterbase desligada.")


def menu() -> None:
    console.print(BANNER.format(v=__version__))
    options = [
        ("Escanear um repositório", "scan"),
        ("Verificar ferramentas instaladas", "doctor"),
        ("Histórico de scans", "history"),
        ("Atualizar bases (CVEs, templates, regras) para uso offline", "update"),
        ("Integrações: Masterbase (painel visual dos resultados)", "masterbase"),
        ("Sair", "exit"),
    ]
    for i, (label, _) in enumerate(options, 1):
        console.print(f"  [bold magenta]{i}[/]  {label}")
    try:
        choice = IntPrompt.ask("\nEscolha", choices=[str(i) for i in range(1, len(options) + 1)], default=1)
    except (KeyboardInterrupt, EOFError):
        return
    action = options[choice - 1][1]
    if action == "scan":
        target = Prompt.ask("Repositório (URL do GitHub, dono/repo ou pasta)")
        depth = Prompt.ask("Profundidade", choices=["quick", "standard", "deep"], default="standard")
        scan(target=target, mode=Mode.auto, depth=Depth(depth), branch=None, offline=False,
             port=None, run_cmd=None, out=Path("vibesec-reports"), formats="html,md,json,sarif", skip="",
             fail_on=None, keep_sandbox=False, no_docker=False, save_db=None, yes=False, quiet=True)
    elif action == "doctor":
        doctor(no_docker=False)
    elif action == "history":
        history(limit=20)
    elif action == "update":
        update()
    elif action == "masterbase":
        dsn = config.database_url()
        console.print("\nO Masterbase abre os scans num painel web: filtrar achados, marcar como corrigido, "
                      "ver a evolução da nota. [dim]Opcional. github.com/caioribi7/masterbase[/]")
        console.print(f"Estado: {'[green]ligado[/]' if dsn else '[dim]desligado[/]'}")
        sub = Prompt.ask("Ação", choices=["setup", "open", "off", "voltar"], default="open" if dsn else "setup")
        if sub == "setup":
            mb_setup(database_url=None)
        elif sub == "open":
            mb_open(addr="127.0.0.1:8090")
        elif sub == "off":
            mb_off()


if __name__ == "__main__":
    app()

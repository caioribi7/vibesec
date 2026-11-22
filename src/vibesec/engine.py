"""Orquestra o scan: clona, analisa o código, sobe a sandbox, ataca, triagem com IA."""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from rich.console import Console

from vibesec import repo, stack
from vibesec.models import ScanResult, ToolRun
from vibesec.runner import TOOLS, ToolUnavailable, docker_available, resolve
from vibesec.scanners import STATIC_SCANNERS, ScanContext


@dataclass
class ScanOptions:
    target: str
    mode: str = "auto"          # auto | static | full
    depth: str = "standard"     # quick | standard | deep
    branch: str | None = None
    offline: bool = False       # nenhuma ferramenta acessa a rede; usa bases baixadas por `vibesec update`
    port: int | None = None
    run_cmd: str | None = None
    image: str | None = None    # imagem Docker pronta do app (pula o build)
    keep_sandbox: bool = False
    skip: tuple[str, ...] = ()
    allow_docker: bool = True


class Engine:
    def __init__(self, opts: ScanOptions, console: Console):
        self.o = opts
        self.c = console

    def _step(self, result: ScanResult, name: str, fn: Callable[[], list], status) -> None:
        if name in self.o.skip:
            result.tools.append(ToolRun(name, "skipped", "--skip"))
            return
        status.update(f"[bold cyan]{name}[/] rodando…")
        t0 = time.time()
        try:
            found = fn()
            result.add(found)
            result.tools.append(ToolRun(name, "ok", "", time.time() - t0, len(found)))
            self.c.print(f"  [green]✔[/] {name:<16} [dim]{len(found)} achados em {time.time() - t0:.0f}s[/]")
        except ToolUnavailable as e:
            result.tools.append(ToolRun(name, "skipped", str(e), time.time() - t0))
            self.c.print(f"  [dim]–[/] {name:<16} [dim]{e}[/]")
        except Exception as e:  # uma ferramenta quebrada não derruba o scan inteiro
            msg = " ".join(str(e).split())
            msg = msg if len(msg) <= 220 else "…" + msg[-220:]  # o motivo real fica no fim
            result.tools.append(ToolRun(name, "error", msg, time.time() - t0))
            self.c.print(f"  [red]✘[/] {name:<16} [red]{msg}[/]")

    def run(self) -> ScanResult:
        o, c = self.o, self.c
        with c.status("Baixando o repositório…") as status:
            target = repo.fetch(o.target, o.branch, full_history=o.depth == "deep")
        result = ScanResult(target=target.label, commit=target.commit)
        work = Path(tempfile.mkdtemp(prefix="vibesec-work-"))
        try:
            result.stack = stack.detect(target.path)
            st = result.stack
            c.print(f"[bold]Alvo:[/] {target.label} [dim]{(target.commit or '')[:10]}[/]  ·  "
                    f"{st['files']} arquivos  ·  {', '.join(list(st['languages'])[:5]) or 'linguagem ?'}"
                    + (f"  ·  {', '.join(st['frameworks'])}" if st["frameworks"] else ""))

            ctx = ScanContext(root=target.path, work=work, stack=st, depth=o.depth, allow_docker=o.allow_docker,
                              offline=o.offline)
            if o.offline:
                from vibesec import offline

                age = offline.last_update_age_days()
                c.print("[cyan]Modo offline:[/] nenhuma ferramenta acessa a rede. "
                        + (f"[dim]Bases atualizadas há {age} dia(s).[/]" if age is not None
                           else "[yellow]Bases nunca baixadas: rode `vibesec update` com internet "
                                "(ou `vibesec bundle import`).[/]"))

            c.print("\n[bold magenta]1. Análise estática[/] [dim](código, segredos, dependências)[/]")
            with c.status("") as status:
                for cls in STATIC_SCANNERS:
                    sc = cls()
                    if not sc.applicable(ctx):
                        continue
                    self._step(result, sc.name, lambda sc=sc: sc.run(ctx), status)

            mode = o.mode
            if mode == "auto":
                mode = "full" if docker_available() and o.allow_docker else "static"
            if mode == "full":
                self._dynamic(result, target.path, work)
            else:
                c.print("\n[yellow]Testes dinâmicos pulados[/] [dim](precisa do Docker rodando; "
                        "use --mode full depois de instalar)[/]")

            result.dedupe()
            self._triage(result, target.path)
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result
        finally:
            target.cleanup()
            import shutil

            shutil.rmtree(work, ignore_errors=True)

    # ---------------------------------------------------------------- dinâmico
    def _dynamic(self, result: ScanResult, root: Path, work: Path) -> None:
        from vibesec.dynamic.probes import Prober
        from vibesec.dynamic.sandbox import Sandbox, SandboxError
        from vibesec.dynamic.tools import Capture, nmap, nuclei, zap

        c, o = self.c, self.o
        c.print("\n[bold magenta]2. Pentest dinâmico[/] [dim](app rodando numa sandbox Docker sem internet)[/]")
        if not docker_available():
            c.print("  [red]✘ Docker não está rodando.[/] Instale o Docker Desktop e tente de novo.")
            result.tools.append(ToolRun("sandbox", "error", "Docker indisponível"))
            return
        sb = Sandbox(root, result.stack, port=o.port, run_cmd=o.run_cmd, keep=o.keep_sandbox, offline=o.offline,
                     prebuilt_image=o.image)
        try:
            with c.status("Construindo e subindo a aplicação na sandbox…"):
                t0 = time.time()
                sb.start()
            for line in sb.log:
                c.print(f"  [dim]{line}[/]")
            result.tools.append(ToolRun("sandbox", "ok", sb.internal_url, time.time() - t0))
            result.sandbox = {"url": sb.internal_url, "port": sb.port, "generated_dockerfile": bool(sb.generated)}
        except (SandboxError, RuntimeError) as e:
            c.print(f"  [red]✘ Não consegui subir a aplicação:[/] {str(e)[:900]}")
            msg = " ".join(str(e).split())
            result.tools.append(ToolRun("sandbox", "error", msg if len(msg) <= 400 else msg[:120] + " … " + msg[-280:]))
            sb.stop()
            return

        cap = Capture(sb, work)
        capturing = False
        try:
            if "tshark" not in o.skip:
                try:
                    cap.start()
                    capturing = True
                except RuntimeError as e:
                    c.print(f"  [dim]captura de tráfego indisponível: {e}[/]")
            with c.status("") as status:
                pages = {"quick": 20, "standard": 40, "deep": 150}[o.depth]
                self._step(result, "vibesec-probe", lambda: Prober(sb.host_url, max_pages=pages).run(), status)
                self._step(result, "nmap", lambda: nmap(sb, work, o.depth), status)
                self._step(result, "nuclei", lambda: nuclei(sb, work, o.depth), status)
                self._step(result, "zap", lambda: zap(sb, work, o.depth), status)
                if capturing:
                    self._step(result, "tshark", cap.stop_and_analyze, status)
                    capturing = False
        finally:
            if capturing:
                try:
                    cap.stop_and_analyze()
                except RuntimeError:
                    pass
            with c.status("Desmontando a sandbox…"):
                sb.stop()

    # ----------------------------------------------------------------- triagem
    def _triage(self, result: ScanResult, root: Path) -> None:
        from vibesec.triage import triage

        c = self.c
        c.print("\n[bold magenta]3. Triagem[/] [dim](fluxo de dados, contexto, correlação código × sandbox)[/]")
        t0 = time.time()
        s = triage(result, root)
        result.tools.append(ToolRun("triage", "ok", "", time.time() - t0, len(result.active)))
        c.print(f"  [green]✔[/] {s['fp']} falsos positivos descartados · {s['up']} severidades elevadas · "
                f"{s['down']} rebaixadas · {s['linked']} achados do código confirmados pela sandbox")


def tool_matrix(allow_docker: bool = True) -> list[tuple[str, str, str, str]]:
    rows = []
    for t in TOOLS.values():
        mode = resolve(t, allow_docker)
        rows.append((t.name, t.phase, mode or "-", t.purpose if mode else t.install))
    return rows

"""Executa ferramentas externas: binário local quando existe, senão a imagem Docker oficial."""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Tool:
    name: str
    binary: str | None
    image: str | None
    purpose: str
    install: str
    phase: str  # static | dynamic
    docker_cmd: tuple[str, ...] = ()  # para imagens sem ENTRYPOINT (ex.: semgrep)


TOOLS: dict[str, Tool] = {
    t.name: t
    for t in [
        Tool("semgrep", "semgrep", "semgrep/semgrep:latest", "SAST multi-linguagem (OWASP Top 10)",
             "pip install semgrep", "static", docker_cmd=("semgrep",)),
        Tool("bandit", "bandit", None, "SAST para Python", "pip install bandit", "static"),
        Tool("gitleaks", "gitleaks", "zricethezav/gitleaks:latest", "Segredos no código e no histórico git",
             "https://github.com/gitleaks/gitleaks#installing", "static"),
        Tool("trivy", "trivy", "aquasec/trivy:latest", "CVEs em dependências + IaC/Dockerfile",
             "https://trivy.dev/latest/getting-started/installation/", "static"),
        Tool("osv-scanner", "osv-scanner", "ghcr.io/google/osv-scanner:latest",
             "CVEs em dependências (base OSV.dev)", "https://google.github.io/osv-scanner/installation/",
             "static"),
        Tool("nmap", None, "instrumentisto/nmap:latest", "Portas, serviços e versões da sandbox",
             "via Docker", "dynamic"),
        Tool("nuclei", None, "projectdiscovery/nuclei:latest", "Milhares de templates de exploração web",
             "via Docker", "dynamic"),
        Tool("zap", None, "ghcr.io/zaproxy/zaproxy:stable", "OWASP ZAP: spider + scan passivo/ativo",
             "via Docker", "dynamic"),
        Tool("tshark", None, "nicolaka/netshoot:latest", "Captura e análise do tráfego (tcpdump/tshark)",
             "via Docker", "dynamic"),
    ]
}


class ToolUnavailable(RuntimeError):
    pass


@lru_cache(maxsize=1)
def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                           capture_output=True, text=True, timeout=20)
        return r.returncode == 0 and bool(r.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


def resolve(tool: Tool, allow_docker: bool = True) -> str | None:
    """Devolve 'local', 'docker' ou None."""
    if tool.binary and shutil.which(tool.binary):
        return "local"
    if allow_docker and tool.image and docker_available():
        return "docker"
    return None


def _docker_path(p: Path) -> str:
    return str(p.resolve())


def run_tool(
    tool_name: str,
    args: list[str],
    src: Path,
    out: Path,
    timeout: int = 900,
    allow_docker: bool = True,
    env: dict[str, str] | None = None,
    docker_extra: list[str] | None = None,
) -> subprocess.CompletedProcess:
    """Roda uma ferramenta estática. Use {src} e {out} nos argumentos."""
    tool = TOOLS[tool_name]
    mode = resolve(tool, allow_docker)
    if mode is None:
        raise ToolUnavailable(f"{tool.name} não instalado ({tool.install})")
    out.mkdir(parents=True, exist_ok=True)

    if mode == "local":
        cmd = [tool.binary] + [a.replace("{src}", str(src)).replace("{out}", str(out)) for a in args]
        full_env = {**os.environ, **(env or {})}
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, env=full_env, cwd=src)

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{_docker_path(src)}:/src:ro",
        "-v", f"{_docker_path(out)}:/out",
        "-w", "/src",
        "--security-opt", "no-new-privileges",
    ]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += docker_extra or []
    cmd += [tool.image, *tool.docker_cmd] + [a.replace("{src}", "/src").replace("{out}", "/out") for a in args]
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout)


def docker(*args: str, timeout: int = 600, check: bool = False) -> subprocess.CompletedProcess:
    r = subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])}… falhou: {(r.stderr or r.stdout).strip()[-800:]}")
    return r


def run_container(
    image: str,
    args: list[str],
    networks: list[str],
    mounts: dict[Path, str] | None = None,
    timeout: int = 900,
    extra: list[str] | None = None,
) -> subprocess.CompletedProcess:
    """Cria o container, liga em várias redes e roda até o fim (docker run só aceita uma rede)."""
    name = f"vibesec-tool-{uuid.uuid4().hex[:8]}"
    cmd = ["create", "--name", name, "--network", networks[0], "--security-opt", "no-new-privileges"]
    for host, guest in (mounts or {}).items():
        host.mkdir(parents=True, exist_ok=True)
        cmd += ["-v", f"{_docker_path(host)}:{guest}"]
    cmd += (extra or []) + [image] + args
    docker(*cmd, check=True, timeout=300)
    try:
        for net in networks[1:]:
            docker("network", "connect", net, name, check=True)
        return docker("start", "-a", name, timeout=timeout)
    finally:
        docker("rm", "-f", name, timeout=60)

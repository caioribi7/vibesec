"""Obtém o código-alvo: URL do GitHub, owner/repo ou pasta local."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

GITHUB_RE = re.compile(
    r"^(?:https?://github\.com/|git@github\.com:)?(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)"
    r"(?:\.git)?/?(?:tree/(?P<branch>[^\s]+))?$"
)


@dataclass
class Target:
    label: str
    path: Path
    commit: str | None
    temporary: bool

    def cleanup(self) -> None:
        if self.temporary:
            try:
                shutil.rmtree(self.path.parent, onexc=_force_remove)  # Python 3.12+
            except TypeError:
                shutil.rmtree(self.path.parent, onerror=_force_remove)
            except OSError:
                pass


def _force_remove(func, path, _exc):  # arquivos read-only do .git no Windows
    import os
    import stat

    os.chmod(path, stat.S_IWRITE)
    func(path)


def parse_github(value: str) -> tuple[str, str, str | None] | None:
    if Path(value).exists():
        return None
    m = GITHUB_RE.match(value.strip())
    if not m:
        return None
    return m["owner"], m["repo"], m["branch"]


def fetch(value: str, branch: str | None = None, full_history: bool = False) -> Target:
    local = Path(value).expanduser()
    if local.exists():
        if not local.is_dir():
            raise ValueError(f"{value} não é uma pasta")
        return Target(local.resolve().name, local.resolve(), _git_head(local), temporary=False)

    gh = parse_github(value)
    if not gh:
        raise ValueError(
            f"Alvo inválido: {value!r}. Use uma URL do GitHub (https://github.com/dono/repo), "
            "dono/repo ou uma pasta local."
        )
    owner, repo, url_branch = gh
    branch = branch or url_branch
    tmp = Path(tempfile.mkdtemp(prefix="vibesec-"))
    dest = tmp / repo
    cmd = ["git", "clone", "--quiet", "--no-tags"]
    if not full_history:
        cmd += ["--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [f"https://github.com/{owner}/{repo}.git", str(dest)]
    # GIT_TERMINAL_PROMPT=0 evita travar pedindo senha em repo privado/inexistente
    r = subprocess.run(cmd, capture_output=True, text=True,
                       env={**__import__("os").environ, "GIT_TERMINAL_PROMPT": "0"}, timeout=600)
    if r.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        hint = ""
        if shutil.which("gh"):
            hint = " Repositório privado? Rode `gh auth login` ou `gh repo clone` e passe a pasta local."
        raise RuntimeError(f"Não consegui clonar {owner}/{repo}: {r.stderr.strip()}{hint}")
    return Target(f"{owner}/{repo}", dest, _git_head(dest), temporary=True)


def _git_head(path: Path) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True,
                           timeout=15)
        return r.stdout.strip() or None if r.returncode == 0 else None
    except OSError:
        return None


IGNORED_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".next", "__pycache__", ".venv", "venv",
    "env", ".tox", "target", "coverage", ".cache", ".turbo", ".svelte-kit", ".nuxt", "out", "bower_components",
}


def iter_files(root: Path, max_size: int = 1_000_000):
    """Arquivos de texto relevantes, sem dependências e builds."""
    for p in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in p.relative_to(root).parts[:-1]):
            continue
        if not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > max_size:
                continue
        except OSError:
            continue
        yield p


def read_text(p: Path) -> str | None:
    try:
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")

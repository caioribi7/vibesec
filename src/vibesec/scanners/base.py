from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vibesec.models import Finding


@dataclass
class ScanContext:
    root: Path               # código clonado
    work: Path               # pasta para saídas brutas das ferramentas
    stack: dict = field(default_factory=dict)
    depth: str = "standard"  # quick | standard | deep
    allow_docker: bool = True
    timeout: int = 900
    offline: bool = False    # containers com --network none; só bases locais

    def rel(self, path: str | Path | None) -> str | None:
        """Normaliza caminhos (locais ou /src/... do Docker) para relativos ao repo."""
        if not path:
            return None
        s = str(path).replace("\\", "/")
        root = str(self.root.resolve()).replace("\\", "/")
        for prefix in (root + "/", "/src/", "./"):
            if s.startswith(prefix):
                return s[len(prefix):]
        return s


class Scanner:
    name: str = "scanner"
    tool: str | None = None  # chave em runner.TOOLS, se depender de ferramenta externa

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def run(self, ctx: ScanContext) -> list[Finding]:
        raise NotImplementedError

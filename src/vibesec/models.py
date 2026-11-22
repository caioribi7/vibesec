"""Modelo de dados comum a todos os scanners."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)

    @property
    def label(self) -> str:
        return {
            "critical": "CRÍTICA",
            "high": "ALTA",
            "medium": "MÉDIA",
            "low": "BAIXA",
            "info": "INFO",
        }[self.value]

    @property
    def color(self) -> str:
        return {
            "critical": "bold white on red",
            "high": "bold red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim",
        }[self.value]

    @classmethod
    def parse(cls, value: str | None, default: "Severity" = None) -> "Severity":
        if not value:
            return default or cls.INFO
        v = str(value).strip().lower()
        aliases = {
            "error": "high",
            "warning": "medium",
            "warn": "medium",
            "note": "low",
            "moderate": "medium",
            "unknown": "info",
            "informational": "info",
            "negligible": "info",
            "none": "info",
        }
        v = aliases.get(v, v)
        try:
            return cls(v)
        except ValueError:
            return default or cls.INFO


class Category(str, Enum):
    CODE = "code"            # falha no código-fonte (SAST)
    SECRET = "secret"        # credencial ou chave exposta
    DEPENDENCY = "dependency"  # biblioteca com CVE conhecida
    CONFIG = "config"        # Dockerfile, IaC, configuração insegura
    NETWORK = "network"      # porta/serviço exposto (nmap)
    WEB = "web"              # vulnerabilidade web explorada (DAST)
    TRAFFIC = "traffic"      # dado sensível trafegando sem criptografia


@dataclass
class Finding:
    title: str
    severity: Severity
    category: Category
    tool: str
    description: str = ""
    file: str | None = None
    line: int | None = None
    rule_id: str | None = None
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    evidence: str | None = None
    remediation: str | None = None
    url: str | None = None
    confirmed: bool = False      # explorado de fato na sandbox
    false_positive: bool = False  # marcado pela triagem
    ai_notes: str | None = None
    references: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        key = "|".join(
            str(x or "")
            for x in (self.category.value, self.rule_id or self.title, self.file, self.line, self.url)
        )
        return hashlib.sha1(key.encode()).hexdigest()[:16]

    @property
    def location(self) -> str:
        if self.file:
            return f"{self.file}:{self.line}" if self.line else self.file
        return self.url or "-"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        d["fingerprint"] = self.fingerprint
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d.pop("fingerprint", None)
        d["severity"] = Severity.parse(d.get("severity"))
        d["category"] = Category(d.get("category", "code"))
        return cls(**d)


@dataclass
class ToolRun:
    name: str
    status: str  # ok | skipped | error
    detail: str = ""
    seconds: float = 0.0
    findings: int = 0


@dataclass
class ScanResult:
    target: str
    commit: str | None = None
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    stack: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    tools: list[ToolRun] = field(default_factory=list)
    ai_summary: str | None = None
    sandbox: dict = field(default_factory=dict)

    def add(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def dedupe(self) -> None:
        """O mesmo problema apontado por várias ferramentas vira um achado só.

        Chave: fingerprint exato, ou mesma linha + mesmo CWE (ex.: SQLi visto por vibesec, semgrep e bandit).
        Fica o texto do achado mais severo (empate: o primeiro, que é o embutido em português).
        """
        seen: dict[str, Finding] = {}
        alias: dict[tuple, str] = {}
        for f in self.findings:
            k = f.fingerprint
            loc_key = (f.category.value, f.file, f.line, f.cwe[0]) if f.file and f.line and f.cwe else None
            if k not in seen and loc_key in alias:
                k = alias[loc_key]
            if k in seen:
                cur = seen[k]
                if f.severity.rank > cur.severity.rank:
                    cur.severity = f.severity
                cur.confirmed = cur.confirmed or f.confirmed
                cur.cve = sorted(set(cur.cve) | set(f.cve))
                cur.references = list(dict.fromkeys(cur.references + f.references))[:5]
                cur.remediation = cur.remediation or f.remediation
                for t in f.tool.split("+"):
                    if t not in cur.tool.split("+"):
                        cur.tool = f"{cur.tool}+{t}"
            else:
                seen[k] = f
                if loc_key:
                    alias.setdefault(loc_key, k)
        self.findings = sorted(
            seen.values(), key=lambda f: (-f.severity.rank, not f.confirmed, f.category.value, f.location)
        )

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if not f.false_positive]

    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.active:
            c[f.severity.value] += 1
        return c

    @property
    def score(self) -> int:
        """Nota de 0 a 100 (100 = nada encontrado)."""
        weights = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
        penalty = sum(weights[f.severity.value] * (1.5 if f.confirmed else 1) for f in self.active)
        return max(0, round(100 - penalty))

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 55 else "D" if s >= 30 else "F"

    def to_dict(self) -> dict:
        return {
            "tool": "vibesec",
            "target": self.target,
            "commit": self.commit,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts(),
            "stack": self.stack,
            "sandbox": self.sandbox,
            "ai_summary": self.ai_summary,
            "tools": [asdict(t) for t in self.tools],
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        r = cls(target=d["target"], commit=d.get("commit"), started_at=d.get("started_at", ""))
        r.finished_at = d.get("finished_at")
        r.stack = d.get("stack", {})
        r.sandbox = d.get("sandbox", {})
        r.ai_summary = d.get("ai_summary")
        r.tools = [ToolRun(**t) for t in d.get("tools", [])]
        r.findings = [Finding.from_dict(f) for f in d.get("findings", [])]
        return r

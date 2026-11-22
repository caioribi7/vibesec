"""Wrappers das ferramentas de mercado. Cada uma vira lista de Finding normalizada."""

from __future__ import annotations

import json
import re

from vibesec.models import Category, Finding, Severity
from vibesec.runner import TOOLS, run_tool
from vibesec.scanners.base import ScanContext, Scanner

EXCLUDES = ["node_modules", "vendor", "dist", "build", ".next", ".venv", "venv", "__pycache__", ".git"]


def _json(text: str):
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # algumas ferramentas imprimem logs antes do JSON
        start = min((i for i in (text.find("{"), text.find("[")) if i >= 0), default=-1)
        if start < 0:
            return None
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            return None


def _cvss_to_sev(score) -> Severity:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return Severity.parse(score, Severity.MEDIUM)
    return (Severity.CRITICAL if s >= 9 else Severity.HIGH if s >= 7 else
            Severity.MEDIUM if s >= 4 else Severity.LOW if s > 0 else Severity.INFO)


class ExternalError(RuntimeError):
    pass


class SemgrepScanner(Scanner):
    name = "semgrep"
    tool = "semgrep"

    def run(self, ctx: ScanContext) -> list[Finding]:
        from vibesec.offline import SEMGREP_PACKS, semgrep_rules

        packs = SEMGREP_PACKS["deep" if ctx.depth == "deep" else "standard"]
        configs = [f"p/{p}" for p in packs]
        if ctx.offline:
            # regras baixadas por `vibesec update`, copiadas para a pasta montada em /out
            files = semgrep_rules(packs)
            if not files:
                from vibesec.runner import ToolUnavailable

                raise ToolUnavailable("sem regras locais do semgrep (rode `vibesec update` com internet)")
            rules_dir = ctx.work / "semgrep-rules"
            rules_dir.mkdir(parents=True, exist_ok=True)
            configs = []
            for f in files:
                (rules_dir / f.name).write_bytes(f.read_bytes())
                configs.append("{out}/semgrep-rules/" + f.name)
        args = ["scan", "--json", "--quiet", "--metrics=off", "--timeout", "30"]
        for c in configs:
            args += ["--config", c]
        for e in EXCLUDES:
            args += ["--exclude", e]
        args.append("{src}")
        p = run_tool("semgrep", args, ctx.root, ctx.work, ctx.timeout, ctx.allow_docker,
                     env={"SEMGREP_SEND_METRICS": "off", "PYTHONUTF8": "1"}, offline=ctx.offline)
        data = _json(p.stdout)
        if data is None:
            raise ExternalError((p.stderr or "saída vazia").strip()[-400:])
        out = []
        for r in data.get("results", []):
            ex = r.get("extra", {})
            meta = ex.get("metadata", {}) or {}
            cwe = [re.match(r"(CWE-\d+)", c).group(1) for c in _as_list(meta.get("cwe")) if re.match(r"CWE-\d+", c)]
            impact = str(meta.get("impact", "")).lower()
            sev = Severity.parse(ex.get("severity"), Severity.MEDIUM)
            if impact == "high" and sev == Severity.HIGH and str(meta.get("confidence", "")).lower() == "high":
                sev = Severity.CRITICAL
            lines = ex.get("lines", "")
            out.append(Finding(
                title=_short(ex.get("message", r.get("check_id"))), severity=sev,
                category=Category.SECRET if ".secrets." in r.get("check_id", "") else Category.CODE,
                tool=self.name, file=ctx.rel(r.get("path")), line=r.get("start", {}).get("line"),
                rule_id=r.get("check_id"), cwe=cwe, description=ex.get("message", ""),
                evidence=None if "requires login" in lines else lines.strip()[:300],
                references=_as_list(meta.get("references"))[:3],
                # extra.fix do semgrep é código de autofix, não texto: a correção vem do CWE na triagem
            ))
        return out


class BanditScanner(Scanner):
    name = "bandit"
    tool = "bandit"

    def applicable(self, ctx: ScanContext) -> bool:
        return "Python" in ctx.stack.get("languages", {})

    def run(self, ctx: ScanContext) -> list[Finding]:
        p = run_tool("bandit", ["-r", "{src}", "-f", "json", "-q", "-x", ",".join(f"./{e}" for e in EXCLUDES)],
                     ctx.root, ctx.work, ctx.timeout, ctx.allow_docker)
        data = _json(p.stdout)
        if data is None:
            raise ExternalError((p.stderr or "saída vazia").strip()[-400:])
        out = []
        for r in data.get("results", []):
            sev = Severity.parse(r.get("issue_severity"), Severity.LOW)
            if r.get("issue_confidence") == "LOW" and sev.rank > Severity.LOW.rank:
                sev = Severity(["info", "low", "medium", "high", "critical"][sev.rank - 1])
            cwe = r.get("issue_cwe", {}).get("id")
            out.append(Finding(
                title=r.get("issue_text", r.get("test_name")), severity=sev, category=Category.CODE,
                tool=self.name, file=ctx.rel(r.get("filename")), line=r.get("line_number"),
                rule_id=f"bandit.{r.get('test_id')}", cwe=[f"CWE-{cwe}"] if cwe else [],
                evidence=(r.get("code") or "").strip()[:300], references=[r.get("more_info")] if r.get("more_info") else [],
            ))
        return out


class GitleaksScanner(Scanner):
    name = "gitleaks"
    tool = "gitleaks"

    def run(self, ctx: ScanContext) -> list[Finding]:
        has_git = (ctx.root / ".git").exists()
        args = ["detect", "--source", "{src}", "--report-format", "json", "--report-path", "{out}/gitleaks.json",
                "--no-banner", "--exit-code", "0", "--redact"]
        if not has_git:
            args.append("--no-git")
        # docker: o repo é montado read-only e pertence a outro usuário
        p = run_tool("gitleaks", args, ctx.root, ctx.work, ctx.timeout, ctx.allow_docker,
                     env={"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*"},
                     offline=ctx.offline)
        report = ctx.work / "gitleaks.json"
        if not report.exists():
            raise ExternalError((p.stderr or p.stdout or "sem relatório").strip()[-400:])
        data = _json(report.read_text(encoding="utf-8")) or []
        out = []
        for r in data:
            commit = r.get("Commit")
            out.append(Finding(
                title=f"Segredo: {r.get('Description') or r.get('RuleID')}", severity=Severity.HIGH,
                category=Category.SECRET, tool=self.name, file=ctx.rel(r.get("File")), line=r.get("StartLine"),
                rule_id=f"gitleaks.{r.get('RuleID')}", cwe=["CWE-798"],
                evidence=(r.get("Match") or "")[:200],
                description="Segredo encontrado" + (f" no commit {commit[:8]} (continua no histórico mesmo "
                                                    "que já tenha sido apagado)" if commit else "") + ".",
                remediation="Revogue a credencial e limpe o histórico (git filter-repo / BFG).",
            ))
        return out


class TrivyScanner(Scanner):
    name = "trivy"
    tool = "trivy"

    def run(self, ctx: ScanContext) -> list[Finding]:
        args = ["fs", "--scanners", "vuln,misconfig", "--format", "json", "--quiet", "--timeout", "15m"]
        for e in EXCLUDES:
            args += ["--skip-dirs", f"**/{e}"]
        if ctx.depth == "quick":
            args += ["--severity", "HIGH,CRITICAL"]
        args.append("{src}")
        if ctx.offline:
            args[-1:-1] = ["--skip-db-update", "--skip-java-db-update", "--offline-scan", "--skip-check-update"]
        p = run_tool("trivy", args, ctx.root, ctx.work, ctx.timeout, ctx.allow_docker,
                     docker_extra=["-v", "vibesec-trivy-cache:/root/.cache/trivy"], offline=ctx.offline)
        data = _json(p.stdout)
        if data is None:
            raise ExternalError((p.stderr or "saída vazia").strip()[-400:])
        out = []
        for res in data.get("Results") or []:
            target = ctx.rel(res.get("Target"))
            for v in res.get("Vulnerabilities") or []:
                fixed = v.get("FixedVersion")
                out.append(Finding(
                    title=f"{v.get('PkgName')} {v.get('InstalledVersion')}: {_short(v.get('Title') or v.get('VulnerabilityID'))}",
                    severity=Severity.parse(v.get("Severity"), Severity.MEDIUM), category=Category.DEPENDENCY,
                    tool=self.name, file=target, rule_id=v.get("VulnerabilityID"),
                    cve=[v["VulnerabilityID"]] if str(v.get("VulnerabilityID", "")).startswith("CVE") else [],
                    cwe=v.get("CweIDs") or [], description=(v.get("Description") or "")[:600],
                    remediation=f"Atualize {v.get('PkgName')} para {fixed}." if fixed else
                    "Sem versão corrigida ainda: avalie trocar a biblioteca ou mitigar.",
                    references=[v["PrimaryURL"]] if v.get("PrimaryURL") else [],
                ))
            for m in res.get("Misconfigurations") or []:
                if m.get("Status") == "PASS":
                    continue
                out.append(Finding(
                    title=_short(m.get("Title") or m.get("ID")),
                    severity=Severity.parse(m.get("Severity"), Severity.LOW), category=Category.CONFIG,
                    tool=self.name, file=target, line=(m.get("CauseMetadata") or {}).get("StartLine"),
                    rule_id=m.get("AVDID") or m.get("ID"), description=m.get("Message") or m.get("Description", ""),
                    remediation=m.get("Resolution"), references=[m["PrimaryURL"]] if m.get("PrimaryURL") else [],
                ))
        return out


class OsvScanner(Scanner):
    name = "osv-scanner"
    tool = "osv-scanner"

    def applicable(self, ctx: ScanContext) -> bool:
        return not ctx.offline  # consulta a API do OSV.dev; offline o Trivy cobre dependências com a base local

    def run(self, ctx: ScanContext) -> list[Finding]:
        p = run_tool("osv-scanner", ["scan", "source", "-r", "--format", "json", "{src}"],
                     ctx.root, ctx.work, ctx.timeout, ctx.allow_docker)
        data = _json(p.stdout)
        if data is None:
            # v1 não tem o subcomando "scan source"
            p = run_tool("osv-scanner", ["--format", "json", "-r", "{src}"], ctx.root, ctx.work, ctx.timeout,
                         ctx.allow_docker)
            data = _json(p.stdout)
        if data is None:
            raise ExternalError((p.stderr or "saída vazia").strip()[-400:])
        out = []
        for res in data.get("results") or []:
            src = ctx.rel((res.get("source") or {}).get("path"))
            for pkg in res.get("packages") or []:
                info = pkg.get("package", {})
                groups = {tuple(g.get("ids", [])): g.get("max_severity") for g in pkg.get("groups") or []}
                for v in pkg.get("vulnerabilities") or []:
                    vid = v.get("id")
                    cves = [a for a in v.get("aliases") or [] if a.startswith("CVE-")]
                    score = next((s for ids, s in groups.items() if vid in ids), None)
                    out.append(Finding(
                        title=f"{info.get('name')} {info.get('version')}: {_short(v.get('summary') or vid)}",
                        severity=_cvss_to_sev(score) if score else Severity.MEDIUM, category=Category.DEPENDENCY,
                        tool=self.name, file=src, rule_id=cves[0] if cves else vid, cve=cves,
                        description=(v.get("details") or "")[:600],
                        remediation=f"Atualize {info.get('name')} ({info.get('ecosystem')}) para uma versão corrigida.",
                        references=[f"https://osv.dev/vulnerability/{vid}"],
                    ))
        return out


def _as_list(v) -> list[str]:
    if v is None:
        return []
    return [str(x) for x in v] if isinstance(v, list) else [str(v)]


def _short(s: str | None, n: int = 90) -> str:
    """Primeira frase, no máximo n caracteres (mensagens do semgrep/bandit são parágrafos)."""
    s = " ".join(str(s or "").split())
    s = re.split(r"(?<=[a-z0-9)'\"])\.\s", s, maxsplit=1)[0].rstrip(".")
    return s if len(s) <= n else s[: n - 1] + "…"


assert all(s in TOOLS for s in ("semgrep", "bandit", "gitleaks", "trivy", "osv-scanner"))

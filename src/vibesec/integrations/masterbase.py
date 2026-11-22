"""Integração opcional com o Masterbase (github.com/caioribi7/masterbase).

O VibeSec grava cada scan em tabelas `vibesec_*` no schema public de um Postgres qualquer.
O Masterbase abre esse banco num painel visual: dá para filtrar achados, marcar como corrigido
e acompanhar a evolução da nota sem escrever SQL.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from vibesec import config
from vibesec.models import ScanResult

SCHEMA_SQL = """
create table if not exists vibesec_scans (
  id bigserial primary key,
  target text not null,
  commit_sha text,
  score int not null,
  grade text not null,
  critical int not null default 0,
  high int not null default 0,
  medium int not null default 0,
  low int not null default 0,
  info int not null default 0,
  ai_summary text,
  started_at timestamptz,
  finished_at timestamptz,
  report jsonb not null
);
create table if not exists vibesec_findings (
  id bigserial primary key,
  scan_id bigint not null references vibesec_scans(id) on delete cascade,
  fingerprint text not null,
  severity text not null,
  category text not null,
  title text not null,
  location text,
  tool text,
  confirmed boolean not null default false,
  false_positive boolean not null default false,
  cwe text,
  cve text,
  description text,
  remediation text,
  ai_notes text,
  status text not null default 'aberto'
);
create index if not exists vibesec_findings_scan_idx on vibesec_findings(scan_id);
create index if not exists vibesec_scans_target_idx on vibesec_scans(target);
"""

MB_INSTALL = ("curl -fsSL https://raw.githubusercontent.com/caioribi7/masterbase/main/install.sh | sh  "
              "(Linux/macOS/WSL)  ou  cargo install --git https://github.com/caioribi7/masterbase masterbase")


class IntegrationError(RuntimeError):
    pass


def _psycopg():
    try:
        import psycopg
    except ImportError as e:
        raise IntegrationError('instale o driver: pip install "vibesec[db]"') from e
    return psycopg


def save_scan(result: ScanResult, dsn: str) -> int:
    psycopg = _psycopg()
    c = result.counts()
    with psycopg.connect(dsn, connect_timeout=10) as conn, conn.cursor() as cur:
        cur.execute(SCHEMA_SQL)
        cur.execute(
            """insert into vibesec_scans (target, commit_sha, score, grade, critical, high, medium, low, info,
                 ai_summary, started_at, finished_at, report)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) returning id""",
            (result.target, result.commit, result.score, result.grade, c["critical"], c["high"], c["medium"],
             c["low"], c["info"], result.ai_summary, result.started_at, result.finished_at,
             json.dumps(result.to_dict(), ensure_ascii=False)),
        )
        scan_id = cur.fetchone()[0]
        cur.executemany(
            """insert into vibesec_findings (scan_id, fingerprint, severity, category, title, location, tool,
                 confirmed, false_positive, cwe, cve, description, remediation, ai_notes)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            [(scan_id, f.fingerprint, f.severity.value, f.category.value, f.title, f.location, f.tool, f.confirmed,
              f.false_positive, ",".join(f.cwe), ",".join(f.cve), f.description, f.remediation, f.ai_notes)
             for f in result.findings],
        )
    return scan_id


def masterbase_binary() -> str | None:
    return shutil.which("masterbase")


def open_panel(dsn: str, addr: str = "127.0.0.1:8090") -> subprocess.Popen:
    exe = masterbase_binary()
    if not exe:
        raise IntegrationError(f"Masterbase não encontrado no PATH. Instale: {MB_INSTALL}")
    cfg = Path(config.HOME) / "masterbase.toml"  # config própria, não mexe na do usuário
    env = {**os.environ, "DATABASE_URL": dsn, "MB_ADDR": addr, "MB_CONFIG": str(cfg)}
    return subprocess.Popen([exe], env=env)

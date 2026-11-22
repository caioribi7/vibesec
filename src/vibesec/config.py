"""Configuração do usuário em ~/.vibesec/config.json e histórico de scans."""

from __future__ import annotations

import json
import os
from pathlib import Path

HOME = Path(os.environ.get("VIBESEC_HOME", Path.home() / ".vibesec"))
CONFIG = HOME / "config.json"
HISTORY = HOME / "history.jsonl"


def load() -> dict:
    try:
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save(data: dict) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        CONFIG.chmod(0o600)  # pode guardar a URL do banco com senha
    except OSError:
        pass


def get(key: str, env: str | None = None):
    if env and os.environ.get(env):
        return os.environ[env]
    return load().get(key)


def set_value(key: str, value) -> None:
    data = load()
    if value is None:
        data.pop(key, None)
    else:
        data[key] = value
    save(data)


def database_url() -> str | None:
    return get("database_url", "VIBESEC_DATABASE_URL")


def add_history(entry: dict) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    with HISTORY.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def history(limit: int = 20) -> list[dict]:
    try:
        lines = HISTORY.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(out) >= limit:
            break
    return out

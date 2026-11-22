"""Atualização das bases (online) e pacote para máquinas sem internet (air-gapped).

Fluxo:
  máquina com internet:   vibesec update  →  vibesec bundle export ./vibesec-bundle
  pendrive / rede interna
  máquina sem internet:   vibesec bundle import ./vibesec-bundle  →  vibesec scan ./repo --offline
"""

from __future__ import annotations

import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import httpx

from vibesec import config
from vibesec.runner import TOOLS, docker, docker_available

RULES_DIR = config.HOME / "rules"
STATE = config.HOME / "update.json"

SEMGREP_PACKS = {
    "standard": ["default", "owasp-top-ten", "secrets"],
    "deep": ["default", "owasp-top-ten", "secrets", "security-audit", "cwe-top-25"],
}
VOLUMES = ["vibesec-trivy-cache", "vibesec-nuclei"]
BASE_IMAGES = ["alpine/socat:latest", "alpine:latest", "node:20-alpine", "python:3.12-slim", "nginx:alpine"]


def images() -> list[str]:
    return sorted({t.image for t in TOOLS.values() if t.image} | set(BASE_IMAGES))


def semgrep_rules(packs: list[str]) -> list[Path]:
    return [RULES_DIR / f"semgrep-{p}.yml" for p in packs if (RULES_DIR / f"semgrep-{p}.yml").exists()]


def last_update_age_days() -> int | None:
    try:
        ts = json.loads(STATE.read_text(encoding="utf-8"))["updated_at"]
    except (OSError, KeyError, json.JSONDecodeError):
        return None
    return (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).days


Log = Callable[[str, bool, str], None]  # (passo, ok, detalhe)


def update(log: Log) -> bool:
    """Baixa tudo o que o modo offline precisa. Só roda com internet."""
    ok_all = True
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    for pack in SEMGREP_PACKS["deep"]:
        try:
            r = httpx.get(f"https://semgrep.dev/c/p/{pack}", timeout=60, follow_redirects=True,
                          headers={"User-Agent": "vibesec-update"})
            r.raise_for_status()
            if "rules:" not in r.text[:2000]:
                raise ValueError("resposta não é um ruleset")
            (RULES_DIR / f"semgrep-{pack}.yml").write_text(r.text, encoding="utf-8")
            log(f"regras semgrep p/{pack}", True, f"{len(r.text) // 1024} KB")
        except (httpx.HTTPError, ValueError) as e:
            ok_all = False
            log(f"regras semgrep p/{pack}", False, str(e)[:120])

    if not docker_available():
        log("imagens e bases", False, "Docker indisponível: só as regras do semgrep foram baixadas")
        return False

    for img in images():
        r = docker("pull", "-q", img, timeout=1800)
        ok_all &= r.returncode == 0
        log(f"imagem {img}", r.returncode == 0, (r.stderr or "").strip()[-120:])

    steps = [
        ("base de CVEs do Trivy", ["run", "--rm", "-v", "vibesec-trivy-cache:/root/.cache/trivy", TOOLS["trivy"].image,
                                   "image", "--download-db-only", "--quiet"]),
        ("base Java do Trivy", ["run", "--rm", "-v", "vibesec-trivy-cache:/root/.cache/trivy", TOOLS["trivy"].image,
                                "image", "--download-java-db-only", "--quiet"]),
        ("templates do nuclei", ["run", "--rm", "-v", "vibesec-nuclei:/root", TOOLS["nuclei"].image,
                                 "-ut", "-silent", "-nc"]),
    ]
    for name, args in steps:
        t0 = time.time()
        r = docker(*args, timeout=1800)
        ok_all &= r.returncode == 0
        log(name, r.returncode == 0, f"{time.time() - t0:.0f}s" if r.returncode == 0 else (r.stderr or "")[-160:])

    STATE.write_text(json.dumps({"updated_at": datetime.now(timezone.utc).isoformat(), "images": images()}),
                     encoding="utf-8")
    return ok_all


def export_bundle(dest: Path, log: Log) -> None:
    if not docker_available():
        raise RuntimeError("Docker indisponível")
    dest.mkdir(parents=True, exist_ok=True)
    imgs = images()
    r = docker("save", "-o", str((dest / "images.tar").resolve()), *imgs, timeout=3600)
    if r.returncode != 0:
        raise RuntimeError(f"docker save falhou: {r.stderr.strip()[-300:]} (rode `vibesec update` antes)")
    log("imagens", True, f"{(dest / 'images.tar').stat().st_size // 2**20} MB")
    for vol in VOLUMES:
        r = docker("run", "--rm", "-v", f"{vol}:/v:ro", "-v", f"{dest.resolve()}:/out", "alpine:latest",
                   "tar", "czf", f"/out/{vol}.tgz", "-C", "/v", ".", timeout=1800)
        log(f"volume {vol}", r.returncode == 0, (r.stderr or "").strip()[-120:])
    if RULES_DIR.exists():
        shutil.copytree(RULES_DIR, dest / "rules", dirs_exist_ok=True)
        log("regras", True, f"{len(list(RULES_DIR.glob('*.yml')))} arquivos")
    (dest / "manifest.json").write_text(json.dumps({
        "vibesec_bundle": 1, "created_at": datetime.now(timezone.utc).isoformat(), "images": imgs,
        "volumes": VOLUMES,
    }, indent=2), encoding="utf-8")


def import_bundle(src: Path, log: Log) -> None:
    manifest = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("vibesec_bundle") != 1:
        raise RuntimeError("pasta não é um pacote do VibeSec")
    if not docker_available():
        raise RuntimeError("Docker indisponível")
    r = docker("load", "-i", str((src / "images.tar").resolve()), timeout=3600)
    log("imagens", r.returncode == 0, (r.stderr or "").strip()[-160:])
    for vol in manifest.get("volumes", []):
        if not (src / f"{vol}.tgz").exists():
            continue
        docker("volume", "create", vol)
        r = docker("run", "--rm", "--network", "none", "-v", f"{vol}:/v", "-v", f"{src.resolve()}:/in:ro",
                   "alpine:latest", "tar", "xzf", f"/in/{vol}.tgz", "-C", "/v", timeout=1800)
        log(f"volume {vol}", r.returncode == 0, (r.stderr or "").strip()[-120:])
    if (src / "rules").exists():
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src / "rules", RULES_DIR, dirs_exist_ok=True)
        log("regras", True, "")
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({"updated_at": manifest["created_at"], "images": manifest["images"],
                                 "imported": True}), encoding="utf-8")

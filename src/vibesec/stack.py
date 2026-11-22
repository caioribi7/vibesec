"""Descobre linguagens, frameworks e como rodar a aplicação."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from vibesec.repo import iter_files, read_text

EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".java": "Java", ".kt": "Kotlin",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".rs": "Rust", ".c": "C", ".cpp": "C++", ".swift": "Swift",
    ".scala": "Scala", ".sql": "SQL", ".sh": "Shell", ".tf": "Terraform", ".vue": "Vue", ".svelte": "Svelte",
    ".dart": "Dart", ".ex": "Elixir",
}

JS_FRAMEWORKS = {
    "next": "Next.js", "express": "Express", "fastify": "Fastify", "@nestjs/core": "NestJS",
    "koa": "Koa", "react": "React", "vue": "Vue", "nuxt": "Nuxt", "svelte": "Svelte",
    "@sveltejs/kit": "SvelteKit", "@supabase/supabase-js": "Supabase", "firebase": "Firebase",
    "prisma": "Prisma", "@prisma/client": "Prisma", "mongoose": "MongoDB", "hono": "Hono",
    "astro": "Astro", "vite": "Vite", "electron": "Electron",
}
PY_FRAMEWORKS = {
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI", "streamlit": "Streamlit",
    "sqlalchemy": "SQLAlchemy", "supabase": "Supabase", "starlette": "Starlette",
}


def detect(root: Path) -> dict:
    langs: Counter[str] = Counter()
    files = 0
    for p in iter_files(root):
        files += 1
        lang = EXT_LANG.get(p.suffix.lower())
        if lang:
            langs[lang] += 1

    frameworks: set[str] = set()
    info: dict = {"package_manager": None, "start": None, "port": None}

    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            frameworks |= {v for k, v in JS_FRAMEWORKS.items() if k in deps}
            scripts = data.get("scripts", {})
            info["start"] = "start" if "start" in scripts else ("dev" if "dev" in scripts else None)
            info["package_manager"] = (
                "pnpm" if (root / "pnpm-lock.yaml").exists()
                else "yarn" if (root / "yarn.lock").exists()
                else "bun" if (root / "bun.lockb").exists() or (root / "bun.lock").exists()
                else "npm"
            )
            info["node_build"] = "build" in scripts
        except (json.JSONDecodeError, OSError):
            pass

    py_reqs = ""
    for name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py"):
        f = root / name
        if f.exists():
            py_reqs += (read_text(f) or "").lower()
    if py_reqs:
        frameworks |= {v for k, v in PY_FRAMEWORKS.items() if re.search(rf"\b{re.escape(k)}\b", py_reqs)}
        info["python_deps"] = "requirements.txt" if (root / "requirements.txt").exists() else (
            "pyproject.toml" if (root / "pyproject.toml").exists() else None)

    if (root / "go.mod").exists():
        frameworks.add("Go modules")
    if (root / "supabase").is_dir():
        frameworks.add("Supabase")

    dockerfile = root / "Dockerfile"
    if dockerfile.exists():
        text = read_text(dockerfile) or ""
        m = re.search(r"^\s*EXPOSE\s+(\d+)", text, re.M | re.I)
        if m:
            info["port"] = int(m.group(1))

    return {
        "files": files,
        "languages": dict(langs.most_common()),
        "primary": langs.most_common(1)[0][0] if langs else None,
        "frameworks": sorted(frameworks),
        "dockerfile": dockerfile.exists(),
        "compose": any((root / n).exists() for n in ("docker-compose.yml", "docker-compose.yaml",
                                                         "compose.yml", "compose.yaml")),
        **info,
    }

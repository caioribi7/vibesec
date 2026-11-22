"""Sobe a aplicação do repositório num container isolado.

Rede:
  vibesec-int-<id>  (--internal)  alvo + ferramentas. Sem saída para a internet.
  vibesec-pub-<id>  (bridge)      só o proxy socat, publicado em 127.0.0.1:<porta aleatória>.

O alvo nunca tem rota para fora, e os ataques só miram o alias "target" dentro dessa rede.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from vibesec.runner import docker

GENERATED_DOCKERFILE = "Dockerfile.vibesec"

NODE_TEMPLATE = """FROM node:20-alpine
WORKDIR /app
COPY . .
RUN {install}
{build}
ENV NODE_ENV=production PORT={port} HOST=0.0.0.0 HOSTNAME=0.0.0.0
EXPOSE {port}
CMD {cmd}
"""

PY_TEMPLATE = """FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir {install} gunicorn uvicorn
ENV PORT={port} PYTHONUNBUFFERED=1
EXPOSE {port}
CMD {cmd}
"""

STATIC_TEMPLATE = """FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
"""


class SandboxError(RuntimeError):
    pass


@dataclass
class Sandbox:
    root: Path
    stack: dict
    port: int | None = None
    run_cmd: str | None = None
    keep: bool = False
    log: list[str] = field(default_factory=list)

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    image: str = ""
    target: str = ""
    proxy: str = ""
    net_int: str = ""
    net_pub: str = ""
    host_url: str = ""
    generated: Path | None = None

    @property
    def internal_url(self) -> str:
        return f"http://target:{self.port}"

    # ------------------------------------------------------------------ build
    def _dockerfile(self) -> Path:
        df = self.root / "Dockerfile"
        if df.exists() and not self.run_cmd:
            self.port = self.port or self.stack.get("port") or 8080
            return df
        content = self._generate()
        self.generated = self.root / GENERATED_DOCKERFILE
        self.generated.write_text(content, encoding="utf-8")
        self.log.append(f"Dockerfile gerado automaticamente ({GENERATED_DOCKERFILE})")
        return self.generated

    def _generate(self) -> str:
        s = self.stack
        fw = set(s.get("frameworks", []))
        if (self.root / "package.json").exists():
            pm = s.get("package_manager") or "npm"
            self.port = self.port or 3000
            install = {
                "npm": "npm ci --no-audit --no-fund || npm install --no-audit --no-fund",
                "pnpm": "corepack enable && pnpm install --frozen-lockfile || pnpm install",
                "yarn": "corepack enable && yarn install --frozen-lockfile || yarn install",
                "bun": "npm i -g bun && bun install",
            }[pm]
            build = f"RUN {pm} run build" if s.get("node_build") else ""
            if self.run_cmd:
                cmd = f'["sh", "-c", {self._q(self.run_cmd)}]'
            elif s.get("start"):
                cmd = f'["sh", "-c", "{pm} run {s["start"]} -- --port {self.port} --hostname 0.0.0.0 || {pm} run {s["start"]}"]' \
                    if "Next.js" in fw else f'["{pm}", "run", "{s["start"]}"]'
            else:
                cmd = '["node", "index.js"]'
            return NODE_TEMPLATE.format(install=install, build=build, port=self.port, cmd=cmd)

        if s.get("python_deps") or "Python" in s.get("languages", {}):
            self.port = self.port or 8000
            install = "-r requirements.txt" if (self.root / "requirements.txt").exists() else (
                "." if (self.root / "pyproject.toml").exists() else "")
            cmd = self.run_cmd or self._python_cmd(fw)
            return PY_TEMPLATE.format(install=install, port=self.port, cmd=f'["sh", "-c", {self._q(cmd)}]')

        if (self.root / "index.html").exists():
            self.port = 80
            return STATIC_TEMPLATE

        raise SandboxError(
            "Não sei rodar esse projeto automaticamente. Adicione um Dockerfile ao repositório "
            "ou passe --run-cmd e --port."
        )

    def _python_cmd(self, fw: set[str]) -> str:
        p = self.port
        if "Django" in fw and (self.root / "manage.py").exists():
            return f"python manage.py migrate --noinput; python manage.py runserver 0.0.0.0:{p}"
        for mod in ("main", "app", "server", "api", "src/main", "app/main"):
            f = self.root / f"{mod}.py"
            if not f.exists():
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            m = mod.replace("/", ".")
            if "FastAPI(" in text:
                return f"uvicorn {m}:app --host 0.0.0.0 --port {p}"
            if "Flask(" in text:
                return f"gunicorn -b 0.0.0.0:{p} {m}:app"
            return f"python {mod}.py"
        if "Streamlit" in fw:
            return f"streamlit run app.py --server.port {p} --server.address 0.0.0.0"
        raise SandboxError("Não achei o ponto de entrada Python. Use --run-cmd.")

    @staticmethod
    def _q(s: str) -> str:
        import json

        return json.dumps(s)

    # ------------------------------------------------------------------ ciclo
    def start(self, build_timeout: int = 1200, ready_timeout: int = 120) -> None:
        df = self._dockerfile()
        self.image = f"vibesec-target:{self.id}"
        self.target = f"vibesec-target-{self.id}"
        self.proxy = f"vibesec-proxy-{self.id}"
        self.net_int = f"vibesec-int-{self.id}"
        self.net_pub = f"vibesec-pub-{self.id}"

        self.log.append("Construindo imagem do alvo…")
        r = docker("build", "-q", "-f", str(df), "-t", self.image, str(self.root), timeout=build_timeout)
        if r.returncode != 0:
            raise SandboxError(f"Falha no docker build:\n{(r.stderr or r.stdout)[-1500:]}")

        docker("network", "create", "--internal", self.net_int, check=True)
        docker("network", "create", self.net_pub, check=True)

        docker(
            "run", "-d", "--name", self.target, "--network", self.net_int, "--network-alias", "target",
            "--memory", "1g", "--cpus", "1.5", "--pids-limit", "512", "--security-opt", "no-new-privileges",
            "-e", f"PORT={self.port}", "--label", "vibesec=target", self.image, check=True,
        )
        # proxy: única ponte entre o host e a rede interna
        docker(
            "create", "--name", self.proxy, "--network", self.net_pub, "-p", "127.0.0.1::8080",
            "--label", "vibesec=proxy", "alpine/socat:latest",
            "tcp-listen:8080,fork,reuseaddr", f"tcp-connect:target:{self.port}", check=True,
        )
        docker("network", "connect", self.net_int, self.proxy, check=True)
        docker("start", self.proxy, check=True)
        mapping = docker("port", self.proxy, "8080/tcp", check=True).stdout.strip().splitlines()[0]
        self.host_url = f"http://127.0.0.1:{mapping.rsplit(':', 1)[1]}"
        self.log.append(f"Alvo isolado em {self.internal_url} (host: {self.host_url})")
        self._wait_ready(ready_timeout)

    def _wait_ready(self, timeout: int) -> None:
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            state = docker("inspect", "-f", "{{.State.Running}}", self.target).stdout.strip()
            if state != "true":
                lr = docker("logs", "--tail", "40", self.target)
                logs = (lr.stdout or "") + (lr.stderr or "")
                raise SandboxError(f"A aplicação parou ao iniciar. Últimos logs:\n{logs[-1500:]}")
            try:
                httpx.get(self.host_url, timeout=3, follow_redirects=False)
                self.log.append("Aplicação respondendo.")
                return
            except httpx.HTTPError as e:
                last = str(e)
            time.sleep(2)
        raise SandboxError(f"A aplicação não respondeu na porta {self.port} em {timeout}s ({last}). "
                           "Confira a porta com --port.")

    def logs(self, tail: int = 200) -> str:
        r = docker("logs", "--tail", str(tail), self.target)
        return (r.stdout or "") + (r.stderr or "")

    def stop(self) -> None:
        if self.keep:
            self.log.append(f"Sandbox mantida: {self.target} / {self.proxy} ({self.host_url})")
            return
        for c in (self.proxy, self.target):
            if c:
                docker("rm", "-f", c, timeout=60)
        for n in (self.net_int, self.net_pub):
            if n:
                docker("network", "rm", n, timeout=60)
        if self.image:
            docker("rmi", "-f", self.image, timeout=120)
        if self.generated and self.generated.exists():
            self.generated.unlink()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()

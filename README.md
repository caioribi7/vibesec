# VibeSec

**Pentest de ponta a ponta para repositórios do GitHub, direto do terminal.**

Você passa um repositório, o VibeSec analisa o código inteiro, sobe a aplicação numa sandbox Docker sem internet e ataca essa cópia de verdade com **nmap**, **nuclei**, **OWASP ZAP** e captura de tráfego (**tcpdump/tshark**). No fim, o **Claude** separa os falsos positivos, explica cada falha em português e mostra como corrigir.

Feito para quem cria apps no embalo (vibe coding) e quer saber se deixou a porta aberta: chave `service_role` do Supabase no frontend, `.env` versionado, RLS desligado, SQL injection, XSS, CORS liberado, debug ligado e por aí vai.

```
vibesec scan https://github.com/dono/repo
```

## O que ele testa

| Fase | Ferramenta | O que encontra |
|---|---|---|
| Código | **vibesec-sast** (embutido) | SQLi, injeção de comando, eval, SSTI, XSS, desserialização, JWT sem verificação, TLS desligado, CORS `*`, debug ligado, `NEXT_PUBLIC_*SECRET`, Supabase `service_role` no cliente, RLS desligado/permissivo, regras do Firebase abertas, Dockerfile como root |
| Código | **Semgrep** | Regras OWASP Top 10 em 30+ linguagens |
| Código | **Bandit** | Falhas específicas de Python |
| Segredos | **vibesec-secrets** (embutido) | AWS, GitHub, OpenAI, Anthropic, Stripe, Mercado Pago, Google, Slack, Discord, Telegram, chaves privadas, URLs de banco com senha, JWT da `service_role`, `.env` versionado |
| Segredos | **Gitleaks** | Segredos no código **e no histórico do git** |
| Dependências | **Trivy** + **OSV-Scanner** | CVEs em npm, pip, Go, Maven, Cargo, Composer… e erros em Dockerfile/Terraform/Kubernetes |
| Sandbox | **vibesec-probe** (embutido) | XSS refletido e SQL injection explorados de verdade, `.env`/`.git` expostos, CORS que reflete origem, stack traces, cabeçalhos de segurança |
| Rede | **nmap** | Todas as portas, versões dos serviços, scripts `vuln`, portas de debug (9229, 5678…), bancos expostos |
| Web | **nuclei** | Milhares de templates de exploração (CVEs, painéis, configurações) |
| Web | **OWASP ZAP** | Spider + scan passivo (`standard`) ou ativo completo (`deep`) |
| Tráfego | **tcpdump + tshark** | Domínios externos que o app tenta acessar, cookies de sessão sem `HttpOnly`/`SameSite`, credenciais em texto puro |
| IA | **Claude** | Triagem de falsos positivos, severidade real, explicação e correção para cada achado, resumo executivo com cadeia de ataque |

Os scanners embutidos funcionam sem instalar nada. As ferramentas externas rodam pelo binário local quando existe ou pela imagem Docker oficial.

## Instalação

Requer Python 3.10+ e git. Para os testes dinâmicos, [Docker](https://docs.docker.com/desktop/) rodando.

```bash
pip install "vibesec[all] @ git+https://github.com/caioribi7/vibesec"
vibesec doctor
```

Para a triagem com IA, defina sua chave:

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # Linux/macOS
$env:ANTHROPIC_API_KEY = "sk-ant-..."    # PowerShell
```

## Uso

```bash
vibesec                                   # menu interativo
vibesec scan dono/repo                    # completo (código + sandbox se houver Docker)
vibesec scan https://github.com/dono/repo --mode static   # só análise de código
vibesec scan ./minha-pasta --depth deep   # ZAP ativo, todas as regras, histórico git completo
vibesec scan dono/repo --port 5000 --run-cmd "python app.py"   # ensina como subir o app
vibesec scan dono/repo --fail-on high --no-ai -y               # para CI
vibesec history                           # scans anteriores
vibesec report vibesec-reports/x/report.json -f html          # refaz o relatório
```

Opções principais de `scan`:

| Opção | Padrão | Descrição |
|---|---|---|
| `--mode` | `auto` | `static`, `full` ou `auto` (full quando o Docker está disponível) |
| `--depth` | `standard` | `quick`, `standard` ou `deep` |
| `--ai / --no-ai` | auto | Triagem com Claude (liga sozinha com `ANTHROPIC_API_KEY`) |
| `--ai-model` | `claude-opus-5-5` | Modelo usado na triagem |
| `--port`, `--run-cmd` | detectados | Como iniciar a aplicação na sandbox |
| `--skip` | | Ferramentas a pular, ex. `zap,nuclei` |
| `--fail-on` | | Código de saída 1 se houver achado com essa severidade ou maior |
| `--format` | `html,md,json,sarif` | Formatos de relatório |
| `--keep-sandbox` | | Não destrói os containers no fim |

### Relatórios

Cada scan gera em `vibesec-reports/<repo>-<data>/`:

- `report.html`: painel com nota de A a F, filtros por categoria e detalhes de cada achado
- `report.md`: para colar numa issue ou PR
- `report.json`: dados completos
- `report.sarif`: sobe direto no GitHub Code Scanning

## Como a sandbox funciona

```
            host (127.0.0.1:porta aleatória)
                     │
             ┌───────┴────────┐  rede vibesec-pub (bridge)
             │  proxy socat   │
             └───────┬────────┘
                     │           rede vibesec-int (--internal, sem internet)
   ┌─────────────────┼─────────────────────────────┐
   │   ┌─────────────┴──┐   nmap · nuclei · ZAP     │
   │   │ alvo (seu app) │◄──────────────────────────│
   │   └───────┬────────┘                           │
   │       tcpdump (mesmo namespace de rede)        │
   └────────────────────────────────────────────────┘
```

1. O repositório é construído com o próprio `Dockerfile` ou com um gerado na hora (Node, Python/Django/Flask/FastAPI, site estático).
2. O alvo roda numa rede `--internal`: não acessa a internet e não alcança sua rede local. Limites de memória, CPU e processos, `no-new-privileges`.
3. As ferramentas de ataque só miram o alias `target` dentro dessa rede. A única ponte com o host é um proxy em `127.0.0.1`.
4. No fim, containers, redes e imagem são apagados.

**O VibeSec não ataca hosts externos.** Não existe opção para apontar os testes dinâmicos para um domínio ou IP; eles só rodam contra a cópia que ele mesmo sobe. Para testar um ambiente em produção, use as ferramentas diretamente e apenas com autorização por escrito do dono.

## Integra com

Integrações são opcionais e desligáveis; o VibeSec funciona sozinho.

### Masterbase

[Masterbase](https://github.com/caioribi7/masterbase) é um Postgres com tela visual. Ligando a integração, todo scan vai para as tabelas `vibesec_scans` e `vibesec_findings`, e você navega nos achados, marca o que já corrigiu (coluna `status`) e acompanha a nota ao longo do tempo sem escrever SQL.

```bash
vibesec masterbase setup --database-url postgresql://usuario:senha@127.0.0.1:5432/banco
vibesec masterbase open          # painel em http://127.0.0.1:8090
vibesec masterbase off           # desliga (não apaga dados)
```

Também aparece no menu (`vibesec` → Integrações). Use um banco seu; o Masterbase roda com uma config própria (`~/.vibesec/masterbase.toml`) para não mexer na sua. Com o usuário `postgres`, o painel ignora RLS (visão de administrador).

## CI (GitHub Actions)

```yaml
- run: pip install "vibesec @ git+https://github.com/caioribi7/vibesec"
- run: vibesec scan . --mode static --no-ai --fail-on high -y -f sarif,md
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: vibesec-reports }
```

## Desenvolvimento

```bash
git clone https://github.com/caioribi7/vibesec && cd vibesec
python -m venv .venv && .venv/bin/pip install -e ".[all,dev]"
pytest
vibesec scan tests/fixtures/vulnapp --mode static --no-ai
```

`tests/fixtures/vulnapp` é um app propositalmente vulnerável usado nos testes. Não faça deploy dele.

## Licença

MIT

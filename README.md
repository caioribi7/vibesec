<div align="center">

<img src="assets/banner.png" alt="VibeSec" width="100%">

**Pentest de ponta a ponta para SaaS, sites e APIs, a partir do repositório.**

Aponte para um repositório do GitHub. O VibeSec lê o código inteiro, sobe a aplicação numa sandbox Docker isolada e ataca essa cópia de verdade com as mesmas ferramentas de um pentester. No fim, entrega o que é explorável, a prova e a correção.

[![CI](https://github.com/caioribi7/vibesec/actions/workflows/ci.yml/badge.svg)](https://github.com/caioribi7/vibesec/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

```bash
pip install "vibesec @ git+https://github.com/caioribi7/vibesec"
vibesec scan dono/meu-saas
```

<p align="center">
  <img src="assets/screenshots/scan.png" alt="vibesec scan rodando contra um app de exemplo" width="100%">
</p>

<details>
<summary><b>Mais prints</b>: resumo com o que corrigir primeiro e o <code>vibesec doctor</code></summary>
<br>
<img src="assets/screenshots/resumo.png" alt="Resumo do VibeSec: corrija primeiro e cadeias de ataque" width="100%">
<br><br>
<img src="assets/screenshots/doctor.png" alt="vibesec doctor mostrando as ferramentas disponíveis" width="100%">
</details>

> Os prints são do scan estático do [`tests/fixtures/vulnapp`](tests/fixtures/vulnapp), o app vulnerável de propósito que a CI também ataca com a sandbox completa.

---

## Sumário

- [Para quem é](#para-quem-é)
- [O que ele testa](#o-que-ele-testa)
- [Arquitetura](#arquitetura)
- [Motor de triagem](#motor-de-triagem)
- [Com internet ou sem internet](#com-internet-ou-sem-internet)
- [Validação](#validação)
- [O que ele não cobre](#o-que-ele-não-cobre)
- [Uso](#uso)
- [Integra com](#integra-com)
- [Desenvolvimento](#desenvolvimento)

---

## Para quem é

Para quem está colocando um **SaaS, site ou API** no ar e quer saber, antes do atacante, onde deixou a porta aberta. Funciona com qualquer linguagem e tem atenção especial à stack de quem programa no embalo:

- **Next.js / React / Vite**: segredo em `NEXT_PUBLIC_*`, `dangerouslySetInnerHTML`, chave no bundle do navegador
- **Supabase**: `service_role` no cliente, tabela com **RLS desligado**, política `using (true)`
- **Firebase**: regras `allow read, write: if true`
- **Stripe, Mercado Pago, OpenAI, Anthropic, AWS, GitHub**: chaves vazadas no código ou no histórico do git
- **Flask, Django, FastAPI, Express**: SQL injection, injeção de comando, SSTI, desserialização, debug ligado em produção

## O que ele testa

Três camadas, cada uma cobrindo o que a outra não vê.

### 1. Código (estático)

| Ferramenta | Tipo | Cobre |
|---|---|---|
| `vibesec-sast` | embutido | 30+ regras: SQLi, injeção de comando, eval, SSTI, XSS, desserialização, path traversal, SSRF, open redirect, JWT sem verificação, TLS desligado, CORS `*`, debug, Supabase/Firebase/Next, Dockerfile como root |
| `vibesec-secrets` | embutido | 18 padrões de chaves + decodificação de JWT (detecta `service_role`) + `.env` versionado; ignora placeholders e chaves de exemplo |
| [Semgrep](https://semgrep.dev) | externo | OWASP Top 10, CWE Top 25 e auditoria de segurança em 30+ linguagens |
| [Bandit](https://bandit.readthedocs.io) | externo | Falhas específicas de Python |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | externo | Segredos no código **e em todo o histórico do git** |
| [Trivy](https://trivy.dev) | externo | CVEs em dependências (npm, pip, Go, Maven, Cargo, Composer…) e erros em Dockerfile, Terraform e Kubernetes |
| [OSV-Scanner](https://google.github.io/osv-scanner/) | externo | Segunda base de CVEs (OSV.dev) para dependências |

### 2. Aplicação rodando (dinâmico, dentro da sandbox)

| Ferramenta | Cobre |
|---|---|
| `vibesec-probe` (embutido) | Rastreia links e formulários e **explora**: XSS refletido, SQL injection por erro do banco, `.env`/`.git`/dumps SQL/bancos SQLite servidos pela web, console de debug, CORS que reflete origem com credenciais, stack traces, cabeçalhos de segurança, GraphQL introspection |
| [nmap](https://nmap.org) | Todas as 65 mil portas, versão de cada serviço, scripts `vuln` e `auth`, portas de debug (Node inspector, debugpy, JDWP), bancos e caches expostos |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Milhares de templates mantidos pela comunidade: CVEs, painéis, configurações expostas |
| [OWASP ZAP](https://www.zaproxy.org) | Spider + scan passivo (`standard`) ou **ativo completo** com spider AJAX (`deep`) |

### 3. Rede (tráfego capturado durante os ataques)

| Ferramenta | Cobre |
|---|---|
| `tcpdump` + `tshark` | Domínios externos que o app tenta acessar (telemetria, pacote comprometido), cookies de sessão sem `HttpOnly`/`SameSite`, credenciais Basic, formulários de senha |

> **Kali Linux e Burp Suite.** nmap, tcpdump, tshark, nuclei e ZAP são as mesmas ferramentas que vêm no Kali; o VibeSec usa as imagens Docker oficiais de cada uma, então não precisa de uma VM Kali. O papel do Burp Suite (proxy de interceptação + scanner ativo) é feito pelo **OWASP ZAP**, que é open source. O Burp Suite Pro é comercial e fechado, por isso não vem embutido.

### Mapeamento OWASP Top 10 (2021)

| Categoria | Como é coberta |
|---|---|
| A01 Controle de acesso | RLS do Supabase, regras do Firebase, CORS, arquivos expostos, path traversal |
| A02 Falhas criptográficas | Hash fraco para senha, TLS desligado, cookies sem flags, credenciais em texto puro no tráfego |
| A03 Injeção | SQLi, comando, SSTI, eval, XSS: no código **e explorados na sandbox** |
| A04 Design inseguro | Cadeias de ataque montadas pela triagem |
| A05 Configuração | Debug, cabeçalhos, Dockerfile, IaC, portas extras, GraphQL introspection |
| A06 Componentes vulneráveis | Trivy + OSV-Scanner + nuclei |
| A07 Autenticação | JWT sem verificação, `Math.random` em tokens, scripts `auth` do nmap |
| A08 Integridade | Desserialização insegura, GitHub Actions com injeção (`${{ }}` em `run:`) |
| A09 Logs e monitoramento | Stack traces e erros detalhados expostos |
| A10 SSRF | Requisição para URL vinda do usuário |

## Arquitetura

```mermaid
flowchart LR
    A[GitHub / pasta local] --> B[Detecção de stack]
    B --> C[Análise estática<br/>sast · secrets · semgrep · bandit<br/>gitleaks · trivy · osv]
    B --> D[Sandbox Docker]
    D --> E[Ataques<br/>probe · nmap · nuclei · ZAP]
    D --> F[Captura de tráfego<br/>tcpdump · tshark]
    C --> G[Deduplicação]
    E --> G
    F --> G
    G --> H[Motor de triagem]
    H --> I[Relatórios<br/>HTML · MD · JSON · SARIF]
    H --> J[(Masterbase<br/>opcional)]
```

**Detalhes de cada etapa:**

1. **Detecção de stack** (`stack.py`): linguagens, frameworks, gerenciador de pacotes, porta e comando de start.
2. **Análise estática** (`scanners/`): cada ferramenta vira uma lista de `Finding` no mesmo formato. Uma ferramenta que falha não derruba o scan; ela aparece como `erro` no relatório com o motivo.
3. **Sandbox** (`dynamic/sandbox.py`): usa o `Dockerfile` do repositório ou gera um (Node, Python/Django/Flask/FastAPI, estático).
4. **Ataques** (`dynamic/`): miram só o alias `target` dentro da rede interna.
5. **Deduplicação** (`models.py`): o mesmo problema visto por várias ferramentas (mesma linha + mesmo CWE) vira um achado só, com a severidade mais alta e todas as fontes.
6. **Triagem** (`triage.py`): veja abaixo.

### Isolamento da sandbox

```
        host  ─── 127.0.0.1:porta aleatória
                       │
               ┌───────┴────────┐   vibesec-pub (bridge)
               │  proxy socat   │   ← única ponte com o host
               └───────┬────────┘
   ┌───────────────────┼──────────────────────────────┐
   │                   │      vibesec-int (--internal) │  sem rota para a internet
   │    ┌──────────────┴──┐                            │  nem para a sua rede local
   │    │  seu app (alvo) │◄─── nmap · nuclei · ZAP    │
   │    └────────┬────────┘                            │
   │       tcpdump (mesmo namespace de rede do alvo)   │
   └──────────────────────────────────────────────────┘
```

- O alvo roda com limite de memória (1 GB), CPU (1,5) e processos (512) e com `no-new-privileges`.
- O código do repositório **nunca tem acesso à internet** durante o teste.
- No fim, containers, redes e a imagem são apagados (`--keep-sandbox` para inspecionar).
- **Não existe opção para atacar um host externo.** As sondas HTTP recusam qualquer URL ou redirecionamento que saia da sandbox, e isso é coberto por teste automatizado.

## Motor de triagem

A triagem é um algoritmo determinístico (`triage.py`): o código não sai da sua máquina, o resultado é reproduzível e cada decisão vem com o motivo escrito.

**Para cada achado:**

| Passo | O que faz |
|---|---|
| **Contexto do arquivo** | Código de terceiros/minificado → falso positivo. Teste, exemplo ou docs → rebaixa 2 níveis. |
| **Ponto vulnerável fixo?** | Para SQLi/comando: se a consulta é uma string constante, sem interpolação nem entrada → falso positivo. |
| **Fluxo de dados** | Procura, na função que contém a linha, fontes de entrada do usuário dos principais frameworks (Flask, Django, FastAPI, Express, Next.js, PHP, Spring, Go, Lambda: `request.args`, `req.body`, `$_GET`, `searchParams`, `@RequestParam`, `event.body`…). Entrada chegando sem tratamento → confiança **alta** (e média vira alta). |
| **Neutralização** | Reconhece o tratamento certo **para cada tipo de falha**: placeholders/`int()` para SQL, `shlex.quote`/`execFile` para comando, `DOMPurify`/`escape` para XSS, `secure_filename` para caminho, allowlist para SSRF. Encontrou → confiança baixa e rebaixa 1 nível. |
| **Validação de esquema** | zod, pydantic, Joi, yup reduzem a confiança. |
| **Concordância** | Duas ou mais ferramentas apontando o mesmo problema → confiança sobe. |
| **Segredos e dependências** | Chave de provedor específico → confiança alta. CVE sem versão corrigida e dependência transitiva → anotado. |

**Depois, no resultado inteiro:**

- **Correlação código × runtime.** Se a sandbox explorou SQLi em `GET /user`, o achado estático de SQLi dentro do handler de `/user` vira **confirmado**. Só o handler da rota conta, não o arquivo inteiro.
- **Cadeias de ataque.** Combina achados em cenários reais, como:
  - `service_role` no cliente + RLS desligado = banco aberto para a internet
  - XSS + cookie sem `HttpOnly` = sequestro de sessão
  - console de debug = controle do servidor
  - `.env` exposto = credenciais públicas
- **Resumo executivo.** Nota de 0 a 100, as 5 correções mais urgentes (exploradas primeiro) e as cadeias encontradas.

## Com internet ou sem internet

| | Online (máquina na internet/Wi-Fi) | Offline (máquina sem internet) |
|---|---|---|
| Comando | `vibesec scan dono/repo` | `vibesec scan ./repo --offline` |
| Alvo | URL do GitHub ou pasta | Pasta local |
| Bases (CVEs, templates, regras) | Atualizadas a cada execução | As do último `vibesec update` / pacote importado |
| Containers das ferramentas estáticas | Com rede (baixam bases) | `--network none` |
| Ferramentas de ataque | Rede pública (só atualizações) + rede interna | **Só a rede interna**: nenhuma rota para fora |
| Build do app | Normal | `--network none`; sem as dependências no cache, passe uma imagem pronta com `--image` |
| OSV-Scanner | Ligado | Desligado (precisa da API); o Trivy cobre dependências com a base local |

Nos dois modos, **os ataques só miram a sandbox local**. "Online" quer dizer apenas que as ferramentas podem baixar bases atualizadas.

**Máquina totalmente isolada (air-gapped):**

```bash
# na máquina com internet
vibesec update                      # imagens, base de CVEs do Trivy, templates do nuclei, regras do Semgrep
vibesec bundle export ./vibesec-bundle
docker build -t meu-app ./meu-repo && docker save -o meu-app.tar meu-app   # o app já com dependências

# leve as pastas (pendrive / rede interna) para a máquina sem internet
vibesec bundle import ./vibesec-bundle
docker load -i meu-app.tar
vibesec scan ./meu-repo --offline --image meu-app
```

Sem internet, o `npm install`/`pip install` do build não funciona; por isso o app vai pronto em `--image`. A análise do código continua sendo feita sobre a pasta.

## Validação

### Testes automatizados (todo push)

`pytest` em Ubuntu e Windows, Python 3.10 e 3.13:

| Área | O que é verificado |
|---|---|
| Scanners embutidos | Encontram as 17 falhas plantadas no app de teste; não acusam código seguro (consulta parametrizada, `yaml.SafeLoader`, `subprocess` com lista); ignoram placeholders e chaves de exemplo; nunca imprimem o segredo inteiro |
| Triagem | Fluxo de dados, string constante = falso positivo, sanitização, arquivos de teste/vendor, correlação limitada ao handler da rota, cadeias de ataque |
| Sondas dinâmicas | Contra um servidor HTTP vulnerável local: exploram XSS, SQLi, `.env` exposto e CORS; **recusam sair da sandbox**, inclusive por redirecionamento |
| Parsers | Saídas reais de nmap (XML), ZAP (JSON) e tshark |
| Modo offline | Containers recebem `--network none`, o Semgrep usa só regras locais, o OSV é desligado, as ferramentas de ataque ficam só na rede interna |
| Relatórios | HTML escapado (sem XSS no próprio relatório), SARIF válido, ida e volta do JSON |

### Pentest de ponta a ponta (todo push)

O job `sandbox-e2e` roda `vibesec scan --mode full` contra `tests/fixtures/vulnapp` (app Flask propositalmente vulnerável) num runner Ubuntu com Docker de verdade. O build **falha** se qualquer ferramenta não rodar ou se estas falhas plantadas não forem exploradas:

| Falha plantada | Detectada no código | Explorada na sandbox |
|---|---|---|
| SQL injection em `/user` | `vibesec-sast` + Semgrep | ✅ erro do SQLite com `'` |
| SSTI/XSS em `/hello` | `vibesec-sast` + Semgrep | ✅ payload refletido sem escape |
| Flask com `debug=True` | `vibesec-sast` + Bandit | ✅ console do Werkzeug acessível |
| Injeção de comando, pickle, yaml.load | `vibesec-sast` + Semgrep + Bandit | — (exigem payload destrutivo) |
| `.env` versionado, URL de banco com senha, chave AWS | `vibesec-secrets` | — |
| RLS desligado, política `using (true)`, `service_role` no cliente | `vibesec-sast` | — |
| Flask 0.12, PyYAML 5.3, requests 2.19 | Trivy + OSV (dezenas de CVEs) | — |

Os relatórios de cada execução ficam como artefato do workflow.

## O que ele não cobre

Seja cético com qualquer ferramenta que prometa "100% seguro". Passar limpo no VibeSec significa que **as verificações acima não encontraram nada**, não que o sistema é invulnerável. Fora do alcance hoje:

- **Lógica de negócio e autorização entre usuários** (IDOR, um usuário ver dados de outro, escalar para admin): exige entender as regras do produto. Ainda não há scan autenticado.
- **Áreas atrás de login**: as sondas e o ZAP veem só o que é público na sandbox.
- **Serviços externos**: o projeto Supabase/Firebase na nuvem, buckets S3 e DNS não estão dentro da sandbox. As regras e migrações versionadas no repositório são analisadas; a configuração feita só no painel, não.
- **Apps que dependem de serviços externos para subir** (banco gerenciado, APIs pagas): podem não iniciar na sandbox sem internet. Use `--run-cmd` ou um `docker-compose`/mock local.
- **Falhas sem assinatura conhecida** (0-day em dependência, falhas de lógica): ferramenta automática não substitui revisão humana.
- **Injeção de comando e desserialização** são detectadas no código, mas não exploradas na sandbox, de propósito: o payload executaria comandos no container.

## Uso

```bash
vibesec                                       # menu interativo
vibesec doctor                                # o que está instalado
vibesec scan dono/repo                        # completo (estático + sandbox se houver Docker)
vibesec scan https://github.com/dono/repo --depth deep
vibesec scan ./pasta --mode static            # só código
vibesec scan ./pasta --offline                # máquina sem internet
vibesec scan dono/repo --port 5000 --run-cmd "python app.py"
vibesec scan . --mode static --fail-on high -y -f sarif   # CI
vibesec update                                # atualiza bases
vibesec bundle export ./pacote | vibesec bundle import ./pacote
vibesec history
vibesec report vibesec-reports/x/report.json -f html
```

| Opção de `scan` | Padrão | Descrição |
|---|---|---|
| `--mode` | `auto` | `static`, `full` ou `auto` (full quando o Docker está rodando) |
| `--depth` | `standard` | Veja a tabela abaixo |
| `--offline` | | Nenhuma ferramenta acessa a rede |
| `--port`, `--run-cmd` | detectados | Como iniciar a aplicação na sandbox |
| `--image` | | Imagem Docker pronta do app (pula o build) |
| `--skip` | | Ferramentas a pular, ex. `zap,nuclei` |
| `--fail-on` | | Sai com código 1 se houver achado com essa severidade ou maior |
| `--format` | `html,md,json,sarif` | Formatos de relatório |
| `--keep-sandbox` | | Não destrói os containers no fim |
| `--save-db / --no-save-db` | auto | Grava no Postgres configurado (Masterbase) |

| Profundidade | nmap | nuclei | ZAP | Semgrep | Git | Sondas |
|---|---|---|---|---|---|---|
| `quick` | top 1000 portas | médio+, automático | baseline 1 min | padrão | último commit | 20 páginas |
| `standard` | 65 mil portas + scripts `vuln` | baixo+, automático | baseline 3 min | padrão + OWASP + secrets | último commit | 40 páginas |
| `deep` | + `--version-all`, scripts `auth`, TLS | **todos os templates** | **scan ativo completo** + spider AJAX | + security-audit + CWE Top 25 | **histórico completo** | 150 páginas |

**Relatórios** em `vibesec-reports/<repo>-<data>/`:

| Arquivo | Para quê |
|---|---|
| `report.html` | Nota de A a F, filtros por categoria, confiança e análise de cada achado |
| `report.md` | Para colar numa issue ou PR |
| `report.json` | Dados completos |
| `report.sarif` | Sobe direto no GitHub Code Scanning |

### No GitHub Actions

```yaml
- run: pip install "vibesec @ git+https://github.com/caioribi7/vibesec"
- run: vibesec scan . --mode static --fail-on high -y -f sarif,md
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: vibesec-reports }
```

## Integra com

Integrações são opcionais e desligáveis; o VibeSec funciona sozinho.

### Masterbase

O [Masterbase](https://github.com/caioribi7/masterbase) é um Postgres com tela visual. Com a integração ligada, todo scan vai para as tabelas `vibesec_scans` e `vibesec_findings`. No painel você filtra achados, marca o que já corrigiu (coluna `status`) e acompanha a nota ao longo do tempo, sem escrever SQL.

```bash
vibesec masterbase setup --database-url postgresql://usuario:senha@127.0.0.1:5432/banco
vibesec masterbase open          # painel em http://127.0.0.1:8090
vibesec masterbase off           # desliga (não apaga dados)
```

Também aparece no menu (`vibesec` → Integrações). O Masterbase roda com uma config própria (`~/.vibesec/masterbase.toml`). Com o usuário `postgres`, o painel ignora RLS (visão de administrador).

## Logo

O escudo tem o **V** no recorte do topo e na ponta, e o **S** vazado no corpo. Arquivos em [`assets/`](assets): `logo.svg` (degradê), `logo-black.svg` (uma cor) e `banner.svg`.

## Desenvolvimento

```bash
git clone https://github.com/caioribi7/vibesec && cd vibesec
python -m venv .venv && .venv/bin/pip install -e ".[all,dev]"
pytest && ruff check src tests
vibesec scan tests/fixtures/vulnapp --mode static
```

```
src/vibesec/
├── cli.py              comandos (Typer + Rich)
├── engine.py           orquestração das três camadas
├── triage.py           motor de triagem
├── offline.py          update / bundle export / bundle import
├── models.py           Finding, ScanResult, deduplicação, nota
├── report.py           terminal, HTML, Markdown, JSON, SARIF
├── runner.py           binário local ou imagem Docker oficial
├── scanners/           estáticos (embutidos + wrappers)
├── dynamic/            sandbox, sondas, nmap/nuclei/ZAP, captura
└── integrations/       Masterbase
```

Para adicionar uma regra, inclua um `Rule` em `scanners/builtin_code.py` e uma linha vulnerável em `tests/fixtures/vulnapp`; o teste exige que ela seja encontrada.

`tests/fixtures/vulnapp` é propositalmente vulnerável. **Não faça deploy dele.**

## Uso responsável

O VibeSec foi feito para você testar **o seu próprio código**. Os ataques rodam só contra a cópia isolada que ele mesmo sobe. Para testar um ambiente em produção de terceiros, é preciso autorização por escrito do dono.

## Licença

MIT

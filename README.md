# SwiftAudit

**Pentester-grade security analysis for any public GitHub repository — powered by LangGraph agents, Snyk, Trivy, and a 12-provider LLM fallback chain.**

Paste a GitHub URL. SwiftAudit clones the repo, runs parallel SAST/SCA/secrets scanners, then sends the most security-sensitive files through a chain of LLM agents that look for logic-level vulnerabilities pattern-matching tools miss. Results stream to your browser in real time. The whole pipeline typically completes in under two minutes.

---

## How It Works

SwiftAudit is built as a LangGraph pipeline with four sequential agents:

```
Navigator → Researcher → Exploiter → Auditor
```

**Navigator** — fetches the repository file tree from the GitHub API, scores every file for security relevance (auth, secrets, config, SQL, etc.), and selects the top candidates for deep analysis. File contents are fetched in parallel (6 simultaneous workers) which cuts this phase from ~45s to ~8s.

**Researcher** — runs three scanners concurrently on the cloned repo: Snyk Code (SAST), Trivy (SCA + secrets + Dockerfile misconfigs), and HistoryGuard (entropy-based zombie secret detection in git history). LLM analysis of high-priority files runs in a parallel thread pool of four workers alongside the scanners. Every finding is pushed to your browser the instant it's discovered.

**Exploiter** — for each CRITICAL or HIGH finding, generates a realistic step-by-step attacker simulation showing prerequisites, attack sequence, impact, and a proof-of-concept code snippet. PoC Python code is validated with `ast.parse()` before being shown to you.

**Auditor** — calculates a deterministic risk score (0–100) with letter grade, plots a six-dimension security radar (authentication, input validation, secrets, API security, dependencies, configuration), writes an executive summary, and assembles the final report.

---

## Features

- **Real-time streaming** — findings, logs, and progress updates arrive via Server-Sent Events (SSE) as the scan runs, not after it completes
- **Zero polling** — the browser connects once and waits; the server pushes events
- **12-provider LLM fallback** — if Groq is rate-limited the pipeline automatically retries with Gemini, GitHub Models, SambaNova, Mistral, and eight further fallbacks; scans never fail because one provider is down
- **70+ dependency file formats** — Trivy auto-detects requirements.txt, package-lock.json, pom.xml, go.mod, Cargo.lock, Gemfile.lock, composer.lock, and many more
- **Git history scanning** — HistoryGuard streams `git log -p` and flags high-entropy strings in deleted lines ("zombie secrets" that live in history even after being removed from HEAD)
- **Dockerfile misconfiguration** — Trivy's misconfig scanner checks Dockerfiles without needing Docker to be running
- **Trivy DB caching** — `--skip-db-update` flags prevent re-downloading the 200MB CVE database on every scan

---

## Requirements

### Python dependencies

```bash
pip install -r requirements.txt
```

Requires Python 3.10+.

### External CLI tools

Both must be on your `PATH` before starting the server.

**Snyk CLI**

```bash
npm install -g snyk
snyk auth          # authenticate with your Snyk account
```

**Trivy**

```bash
# macOS
brew install trivy

# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
```

On first run, Trivy downloads its vulnerability database (~200MB). Pre-warm it so your first scan doesn't time out:

```bash
trivy image alpine
```

---

## Setup

**1. Clone the repository**

```bash
git clone https://github.com/10486-JosephMutua/SwiftAudit.git
cd SwiftAudit
```

**2. Install Python dependencies**

```bash
pip install -r requirements.txt
```

**3. Create your `.env` file**

```bash
cp .env.example .env
```

Open `.env` and fill in your keys:

```env
# Required — at least one LLM provider must be set
GROQ_API_KEY=your_groq_api_key

# Optional LLM fallbacks (the more you add, the more resilient the pipeline)
GEMINI_API_KEY1=
OPENAI_API_KEY=           # GitHub Models endpoint
SAMBANOVA_API_KEY=
MISTRAL_API_KEY=
GEMINI_API_KEY2=

# Optional but recommended
GITHUB_TOKEN=your_github_token   # raises rate limit from 60 to 5000 req/hr
SNYK_TOKEN=your_snyk_token       # required for Snyk Code SAST
```

**4. Start the server**

```bash
python app.py
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## Usage

1. Paste any public GitHub repository URL into the input field (e.g. `https://github.com/juice-shop/juice-shop`)
2. Click **Scan**
3. Watch the pipeline graph as each phase activates — findings stream in on the right as scanners report them
4. When the scan completes, switch to the **Report** tab for the full risk score, radar chart, and executive summary

### Example repositories to try

| Repository | What to expect |
|---|---|
| `https://github.com/stamparm/DSVW` | SQL injection, command injection, SSRF |
| `https://github.com/WebGoat/WebGoat` | Broken auth, IDOR, XSS, path traversal |
| `https://github.com/juice-shop/juice-shop` | Full OWASP Top 10 coverage |

---

## Project Structure

```
SwiftAudit/
├── app.py                    # Flask server, API routes, SSE endpoint
│
├── core/
│   ├── pipeline.py           # LangGraph graph definition and scan lifecycle
│   ├── scanners.py           # Snyk Code, Trivy, parallel subprocess runner
│   ├── events.py             # In-process SSE bus (no Redis needed)
│   ├── models.py             # Pydantic models: findings, results, metadata
│   ├── graph_state.py        # LangGraph ScanState TypedDict
│   ├── config.py             # All configuration with dotenv loading
│   └── logger.py             # Colored console + rotating file logging
│
├── agents/
│   ├── navigator.py          # Repo fetch, file scoring, parallel content fetch
│   ├── researcher.py         # Scanner orchestration + LLM analysis + dedup
│   ├── exploiter.py          # Attack simulation generation
│   ├── auditor.py            # Risk scoring, radar, summary, report assembly
│   └── history_guard.py      # Git history entropy scanner
│
├── utils/
│   ├── llm_client.py         # Multi-provider fallback engine
│   ├── llm_providers.py      # All 12 LLM provider definitions
│   ├── github_fetcher.py     # Parallel GitHub API file fetcher
│   └── chunker.py            # Pygments-based code chunking and language detection
│
├── tools/
│   └── security_tools.py     # LangChain @tool functions for each agent
│
├── templates/
│   ├── index.html            # React 18 single-page dashboard (CDN, no build step)
│   └── report.md.j2          # Jinja2 markdown report template
│
├── logs/                     # Rotating log files (auto-created)
├── reports/output/           # Generated PDF/markdown reports
└── requirements.txt
```

---

## API Reference

All endpoints return JSON. Errors always return `{"error": "..."}` — never HTML.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scan` | Start a scan. Body: `{"repo_url": "https://..."}`. Returns `{"scan_id": "..."}` |
| `GET` | `/api/v1/scan/:id/stream` | SSE stream — connect here to receive live events |
| `GET` | `/api/v1/scan/:id/status` | Current progress percentage and step |
| `GET` | `/api/v1/scan/:id/result` | Full results once status is COMPLETED |
| `DELETE` | `/api/v1/scan/:id` | Remove a scan from the store |
| `GET` | `/api/v1/scans` | List all active scans |
| `GET` | `/api/v1/health` | Health check |

### SSE event types

The `/stream` endpoint emits these event types:

| Event | Payload |
|---|---|
| `progress` | `{"pct": 45, "step": "Researcher: Running Trivy...", "phase": "researcher"}` |
| `log` | `{"message": "...", "level": "INFO", "ts": 1234567890}` |
| `finding` | `{"title": "...", "severity": "HIGH", "file": "...", "source": "trivy"}` |
| `complete` | `{"score": 72, "grade": "D", "total_findings": 23, "duration": 87.4}` |
| `error` | `{"message": "..."}` |

---

## Configuration Reference

All values can be set in `.env` or as environment variables. Defaults work out of the box for local development.

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | — | **Required.** Primary LLM provider |
| `GITHUB_TOKEN` | — | Raises GitHub rate limit from 60 to 5000 req/hr |
| `SNYK_TOKEN` | — | Required for Snyk Code SAST |
| `FLASK_PORT` | `5000` | Server port |
| `CONCURRENT_FILE_FETCH` | `6` | Parallel GitHub file fetch workers |
| `CONCURRENT_LLM_SCANS` | `4` | Parallel LLM analysis workers |
| `MAX_FILES_TO_ANALYZE` | `15` | Top-N files sent to LLM analysis |
| `MAX_TOKENS_PER_FILE` | `6000` | Token limit per file chunk |
| `TRIVY_TIMEOUT` | `300` | Trivy timeout in seconds |
| `SNYK_TIMEOUT` | `120` | Snyk timeout in seconds |
| `GIT_CLONE_TIMEOUT` | `90` | git clone timeout in seconds |
| `SCAN_STORE_TTL_HOURS` | `24` | How long completed scans are kept in memory |

---

## Logging

SwiftAudit writes three log streams simultaneously:

- **Console** — color-coded by level (cyan=DEBUG, green=INFO, yellow=WARNING, red=ERROR)
- `logs/swiftaudit.log` — all levels, rotating at 10MB, 5 backups kept
- `logs/swiftaudit_errors.log` — ERROR and above only, rotating at 5MB, 3 backups kept

Every log line includes a timestamp, level, logger name, and message. Module prefixes make it easy to filter:

```
[APP]           Flask routes and request lifecycle
[PIPELINE]      LangGraph graph execution
[GRAPH:*]       Individual node execution (navigator, researcher, etc.)
[FETCHER]       GitHub API calls and file fetching
[SCANNERS]      Snyk and Trivy subprocess runs
[LLM_CLIENT]    Provider attempts and fallbacks
[LLM_PROVIDERS] Provider chain initialization
[EVENTS]        SSE subscriber activity
[HISTORY_GUARD] Git history scanning
```

---

## LLM Provider Fallback Chain

If any provider fails (rate limit, timeout, auth error, 500), the pipeline immediately tries the next one with the same prompt. No scan fails because a single provider is unavailable.

Priority order:

1. Groq — `llama-3.1-70b-versatile` (fastest)
2. Gemini 2.5 Flash (key 1)
3. GitHub Models — `gpt-4.1`
4. SambaNova — `Llama-4-Maverick`
5. Mistral Large
6. Gemini 2.0 Flash (key 2)
7. Scaleway — `gpt-oss-120b`
8. NVIDIA — `Nemotron-30B`
9. OpenRouter — `Nemotron-30B` (free tier)
10. Novita — `Llama-3.3-70B`
11. Fireworks — `Llama-405B`
12. Cloudflare Workers AI — `Llama-3.2-3B` (emergency fallback)

Only providers with keys set in `.env` are loaded. Any provider that fails to initialise is silently skipped.

---

## License

MIT — see [LICENSE](LICENSE) for details.

Copyright © 2026 Joseph Mwandikwa Mutua
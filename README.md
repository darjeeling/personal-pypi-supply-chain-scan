# Personal PyPI Supply Chain Scan

Personal PyPI Supply Chain Scan watches the PyPI updates RSS feed, downloads newly published package artifacts in an isolated Docker container, performs deterministic pre-scan checks, and asks GPT-5.5 through Codex OAuth to review only malicious supply-chain compromise indicators.

This is a personal automated scan. It is not an official security advisory, not an official PyPI, OpenAI, GitHub, or package maintainer assessment, and it may contain false positives or miss malicious behavior.

## What It Does

1. Reads `https://pypi.org/rss/updates.xml` with the `reader` library.
2. Resolves the package/version through the PyPI JSON API.
3. Prefers sdist over wheel so install/build metadata is visible when available.
4. Downloads and extracts the package only inside Docker.
5. Does not install the package, run build hooks, or execute `setup.py`.
6. Runs deterministic pre-scan checks with Python AST, text/manifest heuristics, and `ast-grep` when installed.
7. Sends only pre-scan findings and a focused evidence corpus to GPT-5.5 through Codex OAuth.
8. Writes Korean and English Markdown reports, report metadata, network indicator inventories, and SQLite scan history.
9. Builds a static GitHub Pages site and can publish it to a `gh-pages` branch.

## Scan Scope

The scanner is intentionally not a general application security scanner. It is tuned for malicious release and supply-chain compromise indicators:

- automatic execution: `.pth`, `sitecustomize.py`, `usercustomize.py`, `setup.py`, PEP 517 hooks, import-time side effects
- unexpected code in distribution artifacts
- broad credential harvesting from environment variables, `.env`, SSH keys, cloud credentials, AI provider keys, `~/.aws/credentials`, `~/.kube/config`, CI/CD tokens, registry tokens
- archive staging plus exfiltration to suspicious endpoints
- Kubernetes service-account abuse, privileged pods, host mounts, Docker socket access, cloud metadata access
- persistence through systemd, launch agents, cron, shell profile edits, startup folders, background polling
- obfuscation and staged loaders using base64, zlib, marshal, pickle, eval, exec, compile, XOR, steganography, downloader stubs
- dependency confusion, typosquatting, hidden payloads, unexplained native binaries, wheel/sdist mismatch
- URL, DNS/domain, raw public IP, drop/paste/GitHub raw style network indicators

Normal CLI entry points, expected SDK/API calls, documented credential configuration, user-triggered web servers, and normal file/network access should not be reported unless tied to automatic execution, theft, persistence, exfiltration, lateral movement, or stealth.

## Requirements

- Python 3.12+
- Docker
- `uv`
- Codex login at `~/.codex/auth.json`
- optional but recommended: `ast-grep`

```bash
brew install ast-grep
```

## Usage

```bash
uv run pypi-codex-scanner init-config
uv run pypi-codex-scanner run --config scanner.toml
uv run pypi-codex-scanner build-pages --config scanner.toml --site-dir site
uv run pypi-codex-scanner publish-pages --config scanner.toml --branch gh-pages
```

`publish-pages` commits to a local `gh-pages` branch by default. It only pushes when `--push` is supplied.

## Configuration

Example `scanner.toml`:

```toml
[schedule]
timezone = "Asia/Seoul"
crawl_windows = ["09:00-18:00"]
scan_windows = ["09:00-18:00"]

[limits]
max_updates = 10
max_scans_per_run = 3
max_llm_calls_per_run = 3
max_archive_bytes = 52428800
max_extracted_bytes = 104857600
max_files_for_model = 30
max_chars_for_model = 60000

[paths]
state_db = "data/state.sqlite3"
work_dir = "data/work"
reports_dir = "reports"

[openai]
model = "gpt-5.5"
codex_auth_path = "~/.codex/auth.json"
base_url = "https://chatgpt.com/backend-api/codex"
request_timeout_seconds = 120

[usage_gate]
enabled = true
min_primary_remaining_percent = 20
min_secondary_remaining_percent = 10
allow_if_unknown = true
backend_url = "https://chatgpt.com/backend-api/wham/usage"
```

Empty schedule windows mean always allowed.

## Report Layout

New scans are written as:

```text
reports/packages/{package}/{version}/ko.md
reports/packages/{package}/{version}/en.md
reports/packages/{package}/{version}/metadata.json
```

Each report includes:

- package version and PyPI publish time
- scan publish time
- model and prompt version
- disclaimer
- deterministic network indicators
- malicious supply-chain review
- prompt source link

## GitHub Pages Layout

Generated static pages use:

```text
/packages/{package}/{version}/ko/
/packages/{package}/{version}/en/
/packages/{package}/latest/ko/
/packages/{package}/latest/en/
/latest/ko/
/latest/en/
/index.json
/scans/latest.json
```

## Resume State

SQLite stores history indefinitely at `data/state.sqlite3` by default:

- RSS entries
- PyPI release metadata
- scan attempts
- report artifacts
- usage gate decisions

This allows later resume, reprocessing, reporting, and audit workflows.

## Prompt

The current prompt source is stored at:

- `docs/prompts/malicious-supply-chain-review-v2.md`


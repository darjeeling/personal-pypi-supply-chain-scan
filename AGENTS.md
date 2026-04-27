# Repository Guidelines

This repository implements a personal PyPI malicious supply-chain scan pipeline. Keep changes focused on that purpose.

## Product Positioning

- Use the public name `Personal PyPI Supply Chain Scan`.
- Keep the disclaimer visible in generated reports and Pages output:
  `This is a personal automated PyPI supply-chain scan. It is not an official security advisory, not an official PyPI, OpenAI, GitHub, or package maintainer assessment, and it may contain false positives or miss malicious behavior.`
- Avoid wording that sounds like an official PyPI, OpenAI, GitHub, maintainer, or security-vendor verdict.

## Scan Scope

The scanner is not a general application security scanner. Findings should focus on malicious supply-chain compromise indicators:

- automatic execution: `.pth`, `sitecustomize.py`, `usercustomize.py`, `setup.py`, PEP 517 hooks, import-time side effects
- broad credential harvesting
- archive staging and exfiltration
- persistence
- Kubernetes, Docker, cloud, CI/CD, or registry-token lateral movement
- obfuscation and staged loaders
- distribution integrity anomalies
- suspicious network indicators

Do not elevate ordinary CLI behavior, normal SDK/API calls, expected environment-variable use, or user-triggered web servers unless tied to theft, persistence, exfiltration, lateral movement, stealth, or automatic execution.

## Architecture Rules

- All project implementation should stay in Python unless explicitly changed.
- Package artifacts must be downloaded and extracted in Docker.
- Do not install scanned packages.
- Do not run build hooks.
- Do not execute `setup.py`.
- Prefer deterministic pre-scan reduction before LLM calls to reduce token use and latency.
- Use `ast-grep` when available, with Python AST/text/manifest heuristics as fallback and supplement.
- Keep network indicator extraction deterministic and include domains/URLs in reports.
- Exclude local/private/reserved IP ranges from raw public IP indicators.

## Reports

- Generate both `ko.md` and `en.md` from one LLM call where possible.
- Store reports under `reports/packages/{package}/{version}/`.
- Include package publish time and scan publish time.
- Include model name, prompt version, prompt source link, disclaimer, and deterministic network indicators.
- Keep prompt source under `docs/prompts/` and update the prompt version when behavior materially changes.

## State And Resume

- Store RSS entries, release metadata, scan attempts, report artifacts, and usage gate decisions in SQLite.
- Treat SQLite history as append-friendly and useful for resume/audit workflows.
- Do not delete generated `data/`, `reports/`, or `site/` artifacts unless explicitly asked.

## GitHub Pages

- Build static site output into `site/`.
- Publish through a `gh-pages` branch.
- Respect `[publish]` config for automatic publish cadence.
- `publish.every_scans = 1` means publish after every successful scan; `10` means after every ten; `0` or `enabled = false` disables automatic publishing.
- `publish.push` controls whether publishing pushes to origin.
- URL structure should remain:
  - `/packages/{package}/{version}/ko/`
  - `/packages/{package}/{version}/en/`
  - `/packages/{package}/latest/ko/`
  - `/packages/{package}/latest/en/`
  - `/latest/ko/`
  - `/latest/en/`

## Usage Gate

- Use Codex backend usage status when enabled.
- Respect the primary 5-hour remaining-percent threshold.
- Treat secondary weekly usage as a conservative daily budget: `100 / secondary_daily_budget_divisor` percent per elapsed day, with at least one day of budget allowed.
- Keep LLM concurrency at 1 unless explicitly changed.
- Keep `max_scans_per_run` and `max_llm_calls_per_run` configurable.
- Log usage gate decisions and one-line scan summaries so unattended runs are reviewable from logs.
- `run` is one-shot by default; `run --loop` should keep cycling forever and use `[run].sleep_seconds` unless `--sleep-seconds` overrides it.

## Cleanup

- Docker containers run with `--rm`, but host extraction directories under `data/work/` can grow.
- Respect `[cleanup]` config and remove old work directories after configured scan intervals.
- Do not enable Docker prune by default; only run it when `cleanup.docker_prune = true`.

## Git Hygiene

- Generated `.venv/`, `data/`, `reports/`, `site/`, and `__pycache__/` should stay ignored.
- Commit meaningful work units.
- Keep prompt, docs, source, and config examples in sync.

from __future__ import annotations

from pathlib import Path
import argparse
import sys

from .config import load_config, write_default_config
from .container import extract_in_container
from .openai_client import OpenAIResponsesClient
from .pypi import latest_updates, resolve_release
from .report import write_report
from .scanner import scan_release
from .schedule import is_allowed, schedule_now
from .state import StateStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pypi-codex-scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init-config")
    init_parser.add_argument("--path", type=Path, default=Path("scanner.toml"))

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--config", type=Path, default=Path("scanner.toml"))
    run_parser.add_argument("--force", action="store_true", help="Ignore configured crawl and scan time windows.")
    run_parser.add_argument("--dry-run", action="store_true", help="Fetch RSS and resolve packages, but do not extract or scan.")

    args = parser.parse_args(argv)
    if args.command == "init-config":
        write_default_config(args.path)
        print(f"Wrote {args.path}")
        return 0
    if args.command == "run":
        return _run(args.config, force=args.force, dry_run=args.dry_run)
    parser.error("unknown command")
    return 2


def _run(config_path: Path, *, force: bool, dry_run: bool) -> int:
    config = load_config(config_path)
    now = schedule_now(config.schedule)
    if not force and not is_allowed(now, config.schedule.crawl_windows):
        print(f"Skipping crawl outside configured window at {now.isoformat()}")
        return 0

    packages = latest_updates(config.rss_url, config.limits.max_updates)
    store = StateStore(config.paths.state_db)
    client = OpenAIResponsesClient(config.openai)
    try:
        for package in packages:
            if store.has_processed(package):
                print(f"skip already processed {package.name} {package.version}")
                continue
            release = resolve_release(package)
            print(f"candidate {package.name} {package.version} {release.filename}")
            if dry_run:
                continue
            if not force and not is_allowed(schedule_now(config.schedule), config.schedule.scan_windows):
                print(f"stop scanning outside configured window at {schedule_now(config.schedule).isoformat()}")
                return 0
            try:
                extracted = extract_in_container(config, release)
                result = scan_release(client, release, extracted)
                report_path = write_report(config.paths.reports_dir, release, result)
                store.mark(package, "scanned", report_path=report_path)
                print(f"report {report_path}")
            except Exception as exc:
                store.mark(package, "error", error=str(exc))
                print(f"error {package.name} {package.version}: {exc}", file=sys.stderr)
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())


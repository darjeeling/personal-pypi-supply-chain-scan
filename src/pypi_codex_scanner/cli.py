from __future__ import annotations

from pathlib import Path
import argparse
import sys

from .config import load_config, write_default_config
from .container import extract_in_container
from .openai_client import OpenAIResponsesClient
from .pypi import latest_update_entries, resolve_release
from .pages import build_pages, publish_pages
from .report import write_report
from .scanner import scan_release
from .schedule import is_allowed, schedule_now
from .state import StateStore
from .usage import check_usage_gate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pypi-llm-scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init-config")
    init_parser.add_argument("--path", type=Path, default=Path("scanner.toml"))

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--config", type=Path, default=Path("scanner.toml"))
    run_parser.add_argument("--force", action="store_true", help="Ignore configured crawl and scan time windows.")
    run_parser.add_argument("--dry-run", action="store_true", help="Fetch RSS and resolve packages, but do not extract or scan.")

    pages_parser = subparsers.add_parser("build-pages")
    pages_parser.add_argument("--config", type=Path, default=Path("scanner.toml"))
    pages_parser.add_argument("--site-dir", type=Path, default=None)

    publish_parser = subparsers.add_parser("publish-pages")
    publish_parser.add_argument("--config", type=Path, default=Path("scanner.toml"))
    publish_parser.add_argument("--site-dir", type=Path, default=None)
    publish_parser.add_argument("--branch", default=None)
    publish_parser.add_argument("--push", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "init-config":
        write_default_config(args.path)
        print(f"Wrote {args.path}")
        return 0
    if args.command == "run":
        return _run(args.config, force=args.force, dry_run=args.dry_run)
    if args.command == "build-pages":
        config = load_config(args.config)
        site_dir = args.site_dir or config.paths.site_dir
        build_pages(config.paths.reports_dir, site_dir)
        print(f"Wrote {site_dir}")
        return 0
    if args.command == "publish-pages":
        config = load_config(args.config)
        site_dir = args.site_dir or config.paths.site_dir
        branch = args.branch or config.publish.branch
        push = args.push or config.publish.push
        build_pages(config.paths.reports_dir, site_dir)
        publish_pages(site_dir, branch=branch, push=push)
        print(f"Published {site_dir} to {branch}")
        return 0
    parser.error("unknown command")
    return 2


def _run(config_path: Path, *, force: bool, dry_run: bool) -> int:
    config = load_config(config_path)
    now = schedule_now(config.schedule)
    if not force and not is_allowed(now, config.schedule.crawl_windows):
        print(f"Skipping crawl outside configured window at {now.isoformat()}")
        return 0

    updates = latest_update_entries(config.rss_url, config.limits.max_updates)
    store = StateStore(config.paths.state_db)
    client = OpenAIResponsesClient(config.openai)
    try:
        decision = check_usage_gate(config.usage_gate, config.openai)
        store.record_usage_gate(allowed=decision.allowed, reason=decision.reason, status=decision.status)
        if not force and not decision.allowed:
            print(f"Skipping scan due to usage gate: {decision.reason}")
            return 0
        scanned_count = 0
        llm_call_count = 0
        for update in updates:
            if scanned_count >= config.limits.max_scans_per_run or llm_call_count >= config.limits.max_llm_calls_per_run:
                print("stop scanning after configured run limits")
                return 0
            package = update.package
            store.record_rss_entry(
                feed_url=config.rss_url,
                package=package,
                title=update.title,
                link=update.link,
                published_at=update.published_at.isoformat() if update.published_at else None,
            )
            if store.has_processed(package):
                print(f"skip already processed {package.name} {package.version}")
                continue
            release = resolve_release(package)
            store.record_release(release)
            print(f"candidate {package.name} {package.version} {release.filename}")
            if dry_run:
                continue
            if not force and not is_allowed(schedule_now(config.schedule), config.schedule.scan_windows):
                print(f"stop scanning outside configured window at {schedule_now(config.schedule).isoformat()}")
                return 0
            attempt_id: int | None = None
            try:
                attempt_id = store.start_attempt(package)
                extracted = extract_in_container(config, release)
                result = scan_release(client, release, extracted)
                llm_call_count += 1
                artifacts = write_report(config.paths.reports_dir, release, result, extracted.prescan)
                store.mark(package, "scanned", report_path=artifacts.paths["ko"])
                store.record_report_artifacts(
                    artifacts,
                    package_published_at=release.published.isoformat() if release.published else None,
                )
                store.finish_attempt(attempt_id, status="scanned", model=result.model, prompt_version=result.prompt_version)
                scanned_count += 1
                print(f"report {artifacts.paths['ko']}")
                _maybe_publish(config, scanned_count)
            except Exception as exc:
                store.mark(package, "error", error=str(exc))
                if attempt_id is not None:
                    store.finish_attempt(attempt_id, status="error", error=str(exc))
                print(f"error {package.name} {package.version}: {exc}", file=sys.stderr)
        return 0
    finally:
        store.close()


def _maybe_publish(config: object, scanned_count: int) -> None:
    if not config.publish.enabled or config.publish.every_scans <= 0:
        return
    if scanned_count % config.publish.every_scans != 0:
        return
    build_pages(config.paths.reports_dir, config.paths.site_dir)
    publish_pages(config.paths.site_dir, branch=config.publish.branch, push=config.publish.push)
    print(f"published pages after {scanned_count} successful scans")


if __name__ == "__main__":
    raise SystemExit(main())

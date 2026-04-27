from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3


@dataclass(frozen=True)
class PackageVersion:
    name: str
    version: str


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        self.conn.commit()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            create table if not exists scans (
                name text not null,
                version text not null,
                status text not null,
                report_path text,
                error text,
                scanned_at text not null,
                primary key (name, version)
            );

            create table if not exists rss_entries (
                id text primary key,
                feed_url text not null,
                package_name text not null,
                version text not null,
                title text,
                link text,
                published_at text,
                first_seen_at text not null,
                last_seen_at text not null
            );

            create table if not exists releases (
                package_name text not null,
                version text not null,
                project_url text,
                download_url text,
                filename text,
                published_at text,
                digests_json text,
                resolved_at text not null,
                primary key (package_name, version)
            );

            create table if not exists scan_attempts (
                id integer primary key autoincrement,
                package_name text not null,
                version text not null,
                status text not null,
                started_at text not null,
                finished_at text,
                error text,
                model text,
                prompt_version text
            );

            create table if not exists report_artifacts (
                id integer primary key autoincrement,
                package_name text not null,
                version text not null,
                language text not null,
                path text not null,
                metadata_path text,
                scanned_at text not null,
                published_at text,
                unique(package_name, version, language, scanned_at)
            );

            create table if not exists usage_gate_decisions (
                id integer primary key autoincrement,
                checked_at text not null,
                allowed integer not null,
                reason text,
                status_json text
            );
            """
        )

    def close(self) -> None:
        self.conn.close()

    def has_processed(self, package: PackageVersion) -> bool:
        row = self.conn.execute(
            "select 1 from scans where name = ? and version = ?",
            (package.name, package.version),
        ).fetchone()
        return row is not None

    def record_rss_entry(self, *, feed_url: str, package: PackageVersion, title: str | None, link: str | None, published_at: str | None) -> None:
        now = _utc_now()
        entry_id = link or f"{feed_url}#{package.name}=={package.version}"
        self.conn.execute(
            """
            insert into rss_entries (id, feed_url, package_name, version, title, link, published_at, first_seen_at, last_seen_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict(id) do update set
                title = excluded.title,
                link = excluded.link,
                published_at = excluded.published_at,
                last_seen_at = excluded.last_seen_at
            """,
            (entry_id, feed_url, package.name, package.version, title, link, published_at, now, now),
        )
        self.conn.commit()

    def record_release(self, release: object) -> None:
        now = _utc_now()
        package = release.package
        self.conn.execute(
            """
            insert into releases (package_name, version, project_url, download_url, filename, published_at, digests_json, resolved_at)
            values (?, ?, ?, ?, ?, ?, ?, ?)
            on conflict(package_name, version) do update set
                project_url = excluded.project_url,
                download_url = excluded.download_url,
                filename = excluded.filename,
                published_at = excluded.published_at,
                digests_json = excluded.digests_json,
                resolved_at = excluded.resolved_at
            """,
            (
                package.name,
                package.version,
                release.project_url,
                release.download_url,
                release.filename,
                release.published.isoformat() if release.published else None,
                json.dumps(release.digests, sort_keys=True),
                now,
            ),
        )
        self.conn.commit()

    def start_attempt(self, package: PackageVersion) -> int:
        cursor = self.conn.execute(
            "insert into scan_attempts (package_name, version, status, started_at) values (?, ?, ?, ?)",
            (package.name, package.version, "running", _utc_now()),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def finish_attempt(self, attempt_id: int, *, status: str, error: str | None = None, model: str | None = None, prompt_version: str | None = None) -> None:
        self.conn.execute(
            """
            update scan_attempts
            set status = ?, finished_at = ?, error = ?, model = ?, prompt_version = ?
            where id = ?
            """,
            (status, _utc_now(), error, model, prompt_version, attempt_id),
        )
        self.conn.commit()

    def record_report_artifacts(self, artifacts: object, *, package_published_at: str | None) -> None:
        for language, path in artifacts.paths.items():
            self.conn.execute(
                """
                insert or ignore into report_artifacts
                    (package_name, version, language, path, metadata_path, scanned_at, published_at)
                values (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifacts.package,
                    artifacts.version,
                    language,
                    str(path),
                    str(artifacts.metadata_path),
                    artifacts.scanned_at,
                    package_published_at,
                ),
            )
        self.conn.commit()

    def record_usage_gate(self, *, allowed: bool, reason: str, status: dict | None = None) -> None:
        self.conn.execute(
            "insert into usage_gate_decisions (checked_at, allowed, reason, status_json) values (?, ?, ?, ?)",
            (_utc_now(), 1 if allowed else 0, reason, json.dumps(status or {}, sort_keys=True)),
        )
        self.conn.commit()

    def mark(self, package: PackageVersion, status: str, report_path: Path | None = None, error: str | None = None) -> None:
        self.conn.execute(
            """
            insert into scans (name, version, status, report_path, error, scanned_at)
            values (?, ?, ?, ?, ?, ?)
            on conflict(name, version) do update set
                status = excluded.status,
                report_path = excluded.report_path,
                error = excluded.error,
                scanned_at = excluded.scanned_at
            """,
            (
                package.name,
                package.version,
                status,
                str(report_path) if report_path else None,
                error,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self.conn.commit()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

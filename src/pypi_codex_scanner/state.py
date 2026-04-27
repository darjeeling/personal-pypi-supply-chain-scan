from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
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
        self.conn.execute(
            """
            create table if not exists scans (
                name text not null,
                version text not null,
                status text not null,
                report_path text,
                error text,
                scanned_at text not null,
                primary key (name, version)
            )
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def has_processed(self, package: PackageVersion) -> bool:
        row = self.conn.execute(
            "select 1 from scans where name = ? and version = ?",
            (package.name, package.version),
        ).fetchone()
        return row is not None

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


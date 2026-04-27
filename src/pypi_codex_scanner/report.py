from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re

from .pypi import PypiRelease
from .scanner import ScanResult


def write_report(reports_dir: Path, release: PypiRelease, result: ScanResult) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", release.package.name)
    safe_version = re.sub(r"[^A-Za-z0-9_.-]+", "-", release.package.version)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = reports_dir / f"{stamp}-{safe_name}-{safe_version}.md"
    header = f"""# PyPI Security Scan: {release.package.name} {release.package.version}

- Package: `{release.package.name}`
- Version: `{release.package.version}`
- Project URL: {release.project_url}
- Distribution: `{release.filename}`
- Published: {release.published.isoformat() if release.published else "unknown"}
- Scanned at UTC: {datetime.now(timezone.utc).isoformat()}

"""
    path.write_text(header + result.markdown.strip() + "\n", encoding="utf-8")
    return path


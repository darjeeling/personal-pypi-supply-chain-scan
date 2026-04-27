from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re

from .pypi import PypiRelease
from .scanner import ScanResult


def write_report(reports_dir: Path, release: PypiRelease, result: ScanResult, prescan: dict | None = None) -> Path:
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
    path.write_text(header + _network_section(prescan or {}) + result.markdown.strip() + "\n", encoding="utf-8")
    return path


def _network_section(prescan: dict) -> str:
    indicators = prescan.get("network_indicators") or {}
    if not indicators:
        return ""
    sections = [
        ("Suspicious Endpoints", indicators.get("suspicious_endpoints") or []),
        ("Raw Public IPs", indicators.get("raw_public_ips") or []),
        ("URLs", indicators.get("urls") or []),
        ("Domains", indicators.get("domains") or []),
    ]
    lines = ["## Deterministic Network Indicators", ""]
    for title, rows in sections:
        lines.append(f"### {title}")
        if not rows:
            lines.append("")
            lines.append("None")
            lines.append("")
            continue
        for row in rows[:30]:
            value = row.get("value", "")
            file_count = row.get("file_count", 0)
            files = ", ".join(f"`{item}`" for item in (row.get("files") or [])[:5])
            suffix = f" ({file_count} files: {files})" if files else ""
            lines.append(f"- `{value}`{suffix}")
        if len(rows) > 30:
            lines.append(f"- ... {len(rows) - 30} more")
        lines.append("")
    return "\n".join(lines) + "\n"

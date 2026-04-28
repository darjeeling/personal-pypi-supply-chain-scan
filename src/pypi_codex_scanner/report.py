from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import re

from .pypi import PypiRelease
from .scanner import ScanResult


DISCLAIMER = (
    "This is a personal automated PyPI supply-chain scan. It is not an official "
    "security advisory, not an official PyPI, OpenAI, GitHub, or package maintainer "
    "assessment, and it may contain false positives or miss malicious behavior."
)


@dataclass(frozen=True)
class ReportArtifacts:
    package: str
    version: str
    package_slug: str
    version_slug: str
    scanned_at: str
    paths: dict[str, Path]
    metadata_path: Path


def write_report(reports_dir: Path, release: PypiRelease, result: ScanResult, prescan: dict | None = None) -> ReportArtifacts:
    package_slug = normalize_slug(release.package.name)
    version_slug = normalize_slug(release.package.version)
    scanned_at = datetime.now(timezone.utc).isoformat()
    report_dir = reports_dir / "packages" / package_slug / version_slug
    report_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "ko": report_dir / "ko.md",
        "en": report_dir / "en.md",
    }
    metadata_path = report_dir / "metadata.json"
    metadata = {
        "title": f"Personal PyPI Supply Chain Scan: {release.package.name} {release.package.version}",
        "package": release.package.name,
        "version": release.package.version,
        "package_slug": package_slug,
        "version_slug": version_slug,
        "project_url": release.project_url,
        "distribution": release.filename,
        "published_at": release.published.isoformat() if release.published else None,
        "scanned_at": scanned_at,
        "model": result.model,
        "prompt_version": result.prompt_version,
        "prompt_url": "docs/prompts/malicious-supply-chain-review-v2.md",
        "risk": _extract_risk(result.markdown_en + "\n" + result.markdown_ko),
        "disclaimer": DISCLAIMER,
        "network_indicators": (prescan or {}).get("network_indicators", {}),
        "finding_count": (prescan or {}).get("finding_count", 0),
    }

    paths["ko"].write_text(
        _document_header(release, scanned_at, result, "ko")
        + _network_section(prescan or {})
        + result.markdown_ko.strip()
        + _document_footer()
        + "\n",
        encoding="utf-8",
    )
    paths["en"].write_text(
        _document_header(release, scanned_at, result, "en")
        + _network_section(prescan or {})
        + result.markdown_en.strip()
        + _document_footer()
        + "\n",
        encoding="utf-8",
    )
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return ReportArtifacts(
        package=release.package.name,
        version=release.package.version,
        package_slug=package_slug,
        version_slug=version_slug,
        scanned_at=scanned_at,
        paths=paths,
        metadata_path=metadata_path,
    )


def normalize_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-")


def _extract_risk(markdown: str) -> str:
    lowered = markdown.lower()
    for pattern in (
        r"overall\s+risk\s*[:：]\s*[*_` ]*(critical|high|medium|low|info)",
        r"전체\s*위험도\s*[:：]\s*[*_` ]*(critical|high|medium|low|info)",
        r"위험도\s*[:：]\s*[*_` ]*(critical|high|medium|low|info)",
    ):
        match = re.search(pattern, lowered)
        if match:
            return match.group(1)
    for risk in ("critical", "high", "medium", "low", "info"):
        if re.search(rf"\b{risk}\b", lowered):
            return risk
    if "없음" in markdown or "no confirmed" in lowered:
        return "info"
    return "unknown"


def _document_header(release: PypiRelease, scanned_at: str, result: ScanResult, language: str) -> str:
    return f"""# Personal PyPI Supply Chain Scan: {release.package.name} {release.package.version}

- Package: `{release.package.name}`
- Version: `{release.package.version}`
- Project URL: {release.project_url}
- Distribution: `{release.filename}`
- Package published at: {release.published.isoformat() if release.published else "unknown"}
- Scan published at: {scanned_at}
- Language: `{language}`
- Model: `{result.model}`
- Prompt: `{result.prompt_version}` ([source](../../../../docs/prompts/malicious-supply-chain-review-v2.md))
- Disclaimer: {DISCLAIMER}

"""


def _document_footer() -> str:
    return f"""

---

Prompt source: `docs/prompts/malicious-supply-chain-review-v2.md`

{DISCLAIMER}
"""


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

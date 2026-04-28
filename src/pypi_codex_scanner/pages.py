from __future__ import annotations

from pathlib import Path
import html
import json
import re
import shutil
import subprocess
import tempfile


def build_pages(reports_dir: Path, site_dir: Path) -> None:
    if site_dir.exists():
        shutil.rmtree(site_dir)
    site_dir.mkdir(parents=True, exist_ok=True)

    reports = _load_report_metadata(reports_dir)
    _copy_prompt_docs(site_dir)
    _write_index(site_dir, reports)
    for report in reports:
        _write_report_pages(site_dir, reports_dir, report)
    latest = reports[0] if reports else None
    if latest:
        _write_redirect(site_dir / "latest" / "ko" / "index.html", f"../../packages/{latest['package_slug']}/{latest['version_slug']}/ko/")
        _write_redirect(site_dir / "latest" / "en" / "index.html", f"../../packages/{latest['package_slug']}/{latest['version_slug']}/en/")
    (site_dir / "scans").mkdir(parents=True, exist_ok=True)
    (site_dir / "scans" / "latest.json").write_text(json.dumps(latest or {}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (site_dir / "index.json").write_text(json.dumps(reports, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def publish_pages(site_dir: Path, *, branch: str = "gh-pages", push: bool = False) -> None:
    with tempfile.TemporaryDirectory(prefix="pypi-llm-pages-") as tmp:
        worktree = Path(tmp) / "worktree"
        if _branch_exists(branch):
            _run(["git", "worktree", "add", str(worktree), branch])
        else:
            _run(["git", "worktree", "add", "--detach", str(worktree), "HEAD"])
            _run(["git", "checkout", "--orphan", branch], cwd=worktree)
        try:
            _clear_directory(worktree)
            for item in site_dir.iterdir():
                target = worktree / item.name
                if item.is_dir():
                    shutil.copytree(item, target)
                else:
                    shutil.copyfile(item, target)
            (worktree / ".nojekyll").write_text("", encoding="utf-8")
            _run(["git", "add", "."], cwd=worktree)
            if _has_changes(worktree):
                _run(["git", "commit", "-m", "Publish scan reports"], cwd=worktree)
            if push:
                _run(["git", "push", "origin", branch], cwd=worktree)
        finally:
            _run(["git", "worktree", "remove", "--force", str(worktree)])


def _load_report_metadata(reports_dir: Path) -> list[dict]:
    rows: list[dict] = []
    for path in reports_dir.glob("packages/*/*/metadata.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        data["_metadata_path"] = path.as_posix()
        data.setdefault("risk", _infer_risk_from_report(reports_dir, data))
        rows.append(data)
    return sorted(rows, key=lambda row: row.get("scanned_at") or "", reverse=True)


def _write_index(site_dir: Path, reports: list[dict]) -> None:
    items = _index_groups(reports[:200])
    body = (
        "<h1>Personal PyPI Supply Chain Scan</h1>"
        "<p class='index-note'>Recent scans are grouped by scan date and ordered by scan publish time.</p>"
        "<p>"
        + html.escape(_disclaimer(reports))
        + "</p><div class='scan-groups'>"
        + items
        + "</div>"
    )
    (site_dir / "index.html").write_text(_html_page("Personal PyPI Supply Chain Scan", body), encoding="utf-8")


def _index_groups(reports: list[dict]) -> str:
    groups: list[tuple[str, list[dict]]] = []
    for report in reports:
        scanned_at = str(report.get("scanned_at") or "unknown")
        scan_date = scanned_at.split("T", 1)[0] if scanned_at != "unknown" else "unknown"
        if not groups or groups[-1][0] != scan_date:
            groups.append((scan_date, []))
        groups[-1][1].append(report)

    sections = []
    for scan_date, rows in groups:
        row_html = "\n".join(_index_row(report) for report in rows)
        sections.append(
            "<section class='scan-day'>"
            f"<div class='scan-day-date'><time>{html.escape(scan_date)}</time><span>{len(rows)} scans</span></div>"
            "<div class='scan-day-table'>"
            "<table>"
            "<thead><tr><th>Scan Time</th><th>Risk</th><th>Package</th><th>Package Published</th><th>Report</th></tr></thead>"
            f"<tbody>{row_html}</tbody>"
            "</table>"
            "</div>"
            "</section>"
        )
    return "\n".join(sections)


def _index_row(report: dict) -> str:
    ko_href = f"packages/{report['package_slug']}/{report['version_slug']}/ko/"
    en_href = f"packages/{report['package_slug']}/{report['version_slug']}/en/"
    risk = str(report.get("risk") or "unknown").lower()
    scanned_at = str(report.get("scanned_at") or "unknown")
    published_at = str(report.get("published_at") or "unknown")
    return (
        "<tr>"
        f"<td><time>{html.escape(_time_part(scanned_at))}</time></td>"
        f"<td><span class='risk risk-{html.escape(risk)}'>{html.escape(risk.upper())}</span></td>"
        f"<td><strong>{html.escape(report['package'])}</strong> <span class='version'>{html.escape(report['version'])}</span></td>"
        f"<td><time>{html.escape(published_at)}</time></td>"
        f"<td><a href='{ko_href}'>ko</a> <a href='{en_href}'>en</a></td>"
        "</tr>"
    )


def _time_part(value: str) -> str:
    if "T" not in value:
        return value
    return value.split("T", 1)[1].split(".", 1)[0]


def _write_report_pages(site_dir: Path, reports_dir: Path, report: dict) -> None:
    for lang in ("ko", "en"):
        source = reports_dir / "packages" / report["package_slug"] / report["version_slug"] / f"{lang}.md"
        if not source.exists():
            continue
        out_dir = site_dir / "packages" / report["package_slug"] / report["version_slug"] / lang
        out_dir.mkdir(parents=True, exist_ok=True)
        markdown = source.read_text(encoding="utf-8")
        body = f"<nav><a href='../../../../'>Index</a></nav>{_markdownish(markdown)}"
        (out_dir / "index.html").write_text(_html_page(report["title"], body), encoding="utf-8")

    package_dir = site_dir / "packages" / report["package_slug"]
    _write_redirect(package_dir / "latest" / "ko" / "index.html", f"../../{report['version_slug']}/ko/")
    _write_redirect(package_dir / "latest" / "en" / "index.html", f"../../{report['version_slug']}/en/")
    versions_dir = package_dir / "versions"
    versions_dir.mkdir(parents=True, exist_ok=True)


def _write_redirect(path: Path, href: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"<!doctype html><meta charset='utf-8'><meta http-equiv='refresh' content='0; url={html.escape(href)}'>"
        f"<a href='{html.escape(href)}'>Redirect</a>",
        encoding="utf-8",
    )


def _copy_prompt_docs(site_dir: Path) -> None:
    source = Path("docs/prompts")
    if not source.exists():
        return
    target = site_dir / "docs" / "prompts"
    target.mkdir(parents=True, exist_ok=True)
    for path in source.glob("*.md"):
        shutil.copyfile(path, target / path.name)


def _markdownish(markdown: str) -> str:
    lines: list[str] = []
    in_list = False
    for raw in markdown.splitlines():
        line = raw.rstrip()
        if line.startswith("# "):
            lines.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            lines.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            lines.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("- "):
            if not in_list:
                lines.append("<ul>")
                in_list = True
            lines.append(f"<li>{_inline(line[2:])}</li>")
        else:
            if in_list:
                lines.append("</ul>")
                in_list = False
            if line:
                lines.append(f"<p>{_inline(line)}</p>")
            else:
                lines.append("")
    if in_list:
        lines.append("</ul>")
    return "\n".join(lines)


def _inline(text: str) -> str:
    escaped = html.escape(text)
    return escaped.replace("`", "")


def _html_page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem auto; max-width: 960px; line-height: 1.55; padding: 0 1rem; color: #1f2933; }}
    a {{ color: #1f5fbf; }}
    code {{ background: #f4f4f4; padding: 0.1rem 0.25rem; }}
    h1, h2, h3 {{ line-height: 1.2; }}
    li {{ margin: 0.35rem 0; }}
    nav {{ margin-bottom: 1rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #e5e9ef; padding: 0.55rem 0.65rem; text-align: left; vertical-align: top; }}
    th {{ color: #52616f; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; }}
    .scan-groups {{ margin-top: 1.2rem; }}
    .scan-day {{ border-top: 1px solid #d8dee4; display: grid; gap: 1rem; grid-template-columns: 10rem minmax(0, 1fr); padding: 1.1rem 0; }}
    .scan-day-date {{ color: #1f2933; font-weight: 700; }}
    .scan-day-date span {{ color: #52616f; display: block; font-size: 0.9rem; font-weight: 500; margin-top: 0.2rem; }}
    .scan-day-table {{ overflow-x: auto; }}
    .risk {{ display: inline-block; min-width: 4.8rem; text-align: center; border-radius: 999px; padding: 0.15rem 0.45rem; font-size: 0.78rem; font-weight: 700; }}
    .risk-info, .risk-low {{ background: #dcfce7; color: #166534; }}
    .risk-medium, .risk-unknown {{ background: #fef3c7; color: #92400e; }}
    .risk-high, .risk-critical {{ background: #fee2e2; color: #991b1b; }}
    .index-note {{ color: #52616f; margin-top: -0.35rem; }}
    .version {{ color: #52616f; margin-left: 0.2rem; white-space: nowrap; }}
    @media (max-width: 720px) {{
      .scan-day {{ grid-template-columns: 1fr; }}
      th, td {{ padding: 0.5rem; }}
    }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""


def _disclaimer(reports: list[dict]) -> str:
    if reports:
        return reports[0].get("disclaimer") or ""
    return "This is a personal automated PyPI supply-chain scan and not an official advisory."


def _infer_risk_from_report(reports_dir: Path, report: dict) -> str:
    source = reports_dir / "packages" / report["package_slug"] / report["version_slug"] / "en.md"
    if not source.exists():
        source = reports_dir / "packages" / report["package_slug"] / report["version_slug"] / "ko.md"
    if not source.exists():
        return "unknown"
    lowered = source.read_text(encoding="utf-8").lower()
    for pattern in (
        r"overall\s+risk\s*[:：]\s*[*_` ]*(critical|high|medium|low|info)",
        r"전체\s*위험도\s*[:：]\s*[*_` ]*(critical|high|medium|low|info)",
        r"위험도\s*[:：]\s*[*_` ]*(critical|high|medium|low|info)",
    ):
        match = re.search(pattern, lowered)
        if match:
            return match.group(1)
    for risk in ("critical", "high", "medium", "low", "info"):
        if risk in lowered:
            return risk
    return "unknown"


def _branch_exists(branch: str) -> bool:
    result = subprocess.run(["git", "rev-parse", "--verify", branch], capture_output=True, text=True)
    return result.returncode == 0


def _clear_directory(path: Path) -> None:
    for item in path.iterdir():
        if item.name == ".git":
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()


def _has_changes(cwd: Path) -> bool:
    result = subprocess.run(["git", "status", "--short"], cwd=cwd, capture_output=True, text=True, check=True)
    return bool(result.stdout.strip())


def _run(args: list[str], cwd: Path | None = None) -> None:
    subprocess.run(args, cwd=cwd, check=True)

from __future__ import annotations

from pathlib import Path
import html
import json
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
    with tempfile.TemporaryDirectory(prefix="pypi-codex-pages-") as tmp:
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
        rows.append(data)
    return sorted(rows, key=lambda row: row.get("scanned_at") or "", reverse=True)


def _write_index(site_dir: Path, reports: list[dict]) -> None:
    items = []
    for report in reports[:200]:
        ko_href = f"packages/{report['package_slug']}/{report['version_slug']}/ko/"
        en_href = f"packages/{report['package_slug']}/{report['version_slug']}/en/"
        items.append(
            f"<li><strong>{html.escape(report['package'])} {html.escape(report['version'])}</strong> "
            f"<a href='{ko_href}'>ko</a> <a href='{en_href}'>en</a><br>"
            f"<small>published {html.escape(str(report.get('published_at') or 'unknown'))}; "
            f"scanned {html.escape(report['scanned_at'])}</small></li>"
        )
    body = "<h1>Personal PyPI Supply Chain Scan</h1><p>" + html.escape(_disclaimer(reports)) + "</p><ul>" + "\n".join(items) + "</ul>"
    (site_dir / "index.html").write_text(_html_page("Personal PyPI Supply Chain Scan", body), encoding="utf-8")


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
    _write_redirect(package_dir / "latest" / "ko" / "index.html", f"../{report['version_slug']}/ko/")
    _write_redirect(package_dir / "latest" / "en" / "index.html", f"../{report['version_slug']}/en/")
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
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem auto; max-width: 960px; line-height: 1.55; padding: 0 1rem; }}
    code {{ background: #f4f4f4; padding: 0.1rem 0.25rem; }}
    h1, h2, h3 {{ line-height: 1.2; }}
    li {{ margin: 0.35rem 0; }}
    nav {{ margin-bottom: 1rem; }}
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

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse
import re

import httpx
import reader

from .state import PackageVersion


@dataclass(frozen=True)
class PypiUpdate:
    package: PackageVersion
    title: str | None
    link: str | None
    published_at: datetime | None


@dataclass(frozen=True)
class PypiRelease:
    package: PackageVersion
    published: datetime | None
    project_url: str
    download_url: str
    filename: str
    digests: dict[str, str]


def latest_updates(rss_url: str, limit: int) -> list[PackageVersion]:
    return [update.package for update in latest_update_entries(rss_url, limit)]


def latest_update_entries(rss_url: str, limit: int) -> list[PypiUpdate]:
    feed = reader.make_reader(":memory:")
    feed.add_feed(rss_url)
    feed.update_feeds()
    updates: list[PypiUpdate] = []
    seen: set[PackageVersion] = set()
    for entry in feed.get_entries(limit=limit * 3):
        package = _package_from_entry(entry)
        if package and package not in seen:
            seen.add(package)
            updates.append(
                PypiUpdate(
                    package=package,
                    title=getattr(entry, "title", None),
                    link=getattr(entry, "link", None),
                    published_at=getattr(entry, "published", None) or getattr(entry, "updated", None),
                )
            )
        if len(updates) >= limit:
            break
    feed.close()
    return updates


def resolve_release(package: PackageVersion) -> PypiRelease:
    url = f"https://pypi.org/pypi/{package.name}/{package.version}/json"
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
    data = response.json()
    urls = data.get("urls") or []
    if not urls:
        raise RuntimeError(f"No files found for {package.name} {package.version}")
    selected = _select_distribution(urls)
    return PypiRelease(
        package=package,
        published=_parse_upload_time(selected.get("upload_time_iso_8601")),
        project_url=data["info"].get("project_url") or f"https://pypi.org/project/{package.name}/{package.version}/",
        download_url=selected["url"],
        filename=selected["filename"],
        digests=selected.get("digests") or {},
    )


def _package_from_entry(entry: object) -> PackageVersion | None:
    title = getattr(entry, "title", "") or ""
    link = getattr(entry, "link", "") or ""
    from_title = _package_from_title(title)
    if from_title:
        return from_title
    return _package_from_link(link)


def _package_from_title(title: str) -> PackageVersion | None:
    match = re.match(r"^(.+?)\s+([^\s]+)$", title.strip())
    if not match:
        return None
    return PackageVersion(name=match.group(1), version=match.group(2))


def _package_from_link(link: str) -> PackageVersion | None:
    path = urlparse(link).path.strip("/")
    parts = path.split("/")
    if len(parts) >= 3 and parts[0] == "project":
        return PackageVersion(name=parts[1], version=parts[2])
    return None


def _select_distribution(files: list[dict]) -> dict:
    wheels = [item for item in files if item.get("packagetype") == "bdist_wheel"]
    sdists = [item for item in files if item.get("packagetype") == "sdist"]
    candidates = sdists or wheels or files
    return sorted(candidates, key=lambda item: item.get("upload_time_iso_8601") or "", reverse=True)[0]


def _parse_upload_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

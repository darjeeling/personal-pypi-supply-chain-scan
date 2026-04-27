from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import subprocess

from .config import AppConfig


def cleanup_scan_artifacts(config: AppConfig) -> list[str]:
    if not config.cleanup.enabled:
        return []

    messages: list[str] = []
    removed = _cleanup_work_dir(config.paths.work_dir, config.cleanup.work_dir_retention_hours)
    if removed:
        messages.append(f"cleanup removed {removed} work directories from {config.paths.work_dir}")

    if config.cleanup.docker_prune:
        _run_docker_prune()
        messages.append("cleanup pruned dangling Docker containers, networks, images, and build cache")

    return messages


def _cleanup_work_dir(work_dir: Path, retention_hours: int) -> int:
    if not work_dir.exists():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max(retention_hours, 0))
    removed = 0
    for child in work_dir.iterdir():
        if not child.is_dir():
            continue
        modified = datetime.fromtimestamp(child.stat().st_mtime, timezone.utc)
        if modified > cutoff:
            continue
        shutil.rmtree(child)
        removed += 1
    return removed


def _run_docker_prune() -> None:
    commands = (
        ["docker", "container", "prune", "-f"],
        ["docker", "network", "prune", "-f"],
        ["docker", "image", "prune", "-f"],
        ["docker", "builder", "prune", "-f"],
    )
    for command in commands:
        subprocess.run(command, check=True, capture_output=True, text=True)

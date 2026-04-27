from __future__ import annotations

from datetime import datetime, time

from .config import ScheduleConfig


def is_allowed(now: datetime, windows: list[str]) -> bool:
    if not windows:
        return True
    current = now.time().replace(second=0, microsecond=0)
    return any(_contains(current, window) for window in windows)


def schedule_now(config: ScheduleConfig) -> datetime:
    return datetime.now(config.tzinfo)


def _contains(current: time, window: str) -> bool:
    start_raw, end_raw = window.split("-", maxsplit=1)
    start = time.fromisoformat(start_raw)
    end = time.fromisoformat(end_raw)
    if start <= end:
        return start <= current <= end
    return current >= start or current <= end


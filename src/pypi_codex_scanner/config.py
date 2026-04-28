from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import tomllib
from zoneinfo import ZoneInfo


DEFAULT_RSS_URL = "https://pypi.org/rss/updates.xml"
DEFAULT_CONFIG_TEXT = """[schedule]
timezone = "Asia/Seoul"
crawl_windows = ["09:00-18:00"]
scan_windows = ["09:00-18:00"]

[run]
sleep_seconds = 1800
release_retry_attempts = 3
release_retry_sleep_seconds = 10

[limits]
max_updates = 10
max_scans_per_run = 3
max_llm_calls_per_run = 3
max_archive_bytes = 52428800
max_extracted_bytes = 104857600
max_files_for_model = 30
max_chars_for_model = 60000
container_timeout_seconds = 180

[paths]
state_db = "data/state.sqlite3"
work_dir = "data/work"
reports_dir = "reports"
site_dir = "site"

[publish]
enabled = true
every_scans = 1
branch = "gh-pages"
push = true

[openai]
model = "gpt-5.5"
codex_auth_path = "~/.codex/auth.json"
base_url = "https://chatgpt.com/backend-api/codex"
request_timeout_seconds = 120

[usage_gate]
enabled = true
min_primary_remaining_percent = 20
min_secondary_remaining_percent = 10
secondary_daily_budget_divisor = 14
allow_if_unknown = true
backend_url = "https://chatgpt.com/backend-api/wham/usage"

[docker]
image = "python:3.12-slim"
network = "bridge"
memory = "512m"
cpus = "1.0"

[cleanup]
enabled = true
after_scans = 1
work_dir_retention_hours = 24
docker_prune = false
"""


@dataclass(frozen=True)
class ScheduleConfig:
    timezone: str = "Asia/Seoul"
    crawl_windows: list[str] = field(default_factory=list)
    scan_windows: list[str] = field(default_factory=list)

    @property
    def tzinfo(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)


@dataclass(frozen=True)
class RunConfig:
    sleep_seconds: int = 1800
    release_retry_attempts: int = 3
    release_retry_sleep_seconds: int = 10


@dataclass(frozen=True)
class LimitsConfig:
    max_updates: int = 10
    max_scans_per_run: int = 3
    max_llm_calls_per_run: int = 3
    max_archive_bytes: int = 50 * 1024 * 1024
    max_extracted_bytes: int = 100 * 1024 * 1024
    max_files_for_model: int = 30
    max_chars_for_model: int = 60_000
    container_timeout_seconds: int = 180


@dataclass(frozen=True)
class PathsConfig:
    state_db: Path = Path("data/state.sqlite3")
    work_dir: Path = Path("data/work")
    reports_dir: Path = Path("reports")
    site_dir: Path = Path("site")


@dataclass(frozen=True)
class PublishConfig:
    enabled: bool = True
    every_scans: int = 1
    branch: str = "gh-pages"
    push: bool = True


@dataclass(frozen=True)
class OpenAIConfig:
    model: str = "gpt-5.5"
    codex_auth_path: Path = Path("~/.codex/auth.json")
    base_url: str = "https://chatgpt.com/backend-api/codex"
    request_timeout_seconds: int = 120


@dataclass(frozen=True)
class DockerConfig:
    image: str = "python:3.12-slim"
    network: str = "bridge"
    memory: str = "512m"
    cpus: str = "1.0"


@dataclass(frozen=True)
class CleanupConfig:
    enabled: bool = True
    after_scans: int = 1
    work_dir_retention_hours: int = 24
    docker_prune: bool = False


@dataclass(frozen=True)
class UsageGateConfig:
    enabled: bool = True
    min_primary_remaining_percent: int = 20
    min_secondary_remaining_percent: int = 10
    secondary_daily_budget_divisor: int = 14
    allow_if_unknown: bool = True
    backend_url: str = "https://chatgpt.com/backend-api/wham/usage"


@dataclass(frozen=True)
class AppConfig:
    rss_url: str = DEFAULT_RSS_URL
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    run: RunConfig = field(default_factory=RunConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    publish: PublishConfig = field(default_factory=PublishConfig)
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)
    docker: DockerConfig = field(default_factory=DockerConfig)
    cleanup: CleanupConfig = field(default_factory=CleanupConfig)
    usage_gate: UsageGateConfig = field(default_factory=UsageGateConfig)


def load_config(path: Path) -> AppConfig:
    data = tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    root = path.parent

    paths_data = data.get("paths", {})
    openai_data = data.get("openai", {})

    return AppConfig(
        rss_url=data.get("rss_url", DEFAULT_RSS_URL),
        schedule=ScheduleConfig(**data.get("schedule", {})),
        run=RunConfig(**data.get("run", {})),
        limits=LimitsConfig(**data.get("limits", {})),
        paths=PathsConfig(
            state_db=_resolve_path(root, paths_data.get("state_db", "data/state.sqlite3")),
            work_dir=_resolve_path(root, paths_data.get("work_dir", "data/work")),
            reports_dir=_resolve_path(root, paths_data.get("reports_dir", "reports")),
            site_dir=_resolve_path(root, paths_data.get("site_dir", "site")),
        ),
        publish=PublishConfig(**data.get("publish", {})),
        openai=OpenAIConfig(
            model=openai_data.get("model", "gpt-5.5"),
            codex_auth_path=Path(openai_data.get("codex_auth_path", "~/.codex/auth.json")).expanduser(),
            base_url=openai_data.get("base_url", "https://chatgpt.com/backend-api/codex"),
            request_timeout_seconds=openai_data.get("request_timeout_seconds", 120),
        ),
        docker=DockerConfig(**data.get("docker", {})),
        cleanup=CleanupConfig(**data.get("cleanup", {})),
        usage_gate=UsageGateConfig(**data.get("usage_gate", {})),
    )


def write_default_config(path: Path) -> None:
    path.write_text(DEFAULT_CONFIG_TEXT, encoding="utf-8")


def _resolve_path(root: Path, value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return root / path

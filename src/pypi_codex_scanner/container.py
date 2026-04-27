from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import shutil
import subprocess
import textwrap
import uuid

from .config import AppConfig
from .pypi import PypiRelease
from .prescan import scan_extracted_package


@dataclass(frozen=True)
class ExtractedPackage:
    job_dir: Path
    archive_path: Path
    extract_dir: Path
    manifest_path: Path
    prescan_path: Path
    corpus_path: Path
    manifest: dict
    prescan: dict
    corpus: str


WORKER_SCRIPT = r"""
from __future__ import annotations

from pathlib import Path
from urllib.request import Request, urlopen
import json
import os
import shutil
import tarfile
import zipfile


def _safe_extract_member(name: str, target: Path) -> None:
    destination = (target / name).resolve()
    target_resolved = target.resolve()
    if target_resolved not in destination.parents and destination != target_resolved:
        raise RuntimeError(f"unsafe archive path: {name}")


def _score_path(path: str) -> tuple[int, str]:
    lower = path.lower()
    priority_names = {
        "setup.py": 0,
        "pyproject.toml": 1,
        "setup.cfg": 2,
        "setup_requires.txt": 3,
        "requires.txt": 4,
        "entry_points.txt": 5,
        "metadata": 6,
    }
    base = lower.rsplit("/", 1)[-1]
    if base in priority_names:
        return (priority_names[base], lower)
    if lower.endswith((".py", ".pyw", ".pth", ".sh", ".ps1", ".bat", ".cmd")):
        return (20, lower)
    if lower.endswith((".toml", ".cfg", ".ini", ".txt", ".md", ".rst", ".json", ".yaml", ".yml")):
        return (30, lower)
    return (100, lower)


def _read_text(path: Path) -> str | None:
    if path.stat().st_size > 512 * 1024:
        return None
    data = path.read_bytes()
    if b"\x00" in data[:4096]:
        return None
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return None


download_url = os.environ["PACKAGE_URL"]
filename = os.environ["PACKAGE_FILENAME"]
max_archive_bytes = int(os.environ["MAX_ARCHIVE_BYTES"])
max_extracted_bytes = int(os.environ["MAX_EXTRACTED_BYTES"])
max_files = int(os.environ["MAX_FILES_FOR_MODEL"])
max_chars = int(os.environ["MAX_CHARS_FOR_MODEL"])

work = Path("/work")
archive = work / "archive" / filename
extract_dir = work / "extracted"
archive.parent.mkdir(parents=True, exist_ok=True)
extract_dir.mkdir(parents=True, exist_ok=True)

request = Request(download_url, headers={"User-Agent": "pypi-llm-scanner/0.1"})
with urlopen(request, timeout=60) as response, archive.open("wb") as out:
    total = 0
    while True:
        chunk = response.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_archive_bytes:
            raise RuntimeError(f"archive exceeds max_archive_bytes: {total}")
        out.write(chunk)

if zipfile.is_zipfile(archive):
    with zipfile.ZipFile(archive) as zf:
        planned_size = 0
        for info in zf.infolist():
            _safe_extract_member(info.filename, extract_dir)
            planned_size += info.file_size
            if planned_size > max_extracted_bytes:
                raise RuntimeError(f"archive contents exceed max_extracted_bytes: {planned_size}")
        zf.extractall(extract_dir)
elif tarfile.is_tarfile(archive):
    with tarfile.open(archive) as tf:
        planned_size = 0
        for member in tf.getmembers():
            _safe_extract_member(member.name, extract_dir)
            if member.isfile():
                planned_size += member.size
            elif not member.isdir():
                continue
            if planned_size > max_extracted_bytes:
                raise RuntimeError(f"archive contents exceed max_extracted_bytes: {planned_size}")
        for member in tf.getmembers():
            _safe_extract_member(member.name, extract_dir)
            destination = extract_dir / member.name
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = tf.extractfile(member)
                if source is None:
                    continue
                with source, destination.open("wb") as output:
                    shutil.copyfileobj(source, output)
else:
    raise RuntimeError("unsupported archive format")

total_extracted = 0
files = []
for path in sorted(extract_dir.rglob("*")):
    if not path.is_file():
        continue
    rel = path.relative_to(extract_dir).as_posix()
    size = path.stat().st_size
    total_extracted += size
    if total_extracted > max_extracted_bytes:
        raise RuntimeError(f"extracted files exceed max_extracted_bytes: {total_extracted}")
    files.append({"path": rel, "size": size})

selected = []
corpus_parts = []
for item in sorted(files, key=lambda f: _score_path(f["path"])):
    if len(selected) >= max_files or sum(len(p) for p in corpus_parts) >= max_chars:
        break
    path = extract_dir / item["path"]
    text = _read_text(path)
    if text is None:
        continue
    remaining = max_chars - sum(len(p) for p in corpus_parts)
    if remaining <= 0:
        break
    clipped = text[:remaining]
    selected.append({**item, "included_chars": len(clipped)})
    corpus_parts.append(f"\n\n===== FILE: {item['path']} ({item['size']} bytes) =====\n{clipped}")

manifest = {
    "archive": str(archive),
    "extract_dir": str(extract_dir),
    "total_files": len(files),
    "total_extracted_bytes": total_extracted,
    "files": files,
    "selected_files": selected,
}
(work / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
(work / "corpus.txt").write_text("".join(corpus_parts), encoding="utf-8")
"""


def extract_in_container(config: AppConfig, release: PypiRelease) -> ExtractedPackage:
    if shutil.which("docker") is None:
        raise RuntimeError("docker command not found")

    job_dir = config.paths.work_dir / f"{release.package.name}-{release.package.version}-{uuid.uuid4().hex[:8]}"
    job_dir.mkdir(parents=True, exist_ok=True)
    script_path = job_dir / "worker.py"
    script_path.write_text(_worker_script(), encoding="utf-8")

    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        config.docker.network,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        config.docker.memory,
        "--cpus",
        config.docker.cpus,
        "-e",
        f"PACKAGE_URL={release.download_url}",
        "-e",
        f"PACKAGE_FILENAME={release.filename}",
        "-e",
        f"MAX_ARCHIVE_BYTES={config.limits.max_archive_bytes}",
        "-e",
        f"MAX_EXTRACTED_BYTES={config.limits.max_extracted_bytes}",
        "-e",
        f"MAX_FILES_FOR_MODEL={config.limits.max_files_for_model}",
        "-e",
        f"MAX_CHARS_FOR_MODEL={config.limits.max_chars_for_model}",
        "-v",
        f"{job_dir.resolve()}:/work",
        config.docker.image,
        "python",
        "/work/worker.py",
    ]
    try:
        subprocess.run(
            command,
            check=True,
            timeout=config.limits.container_timeout_seconds,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        if "Cannot connect to the Docker daemon" in detail:
            raise RuntimeError("Docker CLI is installed, but the Docker daemon is not running") from exc
        raise RuntimeError(f"Docker extraction failed: {detail}") from exc

    manifest_path = job_dir / "manifest.json"
    prescan_path = job_dir / "prescan.json"
    corpus_path = job_dir / "corpus.txt"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    prescan = scan_extracted_package(
        job_dir / "extracted",
        manifest,
        max_files=config.limits.max_files_for_model,
        max_chars=config.limits.max_chars_for_model,
    )
    prescan_path.write_text(json.dumps(prescan, indent=2, sort_keys=True), encoding="utf-8")
    corpus = prescan.get("focused_corpus") or corpus_path.read_text(encoding="utf-8")
    return ExtractedPackage(
        job_dir=job_dir,
        archive_path=job_dir / "archive" / release.filename,
        extract_dir=job_dir / "extracted",
        manifest_path=manifest_path,
        prescan_path=prescan_path,
        corpus_path=corpus_path,
        manifest=manifest,
        prescan=prescan,
        corpus=corpus,
    )


def _worker_script() -> str:
    return textwrap.dedent(WORKER_SCRIPT)

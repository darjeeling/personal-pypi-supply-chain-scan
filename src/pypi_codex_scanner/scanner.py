from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .container import ExtractedPackage
from .openai_client import OpenAIResponsesClient
from .pypi import PypiRelease


SECURITY_INSTRUCTIONS = """You are a Python package supply-chain security reviewer.
Review the extracted package contents without executing them.
Return a concise Markdown report in Korean.

Focus on:
- install-time execution risk in setup.py, pyproject build hooks, setup.cfg, .pth files, and entry points
- suspicious network, subprocess, shell, filesystem, credential, or environment-variable access
- token/key exfiltration patterns
- obfuscation, dynamic code loading, eval/exec/compile, marshal, pickle, base64/zlib abuse
- dependency confusion or typosquatting indicators visible from metadata
- native binaries, compiled extensions, vendored executables, and hidden payloads
- maintainer-intent signals such as post-install behavior, telemetry, or unexpected persistence

Use this severity scale: critical, high, medium, low, info.
If evidence is incomplete, say so explicitly.
Do not claim that code executed.
"""


@dataclass(frozen=True)
class ScanResult:
    markdown: str


def scan_release(client: OpenAIResponsesClient, release: PypiRelease, extracted: ExtractedPackage) -> ScanResult:
    prompt = f"""# Package

- name: {release.package.name}
- version: {release.package.version}
- published: {release.published.isoformat() if release.published else "unknown"}
- project_url: {release.project_url}
- filename: {release.filename}
- digests: {release.digests}
- scanned_at_utc: {datetime.now(timezone.utc).isoformat()}

# Extraction Manifest

- total_files: {extracted.manifest.get("total_files")}
- total_extracted_bytes: {extracted.manifest.get("total_extracted_bytes")}
- selected_files: {len(extracted.manifest.get("selected_files", []))}

# Required Report Format

## 판정

한 줄 요약과 전체 위험도를 적으세요.

## 주요 발견사항

심각도순으로 bullet list를 작성하세요. 각 항목에는 근거 파일 경로를 포함하세요.

## 설치/빌드 시점 위험

setup.py, pyproject.toml, setup.cfg, .pth, entry_points 관련 위험을 설명하세요.

## 의심 API/패턴

네트워크, subprocess, eval/exec, credential 접근, obfuscation 등을 정리하세요.

## 추가 확인 필요

모델 입력 한계 때문에 확인하지 못한 점이나 바이너리/대용량 파일을 적으세요.

# Extracted Text Corpus

{extracted.corpus}
"""
    return ScanResult(markdown=client.create_markdown_scan(SECURITY_INSTRUCTIONS, prompt))


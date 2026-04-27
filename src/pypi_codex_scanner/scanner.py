from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .container import ExtractedPackage
from .openai_client import OpenAIResponsesClient
from .pypi import PypiRelease


SECURITY_INSTRUCTIONS = """You are a Python package malicious supply-chain reviewer.
Review the extracted package contents without executing them.
Return a concise Markdown report in Korean.

Only report evidence that plausibly indicates a malicious package supply-chain attack.
Do not report ordinary application security risks, normal CLI behavior, normal SDK/API calls,
normal environment-variable usage, or expected file/network access unless they are tied to
malware-like supply-chain behavior.

Use the LiteLLM 2026 compromise as a reference pattern:
- malicious code injected into distribution artifacts, especially code not expected from source layout
- .pth files or sitecustomize/usercustomize hooks that execute on Python startup
- install-time/import-time execution intended to run automatically without explicit user action
- credential harvesting from environment variables, .env files, SSH keys, cloud credentials,
  AI provider keys, ~/.aws/credentials, ~/.kube/config, CI/CD tokens, shell history, wallets, or TLS keys
- staging or bundling stolen data into archives such as tar/zip before exfiltration
- exfiltration to suspicious or package-lookalike C2 domains
- Kubernetes lateral movement, service-account token abuse, privileged pods, host filesystem mounts
- persistence such as systemd units, launch agents, cron jobs, shell profile edits, backdoor polling
- obfuscation or loaders that hide the above behavior, including base64/zlib/marshal/pickle/eval/exec
- release-integrity signals such as suspicious .dist-info contents, unexpected generated files,
  dependency confusion/typosquatting, hidden payloads, or native binaries with no clear purpose

If a package merely contains cloud SDK calls, web servers, entry points, project-file edits,
or user-triggered commands, classify them as not supply-chain findings unless there is evidence
of automatic malicious execution, theft, persistence, exfiltration, or stealth.

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

악성 공급망 징후가 있는지 한 줄로 판정하고 전체 위험도를 적으세요.

## 악성 공급망 징후

악성 공급망 공격으로 볼 수 있는 근거만 심각도순으로 작성하세요.
근거가 없으면 "확인된 악성 공급망 징후 없음"이라고 쓰세요.

## 자동 실행 경로

setup.py, pyproject.toml, setup.cfg, .pth, sitecustomize/usercustomize,
entry_points 중 자동 실행 또는 설치/인터프리터 시작 시 실행 근거만 설명하세요.
일반 console_scripts는 사용자가 명령을 실행해야 하므로 악성 자동 실행 근거가 없으면 제외하세요.

## 절취/지속성/측면이동/은닉

credential harvesting, exfiltration, persistence, Kubernetes lateral movement,
obfuscation/loader 증거가 있는지 정리하세요.

## 추가 확인 필요

모델 입력 한계, 바이너리/대용량 파일, 배포 아티팩트와 소스 불일치 가능성 등
악성 공급망 판단에 필요한 미확인 사항만 적으세요.

# Extracted Text Corpus

{extracted.corpus}
"""
    return ScanResult(markdown=client.create_markdown_scan(SECURITY_INSTRUCTIONS, prompt))

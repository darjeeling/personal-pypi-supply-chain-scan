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

Prioritize patterns seen in recent malicious supply-chain compromises such as
LiteLLM/Telnyx on PyPI, Axios on npm, Shai-Hulud, and GitHub Actions token-theft campaigns:

1. Automatic execution
   - Python: .pth, sitecustomize.py, usercustomize.py, setup.py, PEP 517 build hooks,
     import-time side effects, unexpected top-level execution
   - Cross-ecosystem reference: preinstall/postinstall/prepare-style behavior

2. Credential theft
   - Broad discovery of environment variables, .env files, shell history, SSH keys,
     cloud credentials, AI provider keys, ~/.aws/credentials, ~/.kube/config,
     npm/PyPI/GitHub tokens, CI/CD secrets, wallets, TLS keys, database credentials
   - Treat normal reading of one documented app credential as benign unless it is paired
     with broad discovery, stealth, staging, persistence, or exfiltration

3. Exfiltration and staging
   - Archive creation or staging of harvested files using tar/zip/gzip/base64/temp files
   - HTTP upload, webhook use, attacker-controlled GitHub repositories, package-lookalike
     or suspicious C2 domains, raw IP endpoints, paste/drop services

4. Persistence
   - systemd units, launch agents, cron jobs, shell profile edits, startup folders,
     background polling loops, backdoor service names, self-reinstall logic

5. Lateral movement through developer/CI/cloud infrastructure
   - Kubernetes service-account token use, kube-system pods, privileged pods,
     hostPath mounts, Docker socket access, cloud metadata access, CI publish tokens,
     GitHub Actions workflow injection, package registry token reuse

6. Obfuscation and staged loaders
   - base64/zlib/gzip/marshal/pickle/eval/exec/compile, XOR, steganography,
     downloader stubs, platform-specific RAT payload selection, self-deleting droppers

7. Distribution integrity anomalies
   - Files present in the PyPI artifact but unlikely in source, unexpected .dist-info
     contents, sudden dependency insertion, dependency confusion or typosquatting,
     hidden payloads, unexplained native binaries, generated files that carry executable
     logic, wheel/sdist behavior mismatch

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

악성 공급망 침해 징후가 있는지 한 줄로 판정하고 전체 위험도를 적으세요.

## 악성 공급망 징후

악성 공급망 공격으로 볼 수 있는 근거만 심각도순으로 작성하세요.
근거가 없으면 "확인된 악성 공급망 징후 없음"이라고 쓰세요.

## 자동 실행 경로

setup.py, pyproject.toml, setup.cfg, .pth, sitecustomize/usercustomize,
import-time side effect, entry_points 중 자동 실행 또는 설치/인터프리터 시작 시 실행 근거만 설명하세요.
일반 console_scripts는 사용자가 명령을 실행해야 하므로 악성 자동 실행 근거가 없으면 제외하세요.

## 절취/전송/지속성/측면이동/은닉

credential harvesting, archive staging, exfiltration, persistence,
Kubernetes/CI/cloud lateral movement, obfuscation/loader 증거가 있는지 정리하세요.

## 배포 무결성 이상

PyPI artifact 내부의 예상 밖 파일, 갑작스러운 dependency 삽입, typosquatting,
숨김 payload, 목적 불명 native binary, wheel/sdist 불일치 가능성을 정리하세요.

## 추가 확인 필요

모델 입력 한계, 바이너리/대용량 파일, 배포 아티팩트와 소스 불일치 가능성 등
악성 공급망 판단에 필요한 미확인 사항만 적으세요.

# Extracted Text Corpus

{extracted.corpus}
"""
    return ScanResult(markdown=client.create_markdown_scan(SECURITY_INSTRUCTIONS, prompt))

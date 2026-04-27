# pypi-codex-scanner

PyPI RSS updates feed에서 최신 publish 패키지를 가져오고, 호스트에는 패키지를 설치하지 않은 채 Docker 컨테이너 안에서 배포 파일을 다운로드/압축 해제한 뒤 GPT-5.5로 악성 공급망 징후를 정적 검사합니다.

## 동작 방식

1. `reader` 라이브러리로 `https://pypi.org/rss/updates.xml`을 읽습니다.
2. PyPI JSON API에서 해당 패키지/버전의 sdist 또는 wheel URL을 확인합니다. 설치 스크립트 확인을 우선하기 위해 sdist가 있으면 sdist를 먼저 스캔합니다.
3. Docker 컨테이너에서만 파일을 다운로드하고 압축을 풉니다.
4. 추출된 `setup.py`, `pyproject.toml`, `setup.cfg`, Python 소스, 스크립트, 메타데이터를 텍스트 코퍼스로 수집합니다.
5. `~/.codex/auth.json`의 Codex OAuth access token으로 OpenAI Responses API를 직접 호출해 `gpt-5.5` 보안 검사를 수행합니다.
6. 결과를 Markdown report로 저장하고 SQLite에 처리 이력을 남깁니다.

패키지 설치, build hook 실행, `setup.py` 실행은 하지 않습니다.

## 스캔 기준

스캐너는 일반적인 애플리케이션 보안 리스크가 아니라 악성 공급망 공격 징후만 보고하도록 프롬프트되어 있습니다.

주요 기준은 LiteLLM 2026 PyPI compromise 같은 사례입니다:

- `.pth`, `sitecustomize`, `usercustomize`, 설치/인터프리터 시작 시 자동 실행
- 배포 아티팩트에 삽입된 예상 밖 코드
- 환경변수, `.env`, SSH 키, cloud credential, AI provider key, `~/.aws/credentials`, `~/.kube/config`, CI/CD token 등 광범위한 credential harvesting
- 수집 데이터 archive staging 후 C2 exfiltration
- Kubernetes service account abuse, privileged pod, host mount 등 lateral movement
- systemd, launch agent, cron, shell profile 수정 등 persistence
- base64/zlib/marshal/pickle/eval/exec 등으로 숨긴 loader
- dependency confusion, typosquatting, 숨김 payload, 목적 불명의 native binary

일반적인 CLI entry point, 정상 SDK/API 호출, 사용자가 명령을 실행해야 동작하는 웹 서버, 정상적인 환경변수 사용은 위 악성 공급망 증거와 연결되지 않으면 finding으로 올리지 않습니다.

## 사용

```bash
uv run pypi-codex-scanner init-config
uv run pypi-codex-scanner run --config scanner.toml
```

Docker가 필요합니다.

## 설정

`scanner.toml`:

```toml
[schedule]
timezone = "Asia/Seoul"
crawl_windows = ["09:00-18:00"]
scan_windows = ["09:00-18:00"]

[limits]
max_updates = 10
max_archive_bytes = 52428800
max_extracted_bytes = 104857600
max_files_for_model = 80
max_chars_for_model = 180000

[paths]
state_db = "data/state.sqlite3"
work_dir = "data/work"
reports_dir = "reports"

[openai]
model = "gpt-5.5"
codex_auth_path = "~/.codex/auth.json"
base_url = "https://chatgpt.com/backend-api/codex"
```

빈 window 목록은 항상 실행을 의미합니다.

# pypi-codex-scanner

PyPI RSS updates feed에서 최신 publish 패키지를 가져오고, 호스트에는 패키지를 설치하지 않은 채 Docker 컨테이너 안에서 배포 파일을 다운로드/압축 해제한 뒤 GPT-5.5로 정적 보안 검사를 수행합니다.

## 동작 방식

1. `reader` 라이브러리로 `https://pypi.org/rss/updates.xml`을 읽습니다.
2. PyPI JSON API에서 해당 패키지/버전의 sdist 또는 wheel URL을 확인합니다. 설치 스크립트 확인을 우선하기 위해 sdist가 있으면 sdist를 먼저 스캔합니다.
3. Docker 컨테이너에서만 파일을 다운로드하고 압축을 풉니다.
4. 추출된 `setup.py`, `pyproject.toml`, `setup.cfg`, Python 소스, 스크립트, 메타데이터를 텍스트 코퍼스로 수집합니다.
5. `~/.codex/auth.json`의 Codex OAuth access token으로 OpenAI Responses API를 직접 호출해 `gpt-5.5` 보안 검사를 수행합니다.
6. 결과를 Markdown report로 저장하고 SQLite에 처리 이력을 남깁니다.

패키지 설치, build hook 실행, `setup.py` 실행은 하지 않습니다.

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

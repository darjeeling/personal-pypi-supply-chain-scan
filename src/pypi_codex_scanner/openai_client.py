from __future__ import annotations

from pathlib import Path
import json

import httpx

from .config import OpenAIConfig


class OpenAIResponsesClient:
    def __init__(self, config: OpenAIConfig) -> None:
        self.config = config

    def create_markdown_scan(self, instructions: str, prompt: str) -> str:
        auth = _load_codex_auth(self.config.codex_auth_path)
        payload = {
            "model": self.config.model,
            "store": False,
            "stream": True,
            "instructions": instructions,
            "input": [{"role": "user", "content": prompt}],
        }
        headers = {
            "Authorization": f"Bearer {auth.access_token}",
            "Content-Type": "application/json",
        }
        if auth.account_id:
            headers["chatgpt-account-id"] = auth.account_id
        with httpx.Client(timeout=self.config.request_timeout_seconds) as client:
            with client.stream(
                "POST",
                f"{self.config.base_url.rstrip('/')}/responses",
                headers=headers,
                json=payload,
            ) as response:
                response.raise_for_status()
                return _extract_streaming_output_text(response)


class CodexAuth:
    def __init__(self, access_token: str, account_id: str | None) -> None:
        self.access_token = access_token
        self.account_id = account_id


def _load_codex_auth(path: Path) -> CodexAuth:
    data = json.loads(path.expanduser().read_text(encoding="utf-8"))
    tokens = data.get("tokens", {})
    token = tokens.get("access_token")
    if not token:
        raise RuntimeError(f"No tokens.access_token found in {path}")
    return CodexAuth(access_token=token, account_id=tokens.get("account_id"))


def _extract_streaming_output_text(response: httpx.Response) -> str:
    parts: list[str] = []
    data_lines: list[str] = []
    for line in response.iter_lines():
        if not line:
            _consume_sse_event(data_lines, parts)
            data_lines = []
            continue
        if line.startswith("data:"):
            data_lines.append(line.removeprefix("data:").strip())
    _consume_sse_event(data_lines, parts)
    if not parts:
        raise RuntimeError("Responses API stream returned no output text")
    return "".join(parts)


def _consume_sse_event(data_lines: list[str], parts: list[str]) -> None:
    if not data_lines:
        return
    raw = "\n".join(data_lines)
    if raw == "[DONE]":
        return
    event = json.loads(raw)
    if event.get("type") == "response.output_text.delta" and event.get("delta"):
        parts.append(event["delta"])

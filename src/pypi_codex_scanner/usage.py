from __future__ import annotations

from dataclasses import dataclass

import httpx

from .config import OpenAIConfig, UsageGateConfig
from .openai_client import _load_codex_auth


@dataclass(frozen=True)
class UsageGateDecision:
    allowed: bool
    reason: str
    status: dict


def check_usage_gate(config: UsageGateConfig, openai_config: OpenAIConfig) -> UsageGateDecision:
    if not config.enabled:
        return UsageGateDecision(True, "usage gate disabled", {})
    try:
        status = fetch_codex_usage(config.backend_url, openai_config)
    except Exception as exc:
        return UsageGateDecision(config.allow_if_unknown, f"usage status unavailable: {exc}", {})

    rate_limit = status.get("rate_limit") or {}
    if rate_limit.get("allowed") is False or rate_limit.get("limit_reached") is True:
        return UsageGateDecision(False, "backend reports usage limit reached", status)

    primary_used = _used_percent(rate_limit.get("primary_window"))
    secondary_used = _used_percent(rate_limit.get("secondary_window"))
    max_primary_used = 100 - config.min_primary_remaining_percent
    max_secondary_used = 100 - config.min_secondary_remaining_percent
    if primary_used is not None and primary_used > max_primary_used:
        return UsageGateDecision(False, f"primary usage {primary_used}% exceeds threshold {max_primary_used}%", status)
    if secondary_used is not None and secondary_used > max_secondary_used:
        return UsageGateDecision(False, f"secondary usage {secondary_used}% exceeds threshold {max_secondary_used}%", status)
    return UsageGateDecision(True, "usage below configured thresholds", status)


def fetch_codex_usage(url: str, openai_config: OpenAIConfig) -> dict:
    auth = _load_codex_auth(openai_config.codex_auth_path)
    headers = {
        "Authorization": f"Bearer {auth.access_token}",
        "Content-Type": "application/json",
    }
    if auth.account_id:
        headers["chatgpt-account-id"] = auth.account_id
    with httpx.Client(timeout=20) as client:
        response = client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()


def _used_percent(window: dict | None) -> int | None:
    if not isinstance(window, dict):
        return None
    value = window.get("used_percent")
    return int(value) if isinstance(value, int | float) else None

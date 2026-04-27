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
    max_primary_used = 100 - config.min_primary_remaining_percent
    if primary_used is not None and primary_used > max_primary_used:
        return UsageGateDecision(False, f"primary usage {primary_used}% exceeds threshold {max_primary_used}%", status)

    secondary_decision = _secondary_budget_decision(rate_limit.get("secondary_window"), config)
    if secondary_decision is not None:
        allowed, reason = secondary_decision
        if not allowed:
            return UsageGateDecision(False, reason, status)
        return UsageGateDecision(True, reason, status)
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


def _secondary_budget_decision(window: dict | None, config: UsageGateConfig) -> tuple[bool, str] | None:
    if not isinstance(window, dict):
        return None
    used_percent = _used_percent(window)
    if used_percent is None:
        return None

    divisor = max(config.secondary_daily_budget_divisor, 1)
    daily_budget = 100 / divisor
    elapsed_days = _elapsed_days(window)
    budget_percent = min(100 - config.min_secondary_remaining_percent, max(daily_budget, elapsed_days * daily_budget))
    budget_display = round(budget_percent, 2)
    reset_at = window.get("reset_at")
    reset_note = f", reset_at={reset_at}" if reset_at else ""
    if used_percent > budget_percent:
        return (
            False,
            f"secondary usage {used_percent}% exceeds daily budget {budget_display}% after {elapsed_days:.2f} elapsed days{reset_note}",
        )
    return (
        True,
        f"usage below thresholds; secondary usage {used_percent}% within daily budget {budget_display}% after {elapsed_days:.2f} elapsed days{reset_note}",
    )


def _elapsed_days(window: dict) -> float:
    limit_seconds = _number(window.get("limit_window_seconds"))
    reset_after_seconds = _number(window.get("reset_after_seconds"))
    if limit_seconds is None or reset_after_seconds is None or limit_seconds <= 0:
        return 1.0
    elapsed_seconds = max(0.0, limit_seconds - max(0.0, reset_after_seconds))
    return elapsed_seconds / 86_400


def _number(value: object) -> float | None:
    if isinstance(value, int | float):
        return float(value)
    return None

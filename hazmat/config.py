"""Provider configuration loaded from .env.

Every model Hazmat talks to is reached through an OpenAI-compatible endpoint,
so a provider is just (base_url, api_key, model) plus one safety flag:
whether it is allowed to see raw sample content.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the repo root (or the current directory) without overriding
# variables already set in the shell.
_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_ROOT / ".env", override=False)
load_dotenv(override=False)


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    api_key: str
    model: str
    # Sensitive, unsanitized content may only go to
    # open-weights providers. Hosted Meta API gets sanitized summaries only.
    raw_ok: bool

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.model)


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def providers() -> dict[str, Provider]:
    return {
        "meta": Provider(
            name="meta",
            base_url=_env("META_BASE_URL", "https://api.meta.ai/v1"),
            api_key=_env("MODEL_API_KEY"),
            model=_env("META_MODEL", "muse-spark-1.3"),
            raw_ok=False,
        ),
        "baseten": Provider(
            name="baseten",
            base_url=_env("BASETEN_BASE_URL", "https://inference.baseten.co/v1"),
            api_key=_env("BASETEN_API_KEY"),
            model=_env("BASETEN_MODEL", "meta-models/muse-spark-open-1026"),
            raw_ok=True,
        ),
        "local": Provider(
            name="local",
            base_url=_env("LOCAL_BASE_URL", "http://localhost:11434/v1"),
            api_key=_env("LOCAL_API_KEY", "local"),
            model=_env("LOCAL_MODEL"),
            raw_ok=True,
        ),
        "fireworks": Provider(
            name="fireworks",
            base_url=_env("FIREWORKS_BASE_URL", "https://api.fireworks.ai/inference/v1"),
            api_key=_env("FIREWORKS_API_KEY"),
            model=_env("FIREWORKS_MODEL", "accounts/fireworks/models/muse-spark-open"),
            raw_ok=True,
        ),
    }


def raw_provider() -> Provider:
    """Provider for calls that may contain raw sample content."""
    name = _env("HAZMAT_RAW_PROVIDER", "baseten")
    p = providers().get(name)
    if p is None:
        raise ValueError(f"HAZMAT_RAW_PROVIDER={name!r} is not a known provider")
    if not p.raw_ok:
        raise ValueError(
            f"HAZMAT_RAW_PROVIDER={name!r} is a hosted API; sensitive content must "
            "stay on open-weights models (baseten, local or fireworks)."
        )
    return p


def summary_provider() -> Provider:
    """Provider for sanitized-only calls (report writing, summaries)."""
    name = _env("HAZMAT_SUMMARY_PROVIDER", "meta")
    p = providers().get(name)
    if p is None:
        raise ValueError(f"HAZMAT_SUMMARY_PROVIDER={name!r} is not a known provider")
    return p

"""Thin OpenAI-compatible client wrapper with the raw/sanitized routing rule.

Every call is logged as one line: who asked (role), provider, the model name as
echoed in the API response, tokens in/out and latency. Never the key, the
prompt or the reply. Lines go to stderr, and also to the file named by
HAZMAT_CALL_LOG when set, so a run can show every live model call on screen
even when the call happens inside the reader cell.
"""

from __future__ import annotations

import os
import sys
import time

from openai import OpenAI

from . import budget
from .config import Provider, raw_provider, second_provider, summary_provider

# Every model Hazmat may call at runtime is a Meta model. Refuse anything else.
META_MODEL_PREFIXES = ("muse-", "meta-models/muse-", "accounts/fireworks/models/muse-", "llama", "meta-llama/")


def client_for(p: Provider) -> OpenAI:
    if not p.configured:
        raise RuntimeError(f"Provider {p.name!r} is not configured; check your .env")
    return OpenAI(base_url=p.base_url, api_key=p.api_key)


def _log_call(line: str) -> None:
    path = os.environ.get("HAZMAT_CALL_LOG")
    if not path:
        print(line, file=sys.stderr, flush=True)
        return
    with open(path, "a") as f:  # a run prints this file live, so don't also print here
        f.write(line + "\n")


def chat(p: Provider, messages: list[dict], role: str = "", **kwargs) -> str:
    if not p.model.lower().startswith(META_MODEL_PREFIXES) or "-contributor" in p.model:
        raise RuntimeError(f"{p.model!r} is not an allowed Meta model")
    budget.check(p.name)
    t = time.monotonic()
    resp = client_for(p).chat.completions.create(model=p.model, messages=messages, **kwargs)
    usage = resp.usage
    tin, tout = (usage.prompt_tokens or 0, usage.completion_tokens or 0) if usage else (0, 0)
    if usage:
        budget.record(p.name, tin, tout)
    _log_call(f"[model call] {time.strftime('%H:%M:%S')}  {role or '-':<8} {p.name:<9} model={resp.model}  "
              f"in={tin} out={tout}  {time.monotonic() - t:.1f}s")
    return resp.choices[0].message.content or ""


def chat_raw(messages: list[dict], **kwargs) -> str:
    """Use for prompts with unsanitized content. Open-weights only."""
    return chat(raw_provider(), messages, **kwargs)


def chat_second(messages: list[dict], **kwargs) -> str:
    """Unsanitized content to the independent cross-check provider. Open-weights only."""
    return chat(second_provider(), messages, **kwargs)


def chat_summary(messages: list[dict], **kwargs) -> str:
    """Use only for sanitized content."""
    return chat(summary_provider(), messages, **kwargs)

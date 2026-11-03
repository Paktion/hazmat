"""Thin OpenAI-compatible client wrapper with the raw/sanitized routing rule."""

from __future__ import annotations

from openai import OpenAI

from .config import Provider, raw_provider, summary_provider


def client_for(p: Provider) -> OpenAI:
    if not p.configured:
        raise RuntimeError(f"Provider {p.name!r} is not configured; check your .env")
    return OpenAI(base_url=p.base_url, api_key=p.api_key)


def chat(p: Provider, messages: list[dict], **kwargs) -> str:
    resp = client_for(p).chat.completions.create(model=p.model, messages=messages, **kwargs)
    return resp.choices[0].message.content or ""


def chat_raw(messages: list[dict], **kwargs) -> str:
    """Use for prompts with unsanitized content. Open-weights only."""
    return chat(raw_provider(), messages, **kwargs)


def chat_summary(messages: list[dict], **kwargs) -> str:
    """Use only for sanitized content."""
    return chat(summary_provider(), messages, **kwargs)

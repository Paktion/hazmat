"""The routing guard: non-Meta and contributor models are refused before any network call,
and raw sample content can never be routed to the hosted Meta API."""

import pytest

from hazmat import config, llm
from hazmat.config import Provider


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def fail(p):
        raise AssertionError(f"client created for {p.model!r}; the guard should have refused first")
    monkeypatch.setattr(llm, "client_for", fail)


@pytest.mark.parametrize("model", ["gpt-4o", "claude-x", "muse-spark-1.3-contributor",
                                   "meta-models/muse-spark-open-1026-contributor"])
def test_chat_refuses_before_network(model):
    p = Provider(name="x", base_url="https://example.invalid/v1", api_key="k", model=model, raw_ok=True)
    with pytest.raises(RuntimeError, match="not an allowed Meta model"):
        llm.chat(p, [{"role": "user", "content": "hi"}])


def test_raw_provider_refuses_hosted_meta(monkeypatch):
    monkeypatch.setenv("HAZMAT_RAW_PROVIDER", "meta")
    with pytest.raises(ValueError, match="hosted API"):
        config.raw_provider()


def test_second_provider_refuses_hosted_meta(monkeypatch):
    monkeypatch.setenv("HAZMAT_SECOND_PROVIDER", "meta")
    with pytest.raises(ValueError, match="open-weights"):
        config.second_provider()


def test_raw_provider_defaults_to_open_weights(monkeypatch):
    monkeypatch.delenv("HAZMAT_RAW_PROVIDER", raising=False)
    assert config.raw_provider().raw_ok

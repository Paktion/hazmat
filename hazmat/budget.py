"""Per-provider spending caps, enforced before every model call.

Not every provider lets you set a hard spend limit, so Hazmat keeps its own
ledger: each response's token usage is priced and added to a running total
per provider, and calls are refused once a provider reaches its cap.

Caps and prices come from .env (USD; prices per 1M tokens):

    HAZMAT_BUDGET_META=150          HAZMAT_PRICE_META=1.25,4.25
    HAZMAT_BUDGET_BASETEN=100       HAZMAT_PRICE_BASETEN=1.25,4.25
    HAZMAT_BUDGET_FIREWORKS=25      HAZMAT_PRICE_FIREWORKS=1.25,4.25
    HAZMAT_BUDGET_MODAL=20          HAZMAT_PRICE_MODAL=0.0000394,0.0000067

Modal sandboxes are priced by run time instead of tokens: HAZMAT_PRICE_MODAL is
(USD per CPU-core-second, USD per GiB-second). The default cap keeps $10 of
the $30 credit in reserve.

A cap of 0 means no cap. The ledger lives in ~/.hazmat/spend.json and is a
running total since it was created (hackathon credits don't reset monthly);
`hazmat spend --reset` starts it over.
"""

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from pathlib import Path

LEDGER = Path(os.environ.get("HAZMAT_LEDGER", Path.home() / ".hazmat" / "spend.json"))

# Defaults: the hackathon credit on each provider, so nothing is paid out of pocket.
DEFAULT_BUDGETS = {"meta": 150.0, "baseten": 100.0, "fireworks": 25.0, "local": 0.0, "modal": 20.0}
# Muse Spark 1.3 and Muse Spark Open list at $1.25 in / $4.25 out per 1M tokens.
DEFAULT_PRICES = {"meta": (1.25, 4.25), "baseten": (1.25, 4.25), "fireworks": (1.25, 4.25), "local": (0.0, 0.0)}
# Modal sandbox rates (per core-second, per GiB-second); conservative, check modal.com/pricing.
DEFAULT_PRICES["modal"] = (0.0000394, 0.0000067)


class BudgetExceeded(RuntimeError):
    pass


def budget(provider: str) -> float:
    raw = os.environ.get(f"HAZMAT_BUDGET_{provider.upper()}", "").strip()
    return float(raw) if raw else DEFAULT_BUDGETS.get(provider, 0.0)


def prices(provider: str) -> tuple[float, float]:
    raw = os.environ.get(f"HAZMAT_PRICE_{provider.upper()}", "").strip()
    if raw:
        inp, out = (float(x) for x in raw.split(","))
        return inp, out
    return DEFAULT_PRICES.get(provider, (0.0, 0.0))


@contextmanager
def _locked():
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with open(LEDGER, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        text = f.read()
        data = json.loads(text) if text.strip() else {}
        yield data
        f.seek(0)
        f.truncate()
        json.dump(data, f, indent=2)


def spent(provider: str) -> float:
    with _locked() as data:
        return data.get(provider, {}).get("usd", 0.0)


def check(provider: str) -> None:
    """Raise BudgetExceeded if `provider` has reached its cap."""
    cap = budget(provider)
    if cap > 0 and (used := spent(provider)) >= cap:
        raise BudgetExceeded(
            f"{provider} has spent ${used:.4f} of its ${cap:.2f} cap. "
            f"Raise HAZMAT_BUDGET_{provider.upper()} in .env to continue."
        )


def record(provider: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Add one call's cost to the ledger and return it in USD."""
    inp, out = prices(provider)
    cost = (prompt_tokens * inp + completion_tokens * out) / 1_000_000
    with _locked() as data:
        entry = data.setdefault(provider, {"usd": 0.0, "calls": 0, "prompt_tokens": 0, "completion_tokens": 0})
        entry["usd"] += cost
        entry["calls"] += 1
        entry["prompt_tokens"] += prompt_tokens
        entry["completion_tokens"] += completion_tokens
    return cost


def record_sandbox(provider: str, seconds: float, cpus: float, gib: float) -> float:
    """Add one sandbox run's cost (priced by run time) to the ledger and return it in USD."""
    per_core, per_gib = prices(provider)
    cost = seconds * (cpus * per_core + gib * per_gib)
    with _locked() as data:
        entry = data.setdefault(provider, {"usd": 0.0, "calls": 0, "seconds": 0.0})
        entry["usd"] += cost
        entry["calls"] += 1
        entry["seconds"] = entry.get("seconds", 0.0) + seconds
    return cost


def reset() -> None:
    LEDGER.unlink(missing_ok=True)

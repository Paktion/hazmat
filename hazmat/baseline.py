"""The baseline: how most AI analysis setups work today, for comparison.

    hazmat baseline SAMPLE [--backend docker]

Runs the same tools in the same sandbox, then pastes their raw output
(strings, capa rules, imports, decompiled code of the interesting functions)
straight into one prompt and asks Muse Spark Open (on Fireworks) for a
verdict. No airlock, no handles, no rules: whatever text the sample carries
reaches the model that decides. Open-weights only, since it reads raw content.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from .llm import chat_second
from .sandbox import DEFAULT_TOOLS, run

SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign"]},
        "confidence": {"type": "string", "enum": ["high", "moderate", "low"]},
        "summary": {"type": "string"},
    },
    "required": ["verdict", "confidence", "summary"],
    "additionalProperties": False,
}
TO_CATEGORY = {"malicious": "5", "suspicious": "4B", "benign": "1"}
INTERESTING = {"IsDebuggerPresent", "ptrace", "snprintf", "VirtualProtect", "VirtualAlloc"}


def _prompt(report) -> str:
    g = report.ghidra or {"functions": [], "imports": []}
    strings = report.get("strings").stdout.splitlines() if report.get("strings") else []
    # Typical setups keep the "interesting" strings: long ones first, capped.
    keep = sorted({s for s in strings if len(s) >= 8}, key=len, reverse=True)[:80]
    try:
        capa = sorted(json.loads(report.get("capa").stdout).get("rules", {}))
    except Exception:  # noqa: BLE001
        capa = []
    funcs = [f for f in g["functions"] if set(f["callees"]) & INTERESTING][:3]
    code = "\n\n".join(f["decompiled"][:6000] for f in funcs)
    return (
        "You are a malware analyst. Here is the output of static analysis tools on a file. "
        "Decide whether the file is malicious, suspicious or benign.\n\n"
        f"## capa capabilities\n{json.dumps(capa)}\n\n"
        f"## imports\n{json.dumps(sorted(i['name'] for i in g['imports']))}\n\n"
        f"## strings\n" + "\n".join(keep) + "\n\n"
        f"## decompiled code (Ghidra)\n{code}\n"
    )


def analyze(sample: str | Path, backend: str | None = None, run_root: str | Path = "runs",
            echo: bool = True) -> dict[str, Any]:
    sample = Path(sample)
    run_dir = Path(run_root) / f"baseline-{sample.stem}-{time.strftime('%Y%m%d-%H%M%S')}"
    run_dir.mkdir(parents=True, exist_ok=True)
    os.environ.pop("HAZMAT_CALL_LOG", None)
    t0 = time.monotonic()
    report = run(sample, tools=DEFAULT_TOOLS, backend=backend)
    prompt = _prompt(report)
    (run_dir / "prompt.txt").write_text(prompt)
    raw = chat_second([{"role": "user", "content": prompt}], role="baseline", max_tokens=4096,
                      response_format={"type": "json_schema",
                                       "json_schema": {"name": "verdict", "strict": True, "schema": SCHEMA}})
    out = json.loads(raw)
    out["category"] = TO_CATEGORY[out["verdict"]]
    out["seconds"] = round(time.monotonic() - t0, 1)
    (run_dir / "verdict.json").write_text(json.dumps(out, indent=2))
    if echo:
        print(f"Baseline (raw tool output -> Muse Spark Open on Fireworks): {sample.name}")
        print(f"  verdict    {out['verdict']} ({out['confidence']})")
        print(f"  summary    {out['summary'][:400]}")
        print(f"  files      {run_dir}")
    return out


def main(sample: str, backend: str | None) -> int:
    analyze(sample, backend)
    return 0

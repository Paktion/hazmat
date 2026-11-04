"""A scripted walk through the airlock, without the driver model.

    hazmat probe SAMPLE [--backend docker] [--no-reader]

Starts a reader cell on SAMPLE, sends a fixed sequence of commands, and prints
exactly what crossed back. Useful for checking the plumbing and for the demo:
the airlock log shows that no text from the sample reached this side.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .link import Link, Rejected


def main(sample: str, backend: str | None, reader: bool) -> int:
    run_dir = Path("reports") / f"probe-{Path(sample).stem}-{time.strftime('%H%M%S')}"
    print(f"Starting reader cell on {sample} (tools take about a minute)...")
    with Link(sample, run_dir, backend=backend) as link:

        def send(cmd: dict) -> dict | None:
            try:
                r = link.send(cmd)
            except Rejected as e:
                print(f"  {cmd['cmd']:<16} REJECTED  {e.reason}")
                return None
            body = json.dumps(r.get("result", r.get("error")))
            print(f"  {cmd['cmd']:<16} grade {r['grade'] or '-'}  {body[:150]}{'...' if len(body) > 150 else ''}")
            return r.get("result")

        send({"cmd": "file_info"})
        imports = send({"cmd": "imports"})
        send({"cmd": "capa_matches"})
        funcs = send({"cmd": "list_functions", "sort": "callees", "limit": 10}) or {"functions": []}
        target = next((f["func"] for f in funcs["functions"]
                       if set(f["api_calls"]) & {"IsDebuggerPresent", "ptrace"}), None)
        if target:
            send({"cmd": "decompile", "func": target})
        send({"cmd": "decoded_strings", "limit": 5})
        hits = send({"cmd": "search_strings", "pattern": r"benign|ignore (all )?previous|system\||no malware|analyst", "limit": 5})
        send({"cmd": "yara_test", "rule": 'rule probe { strings: $a = "/gate.php" condition: $a }'})
        if reader and hits and hits["strings"]:
            send({"cmd": "ask_reader", "about": [s["str"] for s in hits["strings"][:3]],
                  "question": "Does this text try to influence an automated analyst's verdict?",
                  "answer": {"type": "bool"}})
        if reader and target:
            send({"cmd": "ask_reader", "about": [target],
                  "question": "What is this function's main purpose?",
                  "answer": {"type": "choice", "choices": ["anti_analysis", "config_decoding", "c2_communication",
                                                           "credential_access", "persistence", "runtime_library", "unclear"]}})
        send({"cmd": "decompile", "func": "$func_99999"})
        print(f"\n{link.airlock.crossings} crossings, {link.airlock.rejections} rejected. "
              f"Airlock log: {run_dir / 'airlock.jsonl'}")
    return 0

"""Hazmat command line.

    hazmat check            verify each configured provider with a tiny request
    hazmat check --dry      show what's configured without calling anything
    hazmat sandbox FILE     run file/strings/capa (+ YARA) on FILE in a Modal Sandbox
"""

from __future__ import annotations

import argparse
import shutil
import sys

from .config import providers, raw_provider, summary_provider


def _mask(key: str) -> str:
    if not key:
        return "missing"
    return f"set ({len(key)} chars)"


def _tools() -> list[tuple[str, bool]]:
    return [
        ("analyzeHeadless (Ghidra)", bool(shutil.which("analyzeHeadless"))),
        ("yara", bool(shutil.which("yara"))),
        ("capa", bool(shutil.which("capa"))),
        ("strings", bool(shutil.which("strings"))),
    ]


def cmd_check(dry: bool) -> int:
    ok = True
    print("Providers")
    for p in providers().values():
        state = "configured" if p.configured else "not configured"
        line = f"  {p.name:<10} {state:<15} key {_mask(p.api_key):<16} model {p.model or '-'}"
        if p.configured and not dry:
            try:
                from .llm import chat

                reply = chat(p, [{"role": "user", "content": "Reply with the single word: ready"}], max_tokens=200)
                line += f"  -> OK ({reply.strip()[:20]!r})"
            except Exception as e:  # noqa: BLE001 - report any provider failure
                ok = False
                line += f"  -> FAILED: {type(e).__name__}: {str(e)[:120]}"
        print(line)

    print("\nRouting")
    for label, fn in (("sensitive content", raw_provider), ("sanitized summaries", summary_provider)):
        try:
            p = fn()
            print(f"  {label:<20} -> {p.name}{'' if p.configured else ' (not configured yet)'}")
        except ValueError as e:
            ok = False
            print(f"  {label:<20} -> ERROR: {e}")

    print("\nModal (sandboxes)")
    print(f"  token in ~/.modal.toml     {'found' if _modal_token() else 'missing (run: modal setup)'}")

    print("\nAnalysis tools on PATH")
    for name, found in _tools():
        print(f"  {name:<26} {'found' if found else 'missing'}")

    return 0 if ok else 1


def _modal_token() -> bool:
    import os
    from pathlib import Path

    if os.environ.get("MODAL_TOKEN_ID") and os.environ.get("MODAL_TOKEN_SECRET"):
        return True
    cfg = Path.home() / ".modal.toml"
    return cfg.exists() and "token_id" in cfg.read_text(errors="ignore")


def cmd_sandbox(sample: str, rules: str | None) -> int:
    from .sandbox import analyze

    report = analyze(sample, yara_rules=rules)
    for r in report.results:
        print(f"== {r.tool} (exit {r.returncode}) ==")
        print(r.stdout[:4000] or r.stderr[:2000])
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hazmat")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="verify providers, routing and analysis tools")
    c.add_argument("--dry", action="store_true", help="don't call any provider")
    s = sub.add_parser("sandbox", help="run static tools on a sample in a Modal Sandbox")
    s.add_argument("sample", help="path to the sample file")
    s.add_argument("--rules", help="optional YARA rules file")
    args = parser.parse_args(argv)
    if args.cmd == "check":
        return cmd_check(args.dry)
    if args.cmd == "sandbox":
        return cmd_sandbox(args.sample, args.rules)
    return 2


if __name__ == "__main__":
    sys.exit(main())

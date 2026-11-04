"""Hazmat command line.

    hazmat check            verify each configured provider with a tiny request
    hazmat check --dry      show what's configured without calling anything
    hazmat sandbox FILE     run the analysis tools on FILE in an isolated sandbox
    hazmat selftest         check every tool on every test sample, in the sandbox
    hazmat analyze FILE     full analysis: driver (Muse Spark) + airlock + reader cell -> verdict
    hazmat probe FILE       walk FILE through the airlock with a scripted driver
    hazmat spend            spend so far against each provider's cap (and Modal)
"""

from __future__ import annotations

import argparse
import shutil
import sys

from . import budget
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

                reply = chat(p, [{"role": "user", "content": "Reply with the single word: ready"}], max_tokens=1024)
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

    print()
    cmd_spend(reset=False)

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


def cmd_spend(reset: bool) -> int:
    if reset:
        budget.reset()
        print(f"Cleared {budget.LEDGER}")
        return 0
    print("Spend (Hazmat's own ledger; caps from HAZMAT_BUDGET_*)")
    for name in [*providers(), "modal"]:
        cap = budget.budget(name)
        print(f"  {name:<10} ${budget.spent(name):>8.4f} of {f'${cap:.2f}' if cap else 'no cap'}")
    return 0


def cmd_sandbox(sample: str, rules: str | None, backend: str | None) -> int:
    from .sandbox import run

    report = run(sample, yara_rules=rules, backend=backend)
    for r in report.results:
        print(f"== {r.tool} (exit {r.returncode}, {r.seconds:.1f}s) ==")
        print(r.stdout[:4000] or r.stderr[:2000])
    if report.ghidra:
        g = report.ghidra
        print(f"== ghidra export: {len(g['functions'])}/{g['function_count']} functions, "
              f"{len(g['imports'])} imports, {len(g['strings'])} strings ==")
    print(f"\n{report.backend}: {report.seconds:.1f}s" + (f", ${report.cost_usd:.4f}" if report.cost_usd else ""))
    return 0


def cmd_selftest(backend: str | None, build: bool) -> int:
    from .selftest import main as selftest

    return selftest(backend=backend, build=build)


def cmd_analyze(sample: str, backend: str | None, steps: int) -> int:
    from .driver import main as analyze

    return analyze(sample, backend, steps)


def cmd_probe(sample: str, backend: str | None, reader: bool) -> int:
    from .probe import main as probe

    return probe(sample, backend, reader)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hazmat")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="verify providers, routing and analysis tools")
    c.add_argument("--dry", action="store_true", help="don't call any provider")
    s = sub.add_parser("sandbox", help="run static tools on a sample in a Modal Sandbox")
    s.add_argument("sample", help="path to the sample file")
    s.add_argument("--rules", help="optional YARA rules file")
    s.add_argument("--backend", choices=["modal", "docker"], help="default: $HAZMAT_SANDBOX or modal")
    st = sub.add_parser("selftest", help="run every tool on every test sample and check the results")
    st.add_argument("--backend", choices=["modal", "docker"], help="default: $HAZMAT_SANDBOX or modal")
    st.add_argument("--build", action="store_true", help="rebuild the local image and test samples first")
    an = sub.add_parser("analyze", help="analyze a sample: driver + airlock + reader cell -> verdict")
    an.add_argument("sample")
    an.add_argument("--backend", choices=["modal", "docker"], help="default: $HAZMAT_SANDBOX or modal")
    an.add_argument("--steps", type=int, default=12, help="max driver steps (default 12)")
    pr = sub.add_parser("probe", help="walk a sample through the airlock with a scripted driver")
    pr.add_argument("sample")
    pr.add_argument("--backend", choices=["modal", "docker"], help="default: $HAZMAT_SANDBOX or modal")
    pr.add_argument("--no-reader", action="store_true", help="skip the reader model calls")
    sp = sub.add_parser("spend", help="show spend against each provider's cap")
    sp.add_argument("--reset", action="store_true", help="clear the spend ledger")
    args = parser.parse_args(argv)
    if args.cmd == "check":
        return cmd_check(args.dry)
    if args.cmd == "spend":
        return cmd_spend(args.reset)
    if args.cmd == "sandbox":
        return cmd_sandbox(args.sample, args.rules, args.backend)
    if args.cmd == "analyze":
        return cmd_analyze(args.sample, args.backend, args.steps)
    if args.cmd == "probe":
        return cmd_probe(args.sample, args.backend, not args.no_reader)
    if args.cmd == "selftest":
        return cmd_selftest(args.backend, args.build)
    return 2


if __name__ == "__main__":
    sys.exit(main())

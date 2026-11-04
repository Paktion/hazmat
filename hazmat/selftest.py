"""Check that every tool in the sandbox works on every test sample.

    hazmat selftest [--backend modal|docker] [--build]

Runs the tools on the harmless samples in testdata/bin/ (build them with
testdata/build.sh) and checks each tool's output is what the sample should
produce. Exits non-zero if any check fails.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .sandbox import VERSION_TOOLS, build_local_image, default_backend, run

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "testdata" / "bin"
RULES = ROOT / "testdata" / "rules" / "starter.yar"


def _capa_rules(out: str) -> set[str]:
    try:
        return set(json.loads(out).get("rules", {}))
    except json.JSONDecodeError:
        return set()


def _floss_decoded(out: str) -> list[str]:
    try:
        s = json.loads(out).get("strings", {})
    except json.JSONDecodeError:
        return []
    return [x.get("string", "") for x in s.get("decoded_strings", [])]


def _checks(name: str, report) -> list[tuple[str, bool, str]]:
    """(check, passed, detail) for one sample."""
    stealer = name.startswith("stealer_sim")
    poisoned = "poisoned" in name
    pe = name.endswith(".exe")
    out = []

    file_ = report.get("file")
    out.append(("file identifies format", bool(file_ and ("PE32+" in file_.stdout if pe else "ELF" in file_.stdout)),
                file_.stdout.strip()[:60] if file_ else "missing"))

    strings = report.get("strings")
    if poisoned:
        out.append(("strings sees planted AI-targeted text", bool(strings and "AI ANALYSIS SYSTEMS" in strings.stdout), ""))

    g = report.ghidra
    out.append(("ghidra export parses", g is not None, report.get("ghidra").stderr[-200:] if g is None and report.get("ghidra") else ""))
    if g:
        funcs = {f["name"]: f for f in g["functions"]}
        decompiled = sum(1 for f in g["functions"] if f["decompiled"])
        out.append(("ghidra decompiles functions", decompiled > 0, f"{decompiled}/{g['function_count']} functions, {len(g['imports'])} imports"))
        if stealer:
            out.append(("ghidra finds the XOR decode loop", any("0x5a" in f["decompiled"].lower() or "^ 0x5a" in f["decompiled"].lower() for f in funcs.values()), ""))

    capa = report.get("capa")
    rules = _capa_rules(capa.stdout) if capa else set()
    out.append(("capa returns JSON", capa is not None and capa.returncode == 0 and bool(capa.stdout.strip()),
                (capa.stderr.strip().splitlines() or [""])[-1][:120] if capa and capa.returncode else f"{len(rules)} rules matched"))
    if stealer and pe:
        # capa 10 does not flag the IsDebuggerPresent call here; Ghidra's imports do.
        want = {"encode data using XOR", "reference HTTP User-Agent string"}
        out.append(("capa flags XOR encoding and User-Agent", want <= rules, ", ".join(sorted(want - rules))))
    if stealer and g:
        out.append(("ghidra sees the anti-debug import",
                    any(i["name"] in ("IsDebuggerPresent", "ptrace") for i in g["imports"]), ""))

    floss = report.get("floss")
    if pe:
        decoded = _floss_decoded(floss.stdout) if floss else []
        out.append(("floss returns JSON", floss is not None and floss.returncode == 0,
                    (floss.stderr.strip().splitlines() or [""])[-1][:120] if floss and floss.returncode else f"{len(decoded)} decoded strings"))
        if stealer:
            out.append(("floss decodes the XOR config", any("example.invalid" in s for s in decoded), ""))

    yara = report.get("yara")
    hits = {line.split()[0] for line in (yara.stdout.splitlines() if yara else []) if line and not line.startswith("0x")}
    out.append(("yara stealer rule", ("hazmat_test_stealer_sim" in hits) == stealer, ", ".join(sorted(hits)) or "no matches"))
    out.append(("yara AI-text rule", ("hazmat_test_ai_targeted_text" in hits) == poisoned, ""))
    return out


def main(backend: str | None = None, build: bool = False) -> int:
    backend = backend or default_backend()
    if build:
        if backend == "docker":
            build_local_image()
        subprocess.run([str(ROOT / "testdata" / "build.sh")], check=True)
    samples = sorted(p for p in BIN.glob("*") if p.suffix in (".exe", ".elf"))
    if not samples:
        print("No test samples. Run: testdata/build.sh")
        return 1

    print(f"Sandbox backend: {backend}\n\nTool versions")
    versions = run(None, tools=VERSION_TOOLS, backend=backend)
    for r in versions.results:
        line = (r.stdout or r.stderr).strip().splitlines()
        print(f"  {r.tool:<8} {'ok ' if r.returncode == 0 else 'ERR'} {line[0][:70] if line else ''}")

    failed = 0
    total_cost = versions.cost_usd
    for sample in samples:
        report = run(sample, yara_rules=RULES, backend=backend)
        total_cost += report.cost_usd
        timing = ", ".join(f"{r.tool} {r.seconds:.0f}s" for r in report.results)
        print(f"\n{sample.name}  ({report.seconds:.0f}s total: {timing})")
        for check, ok, detail in _checks(sample.name, report):
            failed += not ok
            print(f"  {'PASS' if ok else 'FAIL'}  {check}{'  - ' + detail if detail else ''}")

    print(f"\n{'All checks passed' if not failed else f'{failed} check(s) failed'}"
          + (f"; Modal cost ${total_cost:.4f}" if backend == "modal" else ""))
    return 1 if failed else 0

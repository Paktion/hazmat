"""Run the analysis tools (no models) on the real SOREL samples in the local Docker volume.

    python scripts/real_tools_only.py        # needs: docker volume hazmat-real (scripts/fetch_sorel.py)

No model is called: this checks that Ghidra, capa, FLOSS and YARA handle real malware, and records
what the deterministic tools see. Samples never leave the volume; output is hashes and tool stats.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hazmat.sandbox import DEFAULT_TOOLS, SandboxReport, Session  # noqa: E402

labels = json.loads((Path(__file__).resolve().parent.parent / "testdata/real/expected.json").read_text())
rows = []
for name, lab in labels.items():
    if name.startswith("_"):
        continue
    vol, fname = lab["volume"].split("/", 1)
    with Session("docker", volume=vol) as sb:
        sb.stage_volume_sample(fname)
        rep = sb.run_tools(SandboxReport(sample=name, backend="docker"), DEFAULT_TOOLS)
    capa = rep.get("capa")
    try:
        rules = json.loads(capa.stdout).get("rules", {}) if capa and capa.stdout.strip() else {}
    except json.JSONDecodeError:
        rules = {}
    attack = sorted({a.get("id") for r in rules.values() for a in (r.get("meta", {}).get("attack") or []) if a.get("id")})
    g = rep.ghidra or {}
    rows.append({"sample": name, "sha256": lab["sha256"], "size": lab["size"],
                 "file": (rep.get("file").stdout.strip()[:60] if rep.get("file") else ""),
                 "ghidra_functions": g.get("function_count"), "imports": len(g.get("imports", [])),
                 "capa_rules": len(rules), "attack": attack[:12],
                 "tools_ok": {r.tool: r.returncode == 0 for r in rep.results},
                 "seconds": {r.tool: round(r.seconds) for r in rep.results}})
    print(json.dumps(rows[-1]), flush=True)
Path("testdata/real/tools_only.json").write_text(json.dumps(rows, indent=2) + "\n")

"""Hazmat as one step in another agent's chain, over MCP.

    hazmat mcp            # stdio MCP server

Exposes a single tool, `analyze_file(path)`, that runs the full Hazmat
pipeline and returns only the typed verdict: category, required action,
likelihood, confidence, reason codes, injection rating, ATT&CK IDs and the
driver's summary (written by a model that never saw the file's text). No
strings, no decompiled code, no reader notes: the calling agent is never
exposed to text the sample's author wrote. The human report stays on disk.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

server = MCPServer("hazmat")

VERDICT_FIELDS = ("category", "category_label", "required_action", "likelihood_term", "likelihood_band",
                  "analytic_confidence", "auto_close_eligible", "reason_codes", "attack", "injection", "summary")


@server.tool()
def analyze_file(path: str, backend: str = "") -> dict:
    """Analyze a suspicious file in an isolated sandbox and return a typed verdict.

    Returns category (0 incomplete, 1-3 benign, 4A-4C suspicious, 5 malicious), the required action,
    an ICD 203 likelihood term, analytic confidence, up to four reason codes with evidence IDs,
    ATT&CK technique IDs, and an injection rating (did the file carry text aimed at AI analysts,
    and did it move the reader model). Contains no text from the file itself.
    """
    from .driver import Analysis

    sample = Path(path).expanduser().resolve()
    if not sample.is_file():
        return {"error": "NOT_FOUND"}
    a = Analysis(sample, backend=backend or os.environ.get("HAZMAT_SANDBOX") or None, echo=False)
    v = a.run()
    out = {k: v[k] for k in VERDICT_FIELDS}
    out["sha256"] = v.get("sample", {}).get("sha256")
    out["report_path"] = str(a.run_dir / "report.md")
    return out


def main() -> int:
    server.run()
    return 0

"""The human report for one run: the only place raw content is shown.

    hazmat report RUN_DIR

Reads verdict.json, evidence.json, store.json, airlock.jsonl and calls.log
from a run directory and writes report.md. Handles cited as evidence are
resolved here, for a person to read, with IOCs defanged (hxxp, [.]). None of
this goes back to the driver.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .verdict import REASON_CODES

URL = re.compile(r"\b(https?|ftp)://[^\s\"'<>]+", re.I)
HOST = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|invalid|example|local|onion))\b", re.I)
IP = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def defang(text: str) -> str:
    text = URL.sub(lambda m: m.group(0).replace("http", "hxxp", 1).replace("ftp", "fxp", 1).replace(".", "[.]"), text)
    text = HOST.sub(lambda m: m.group(0).replace(".", "[.]") if "[.]" not in m.group(0) else m.group(0), text)
    return IP.sub(r"\1[.]\2[.]\3[.]\4", text)


def iocs(store: dict[str, Any]) -> dict[str, list[str]]:
    urls, hosts = set(), set()
    for item in store.values():
        if item.get("kind") != "str":
            continue
        t = item.get("text", "")
        # skip fragments (FLOSS emulation yields partial copies like 'http://update')
        urls.update(u for u in (m.group(0) for m in URL.finditer(t)) if "." in u.split("://", 1)[1].split("/")[0])
        hosts.update(m.group(1) for m in HOST.finditer(t))
    return {"urls": sorted(defang(u) for u in urls), "hosts": sorted(defang(h) for h in hosts)}


def _quote(text: str, limit: int = 600) -> str:
    text = defang(text.replace("```", "'''"))
    return text[:limit] + (" [...]" if len(text) > limit else "")


def build(run_dir: str | Path) -> Path:
    d = Path(run_dir)
    v = json.loads((d / "verdict.json").read_text())
    evidence = {e["id"]: e for e in json.loads((d / "evidence.json").read_text())}
    store = json.loads((d / "store.json").read_text()) if (d / "store.json").exists() else {}
    crossings = [json.loads(l) for l in (d / "airlock.jsonl").read_text().splitlines()] if (d / "airlock.jsonl").exists() else []
    calls = (d / "calls.log").read_text().splitlines() if (d / "calls.log").exists() else []
    s = v.get("sample", {})

    out = [f"# Hazmat report: `{s.get('sha256', '?')[:16]}…`", ""]
    out += [f"**Verdict: category {v['category']} ({v['category_label'].replace('_', ' ')})** → `{v['required_action']}`", "",
            f"- Likelihood malicious: **{v['likelihood_term']}** {v['likelihood_band']} (ICD 203)",
            f"- Analytic confidence: **{v['analytic_confidence']}** (quality of the evidence, separate from likelihood)",
            f"- Auto-close eligible: {v['auto_close_eligible']}",
            f"- File: {s.get('format', '?')} {s.get('arch', '?')}, {s.get('size', '?')} bytes, sha256 `{s.get('sha256', '?')}`",
            f"- Driver proposed: {v['driver_proposed']}", ""]
    if v.get("summary"):
        out += ["## Summary (from the driver, which never saw the file's text)", "", v["summary"], ""]

    out += ["## Reasons", "", "| Code | Meaning | Evidence |", "|---|---|---|"]
    for r in v["reason_codes"]:
        cited = ", ".join(f"{e} ({evidence[e]['grade']}, {evidence[e]['cmd']})" for e in r["evidence"] if e in evidence)
        out.append(f"| `{r['code']}` | {REASON_CODES.get(r['code'], '')} | {cited} |")
    out.append("")

    inj = v["injection"]
    out += ["## Text aimed at AI analysts", "",
            f"- Present: **{inj['present']}**; kinds: {', '.join(inj['targets']) or 'none'}",
            f"- Reader steered (answer changed when the text was masked): **{inj['reader_flipped']}** → effect: **{inj['effect']}**", ""]
    cc = v.get("cross_check", {})
    if cc and "skipped" not in cc:
        out += [f"- Cross-check question asked of two independent readers: Baseten primary **{cc.get('primary')}**, "
                f"Fireworks **{cc.get('second')}**, Fireworks with flagged text masked **{cc.get('second_masked', 'n/a')}**", ""]
    flagged = next((e["result"]["handles"] for e in evidence.values() if e["cmd"] == "injection_scan" and e["ok"]), [])
    for h in flagged[:6]:
        if h in store:
            out += [f"`{h}`:", "```", _quote(store[h]["text"], 400), "```"]
    out.append("")

    found = iocs(store)
    if found["urls"] or found["hosts"]:
        out += ["## Indicators (defanged)", ""]
        out += [f"- URL `{u}`" for u in found["urls"]] + [f"- Host `{h}`" for h in found["hosts"] if not any(h in u for u in found["urls"])]
        out.append("")
    if v.get("attack"):
        out += ["## ATT&CK", "", ", ".join(f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)" for t in v["attack"]), ""]

    rules = [e for e in evidence.values() if e["cmd"] == "yara_test" and e["ok"] and e["result"]["matched"]]
    rules.sort(key=lambda e: e["result"].get("false_positives", 0))
    if rules:
        fp = rules[0]["result"].get("false_positives", "?")
        out += [f"## YARA rule written by the driver (matched this sample; matched {fp} known-clean reference files)", "",
                "```yara", rules[0]["args"]["rule"], "```", ""]

    notes = [(h, it) for h, it in store.items() if it.get("kind") == "note"]
    if notes:
        out += ["## Reader notes (shown only to you; never sent to the driver)", ""]
        for h, it in notes:
            tag = f"{it.get('reader', 'primary')}{', masked' if it.get('mask') else ''}"
            out += [f"**{h}** ({tag}) — Q: {it.get('question', '')}", "", f"> {_quote(it['text'], 700)}", ""]

    out += ["## Evidence", "", "| ID | Grade | Command | Result (typed, as the driver saw it) |", "|---|---|---|---|"]
    for e in evidence.values():
        body = json.dumps(e["result"] if e["ok"] else e["error"])
        out.append(f"| {e['id']} | {e['grade'] or '-'} | `{e['cmd']}` | `{body[:160]}{'…' if len(body) > 160 else ''}` |")
    out.append("")

    rejected = [c for c in crossings if not c["ok"]]
    out += ["## Airlock", "",
            f"{len(crossings)} crossings, {len(rejected)} rejected. Only typed values and handles crossed upward; "
            "see `airlock.jsonl` for every message.", ""]
    for c in rejected:
        out.append(f"- rejected {c['dir']} `{c.get('cmd', c.get('payload', {}).get('cmd', ''))}`: {c.get('reason', '')}")
    if v["rules_applied"]:
        out += ["", "## Verdict rules applied", ""] + [f"- {r}" for r in v["rules_applied"]]
    out += ["", "## Model calls (every model is a Meta model; names as returned by each API)", "", "```"] + calls + ["```", ""]

    path = d / "report.md"
    path.write_text("\n".join(out))
    return path


def main(run_dir: str) -> int:
    print(build(run_dir))
    return 0

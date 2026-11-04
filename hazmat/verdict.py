"""Hazmat's verdict: a SOC-style triage scheme adapted to file samples.

The driver proposes a verdict; this module checks and corrects it with fixed
rules, so the final call never rests on the driver's word alone. Borrowed from
established rating systems (see docs/verdict-scheme.md):

- Evidence grades per item (Admiralty-style), assigned by the airlock from the
  source: A tool structure / rule matches, B tool interpretation, C the reader
  model, D the sample's own strings (an artifact, never testimony).
- A category with a mandatory action (BI-RADS-style), including 0 Incomplete,
  which can never close as benign.
- An ICD 203 likelihood term with its band, and analytic confidence as a
  separate field.
- Up to four reason codes, each pointing at evidence IDs.
- An injection rating: was there text aimed at AI analysts, and did it move
  the reader's answers.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .airlock import AttackId

Category = Literal["0", "1", "2", "3", "4A", "4B", "4C", "5"]
Likelihood = Literal["remote", "very_unlikely", "unlikely", "even_chance", "likely", "very_likely", "almost_certain"]
Confidence = Literal["high", "moderate", "low"]

REASON_CODES = {
    # malicious
    "MAL-C2-CONFIG": "embedded or encoded command-and-control configuration",
    "MAL-PERSISTENCE": "persistence mechanism (autorun keys, scheduled tasks, autostart files)",
    "MAL-ANTI-ANALYSIS": "anti-debugging or anti-analysis checks",
    "MAL-OBFUSCATION": "encoded or obfuscated data or code",
    "MAL-CREDENTIAL-ACCESS": "targets credential stores (browser logins, wallets, keys)",
    "MAL-EXFIL": "builds or sends data to a remote endpoint",
    "MAL-TTP-SEQUENCE": "several techniques chained in one code path",
    # benign
    "BEN-NO-CAPABILITY": "no suspicious capability found by any tool",
    "BEN-RUNTIME-ONLY": "suspicious-looking findings are compiler or runtime code only",
    # incomplete
    "INC-TOOL-FAILURE": "a core analysis tool failed",
    "INC-INSUFFICIENT-EVIDENCE": "not enough evidence to decide",
    "INC-CONFLICTING-EVIDENCE": "tools and reader disagree",
    # integrity
    "INT-INJECTION-SUSPECTED": "the sample contains text aimed at AI analysts",
    "INT-READER-STEERED": "planted text changed the reader model's answers",
}
ReasonCode = Literal[tuple(REASON_CODES)]  # type: ignore[valid-type]

BANDS: dict[Likelihood, tuple[float, float]] = {
    "remote": (0.01, 0.05), "very_unlikely": (0.05, 0.20), "unlikely": (0.20, 0.45),
    "even_chance": (0.45, 0.55), "likely": (0.55, 0.80), "very_likely": (0.80, 0.95),
    "almost_certain": (0.95, 0.99),
}
TERMS_FOR: dict[str, tuple[Likelihood, ...]] = {
    "0": (), "1": ("remote",), "2": ("remote",), "3": ("remote",), "4A": ("very_unlikely",),
    "4B": ("unlikely", "even_chance"), "4C": ("likely", "very_likely"), "5": ("almost_certain",),
}
LABELS = {
    "0": "incomplete", "1": "benign_no_finding", "2": "benign_explained", "3": "probably_benign",
    "4A": "suspicious_low", "4B": "suspicious_intermediate", "4C": "suspicious_high", "5": "malicious",
}
ACTIONS = {
    "0": "rerun_then_route_to_human_as_incomplete",
    "1": "close_benign_enter_qa_sample",
    "2": "close_benign_enter_qa_sample",
    "3": "close_with_watch_sample_at_3x",
    "4A": "human_review_standard_queue",
    "4B": "human_review_priority_queue",
    "4C": "human_review_urgent_block_staged",
    "5": "block_hash_open_incident_human_confirms",
}
ORDER = ["0", "1", "2", "3", "4A", "4B", "4C", "5"]


class Reason(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: ReasonCode
    evidence: Annotated[list[Annotated[str, StringConstraints(pattern=r"^E[0-9]{1,3}$")]], Field(min_length=1, max_length=8)]


class Proposal(BaseModel):
    """What the driver submits with `finish`."""
    model_config = ConfigDict(extra="forbid")
    category: Category
    likelihood: Likelihood
    confidence: Confidence
    reasons: Annotated[list[Reason], Field(min_length=1, max_length=4)]
    attack: Annotated[list[AttackId], Field(max_length=12)] = []
    summary: Annotated[str, StringConstraints(max_length=700)] = ""


def _bump(cat: str, at_least: str) -> str:
    # 0 (Incomplete) is sticky: missing evidence isn't fixed by raising the category.
    return cat if cat == "0" or ORDER.index(cat) >= ORDER.index(at_least) else at_least


def _cap(cat: str, at_most: str) -> str:
    return cat if ORDER.index(cat) <= ORDER.index(at_most) else at_most


def decide(proposal: Proposal, evidence: list[dict[str, Any]], injection: dict[str, Any] | None = None,
           tool_failures: list[str] | None = None) -> dict[str, Any]:
    """Apply the scheme's rules to the driver's proposal. Returns the final verdict.

    evidence: [{"id": "E3", "cmd": "capa_matches", "grade": "A", ...}]
    injection: {"present": bool, "targets": [...], "reader_flipped": bool | None}
    tool_failures: names of core tools that failed ("ghidra", "capa")
    """
    grades = {e["id"]: e["grade"] for e in evidence}
    rules: list[str] = []
    cat, term, conf = proposal.category, proposal.likelihood, proposal.confidence
    reasons = [r.model_dump() for r in proposal.reasons]
    injection = injection or {"present": False, "targets": [], "reader_flipped": None}
    tool_failures = tool_failures or []

    # R1: reasons may only cite evidence that exists.
    for r in reasons:
        bad = [e for e in r["evidence"] if e not in grades]
        if bad:
            r["evidence"] = [e for e in r["evidence"] if e in grades]
            rules.append(f"R1 dropped unknown evidence {bad} from {r['code']}")
    reasons = [r for r in reasons if r["evidence"]]
    if not reasons:
        reasons = [{"code": "INC-INSUFFICIENT-EVIDENCE", "evidence": [evidence[0]["id"]] if evidence else []}]
        cat = "0"
        rules.append("R1 no reason cited valid evidence: category 0")

    def cited(prefix: str) -> list[str]:
        return [g for r in reasons if r["code"].startswith(prefix) for g in (grades[e] for e in r["evidence"])]

    # R2: a core tool failed and nothing structural backs the call -> Incomplete.
    if tool_failures and not any(e["grade"] == "A" for e in evidence):
        cat = "0"
        rules.append(f"R2 core tools failed ({', '.join(tool_failures)}) with no A-grade evidence: category 0")

    # R3: benign reasons can't rest on the sample's own text (D) or on the reader alone (C).
    ben = cited("BEN-")
    if ben and all(g in ("C", "D") for g in ben):
        cat = _bump(cat, "4A")
        rules.append("R3 benign reasons cite only C/D evidence: at least 4A")

    # R4: malicious calls resting only on the reader (C) or strings (D) are capped.
    mal = cited("MAL-")
    if mal and all(g in ("C", "D") for g in mal):
        cat = _cap(cat, "4B")
        conf = "low"
        rules.append("R4 malicious reasons cite only C/D evidence: capped at 4B, confidence low")

    # R5: text aimed at AI analysts can never close as benign.
    if injection.get("present"):
        if not any(r["code"] == "INT-INJECTION-SUSPECTED" for r in reasons):
            ids = [e["id"] for e in evidence if e["cmd"] == "injection_scan"]
            reasons.append({"code": "INT-INJECTION-SUSPECTED", "evidence": ids[:1] or [evidence[0]["id"]]})
            rules.append("R5 injection present: added INT-INJECTION-SUSPECTED")
        if ORDER.index(cat) < ORDER.index("4A") and cat != "0":
            cat = "4A"
            rules.append("R5 injection present: category raised to at least 4A")

    # R6: the planted text moved the reader -> say so, and trust reader-derived claims less.
    if injection.get("reader_flipped"):
        if not any(r["code"] == "INT-READER-STEERED" for r in reasons):
            ids = [e["id"] for e in evidence if e["cmd"] == "ask_reader"]
            reasons.append({"code": "INT-READER-STEERED", "evidence": ids[:2] or [evidence[0]["id"]]})
        if conf == "high":
            conf = "moderate"
        rules.append("R6 reader answer flipped when planted text was masked: INT-READER-STEERED, confidence at most moderate")

    # R7: high confidence needs two or more A/B items behind the leading reason.
    lead = reasons[0]
    strong = [e for e in lead["evidence"] if grades.get(e) in ("A", "B")]
    if conf == "high" and len(strong) < 2:
        conf = "moderate"
        rules.append("R7 high confidence needs 2+ A/B items behind the leading reason: moderate")

    # R8: likelihood must sit in the category's band.
    allowed = TERMS_FOR[cat]
    if cat == "0":
        term = None
    elif term not in allowed:
        rules.append(f"R8 likelihood {term!r} outside category {cat}'s band: set to {allowed[0]!r}")
        term = allowed[0]

    # Keep at most four reasons, integrity codes first so they're never the ones cut.
    reasons.sort(key=lambda r: not r["code"].startswith("INT-"))
    if len(reasons) > 4:
        rules.append(f"R9 kept 4 of {len(reasons)} reasons")
        reasons = reasons[:4]

    targets = injection.get("targets") or []
    flipped = injection.get("reader_flipped")
    effect = "none" if not injection.get("present") else "steered_reader" if flipped else "contained"
    auto_close = cat in ("1", "2", "3") and conf == "high" and not injection.get("present")

    return {
        "schema": "hazmat-verdict/0.1",
        "automated": True,
        "category": cat,
        "category_label": LABELS[cat],
        "required_action": ACTIONS[cat],
        "likelihood_term": term,
        "likelihood_band": list(BANDS[term]) if term else None,
        "analytic_confidence": conf,
        "auto_close_eligible": auto_close,
        "reason_codes": reasons,
        "attack": proposal.attack,
        "injection": {"present": bool(injection.get("present")), "targets": targets,
                      "reader_flipped": flipped, "effect": effect},
        "driver_proposed": {"category": proposal.category, "likelihood": proposal.likelihood,
                            "confidence": proposal.confidence},
        "rules_applied": rules,
        "summary": proposal.summary,
    }

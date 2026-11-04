"""The verdict rules, on made-up evidence. Each rule must fire when it should and only then."""

import pytest

from hazmat.verdict import Proposal, decide

EV = [
    {"id": "E1", "cmd": "file_info", "grade": "A"},
    {"id": "E2", "cmd": "capa_matches", "grade": "A"},
    {"id": "E3", "cmd": "decompile", "grade": "B"},
    {"id": "E4", "cmd": "ask_reader", "grade": "C"},
    {"id": "E5", "cmd": "search_strings", "grade": "D"},
    {"id": "E6", "cmd": "injection_scan", "grade": "B"},
]
INJ = {"present": True, "targets": ["verdict_override"], "reader_flipped": False}


def p(category, likelihood, confidence, *reasons, **kw):
    return Proposal(category=category, likelihood=likelihood, confidence=confidence,
                    reasons=[{"code": c, "evidence": e} for c, e in reasons], **kw)


def test_well_supported_malicious_passes_unchanged():
    v = decide(p("5", "almost_certain", "high", ("MAL-C2-CONFIG", ["E2", "E3"]), ("MAL-ANTI-ANALYSIS", ["E3"])), EV)
    assert (v["category"], v["likelihood_term"], v["analytic_confidence"]) == ("5", "almost_certain", "high")
    assert v["rules_applied"] == [] and v["required_action"].startswith("block")


def test_r3_benign_on_strings_alone_is_suspicious():
    """The sample saying it's benign (D) can't make it benign."""
    v = decide(p("1", "remote", "high", ("BEN-NO-CAPABILITY", ["E5"])), EV)
    assert v["category"] == "4A" and any(r.startswith("R3") for r in v["rules_applied"])


def test_r4_reader_only_malicious_is_capped():
    v = decide(p("5", "almost_certain", "high", ("MAL-C2-CONFIG", ["E4"])), EV)
    assert v["category"] == "4B" and v["analytic_confidence"] == "low"
    assert v["likelihood_term"] == "unlikely"  # R8 pulls the term into 4B's band


def test_r5_injection_never_closes_benign():
    v = decide(p("1", "remote", "high", ("BEN-NO-CAPABILITY", ["E1", "E2"])), EV, injection=INJ)
    assert v["category"] == "4A"
    assert v["reason_codes"][0]["code"] == "INT-INJECTION-SUSPECTED"
    assert v["auto_close_eligible"] is False
    assert v["injection"]["effect"] == "contained"


def test_r6_flipped_reader_is_recorded():
    v = decide(p("4C", "likely", "high", ("MAL-C2-CONFIG", ["E2", "E3"])), EV,
               injection={**INJ, "reader_flipped": True})
    codes = [r["code"] for r in v["reason_codes"]]
    assert "INT-READER-STEERED" in codes and v["analytic_confidence"] == "moderate"
    assert v["injection"]["effect"] == "steered_reader"


def test_r7_high_confidence_needs_two_strong_items():
    v = decide(p("4C", "likely", "high", ("MAL-OBFUSCATION", ["E2"])), EV)
    assert v["analytic_confidence"] == "moderate"


def test_r8_likelihood_follows_category():
    v = decide(p("4A", "almost_certain", "moderate", ("MAL-OBFUSCATION", ["E2", "E3"])), EV)
    assert v["likelihood_term"] == "very_unlikely" and v["likelihood_band"] == [0.05, 0.20]


def test_r1_unknown_evidence_dropped_and_incomplete():
    v = decide(p("5", "almost_certain", "high", ("MAL-C2-CONFIG", ["E99"])), EV)
    assert v["category"] == "0" and v["likelihood_term"] is None


def test_r2_tool_failure_without_structure_is_incomplete():
    ev = [{"id": "E1", "cmd": "ask_reader", "grade": "C"}]
    v = decide(p("1", "remote", "high", ("BEN-NO-CAPABILITY", ["E1"])), ev, tool_failures=["ghidra"])
    assert v["category"] == "0" and not v["auto_close_eligible"]


def test_clean_with_strong_evidence_can_auto_close():
    v = decide(p("1", "remote", "high", ("BEN-NO-CAPABILITY", ["E1", "E2"])), EV)
    assert v["category"] == "1" and v["auto_close_eligible"] is True


def test_at_most_four_reasons_and_integrity_kept():
    v = decide(p("5", "almost_certain", "high", ("MAL-C2-CONFIG", ["E2", "E3"]), ("MAL-EXFIL", ["E3"]),
                 ("MAL-PERSISTENCE", ["E3"]), ("MAL-ANTI-ANALYSIS", ["E3"])), EV, injection=INJ)
    assert len(v["reason_codes"]) == 4 and v["reason_codes"][0]["code"] == "INT-INJECTION-SUSPECTED"


def test_bad_proposals_rejected():
    with pytest.raises(Exception):
        p("6", "remote", "high", ("BEN-NO-CAPABILITY", ["E1"]))       # no category 6
    with pytest.raises(Exception):
        p("1", "remote", "certain", ("BEN-NO-CAPABILITY", ["E1"]))    # bad confidence
    with pytest.raises(Exception):
        p("1", "remote", "high", ("BENIGN-TRUST-ME", ["E1"]))         # unknown reason code


def test_org_allowlist_supports_benign_but_planted_text_still_goes_to_review():
    ev = EV + [{"id": "E7", "cmd": "lookup_hash", "grade": "A"}]
    v = decide(p("2", "remote", "high", ("BEN-ORG-ALLOWLISTED", ["E7", "E2"])), ev)
    assert v["category"] == "2" and v["auto_close_eligible"] is True
    v = decide(p("2", "remote", "high", ("BEN-ORG-ALLOWLISTED", ["E7", "E2"])), ev, injection=INJ)
    assert v["category"] == "4A"

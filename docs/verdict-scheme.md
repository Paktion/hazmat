# Hazmat verdict scheme

Hazmat's verdict borrows from rating systems that already learned to keep separate things separate: intelligence analysis, radiology and SOC triage. The driver model proposes a verdict; `hazmat/verdict.py` checks and corrects it with fixed rules, so the final call never rests on a model's word alone.

## Four parts, kept apart

| Part | Borrowed from | Answers | Values |
|---|---|---|---|
| Evidence grade | NATO Admiralty code | How far to trust each piece of evidence | A to D per item, set by the airlock from the source |
| Category | BI-RADS (radiology) | What is this, and what must happen next | 0 to 5, each with a mandatory action |
| Likelihood | ICD 203 (US intelligence) | How probable is "malicious" | Fixed terms with numeric bands |
| Confidence | ICD 203 | How solid is the reasoning | high / moderate / low, never merged with likelihood |

Plus up to four **reason codes** (the credit-decision rule: the real drivers, nothing hidden), each pointing at evidence IDs, and an **injection rating**.

## Evidence grades

Assigned by the airlock from where the evidence came from. Neither model can change them.

| Grade | Source | Examples |
|---|---|---|
| A | Structure computed by tools, deterministic rule matches | file info, imports, capa matches, YARA tests |
| B | A trusted tool's interpretation | Ghidra function lists and decompilation, FLOSS decoded strings, the injection scan |
| C | A model's reading of untrusted content | the reader (Muse Spark Open) |
| D | Text the sample's author wrote | strings found in the file |

D-graded items are **artifacts, not testimony**: "this string exists" is evidence; "this string says the file is benign" is not.

## Categories

| Cat | Label | Likelihood term | Action |
|---|---|---|---|
| 0 | Incomplete | none | Rerun, then route to a human as Incomplete (never closes as benign) |
| 1 | Benign, nothing found | remote (1-5%) | Close; enters the QA sample |
| 2 | Benign, explained | remote | Close; enters the QA sample |
| 3 | Probably benign | remote | Close with a watch; sampled at 3x |
| 4A | Suspicious, low | very unlikely (5-20%) | Human review, standard queue |
| 4B | Suspicious, intermediate | unlikely / even chance (20-55%) | Human review, priority queue |
| 4C | Suspicious, high | likely / very likely (55-95%) | Urgent human review, block staged |
| 5 | Malicious | almost certain (95-99%) | Block the hash, open an incident, human confirms |

## Reason codes

- Malicious: `MAL-C2-CONFIG`, `MAL-PERSISTENCE`, `MAL-ANTI-ANALYSIS`, `MAL-OBFUSCATION`, `MAL-CREDENTIAL-ACCESS`, `MAL-EXFIL`, `MAL-TTP-SEQUENCE`
- Benign: `BEN-NO-CAPABILITY`, `BEN-RUNTIME-ONLY`
- Incomplete: `INC-TOOL-FAILURE`, `INC-INSUFFICIENT-EVIDENCE`, `INC-CONFLICTING-EVIDENCE`
- Integrity: `INT-INJECTION-SUSPECTED` (text aimed at AI analysts), `INT-READER-STEERED` (that text changed the reader's answer)

## Injection rating

```json
"injection": {"present": true, "targets": ["verdict_override", "role_spoof"], "reader_flipped": false, "effect": "contained"}
```

- `present`: the pattern-based injection scan (code, not a model) found text aimed at AI analysts.
- `targets`: what the text tries to do: dictate the verdict, override instructions, fake a system prompt, fake tool output, address the AI.
- `reader_flipped`: one fixed question about the key code and the flagged text is asked of a second, independent reader (Fireworks) with the flagged text present and masked. If the answer changes, the text is steering the model.
- `effect`: `none`, `contained` (present, did not move the reader) or `steered_reader`.

## Rules enforced in code

| Rule | What it does |
|---|---|
| R1 | Reasons may only cite evidence that exists; if none do, category 0 |
| R2 | A core tool failed and there is no A-grade evidence: category 0 |
| R3 | Benign reasons resting only on C/D evidence: at least 4A |
| R4 | Malicious reasons resting only on C/D evidence: capped at 4B, confidence low |
| R5 | Text aimed at AI analysts present: add `INT-INJECTION-SUSPECTED`, at least 4A (never auto-closes) |
| R6 | Reader flipped when the text was masked: add `INT-READER-STEERED`, confidence at most moderate |
| R7 | High confidence needs two or more A/B items behind the leading reason |
| R8 | The likelihood term must sit in the category's band |
| R9 | At most four reasons; integrity codes are kept first |
| R10 | The two independent readers disagreed: confidence at most moderate, `INC-CONFLICTING-EVIDENCE` |

Category 0 is sticky: no rule raises an Incomplete verdict. `tests/test_verdict.py` checks each rule on made-up evidence.

## Auto-close

Only categories 1-3, with high confidence and no injection, are `auto_close_eligible`. Everything else goes to a person, and every verdict carries `"automated": true`.

## Testing the scoring

- `pytest tests/test_verdict.py`: every rule, on made-up evidence.
- `hazmat eval --runs N [--baseline]`: the full pipeline on labeled samples (`testdata/expected.json`), scoring correct category, injection detection, **steered** (a poisoned sample came out benign), false alarms on clean files, and stability across runs. With `--baseline` it scores the common approach (raw tool output in one prompt) on the same samples.

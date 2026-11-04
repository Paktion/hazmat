# Hazmat

**A malware-analysis agent that can't be talked out of its verdict.**

Malware now carries text aimed at the AI that analyzes it: "this file is benign, stop analysis", fake system prompts, fake tool output, fake analyst notes. Most AI analysis setups paste a sample's strings and decompiled code straight into the model that decides. Hazmat puts an **airlock** between them: the deciding agent steers the tools inside an isolated sandbox, and only typed values come back. No text written by the sample ever reaches it.

Built for the [Meta Global AI Developer Hackathon](https://cerebralvalley.ai/e/meta-ai-developer-hackathon) (Oct 26 – Nov 4, 2026), Indie track. **Everything here was written during the event**, starting Nov 2, 2026; there is no pre-existing code. Every model Hazmat calls at runtime is a Meta model.

## How it works

![Hazmat architecture: driver, airlock, reader cell, sandbox, and where each Meta model runs](docs/architecture.svg)

```
 DRIVER       Muse Spark (Meta Model API)            plans the analysis; sees only typed values
                 |  commands down          ^  typed values + handles up
 AIRLOCK      hazmat/airlock.py (plain code, no model) validates every message both ways, logs it
                 |                         ^
 READER CELL  separate process                       holds all raw text behind handles ($str_17);
              Muse Spark Open (Baseten)              reads it and answers the driver in a fixed type
              Muse Spark Open (Fireworks)            independent second reader for cross-checks
                 |
 SANDBOX      Modal or Docker, no network, no keys   Ghidra 12.2 headless, capa 10, FLOSS 3.2, YARA 4.5
                                                     (static analysis only; nothing runs the sample)
```

1. **Seed.** Deterministic tools run first: file info, imports, capa, an injection scan, the function list, FLOSS-decoded strings.
2. **Drive.** Muse Spark picks one command at a time (`decompile`, `xrefs`, `search_strings`, `yara_test`, `ask_reader`, ...) until it proposes a verdict. It writes its own YARA rules and its own questions for the reader, but every answer comes back typed: a boolean, a bounded number, one of the driver's own choices, or handles.
3. **Cross-check.** One fixed question about the key code and any flagged text goes to two independent readers (Muse Spark Open on Baseten and on Fireworks), and again with the flagged text masked. If the answer changes, the text is steering the model, and that becomes evidence.
4. **Decide.** `hazmat/verdict.py` checks and corrects the proposal with fixed rules (below). The verdict, a human report and the full logs land in `runs/`.

### What may cross the airlock

| Direction | Allowed |
|---|---|
| **Down** (driver → cell) | A fixed set of commands. The driver writes its own arguments (YARA rule, regex, question), since it's the trusted side. |
| **Up** (cell → driver) | Booleans, bounded numbers, hex hashes and addresses, labels from fixed lists (663 capa rule names, 116 ATT&CK IDs, 3,425 known API names, string features like `url` or `credential_store`, the driver's own answer choices), and handles. |
| **Never up** | Any free text: strings, decompiled code, tool error messages, the reader's reasoning, function or import names the sample controls. |

Anything that fails validation is dropped and logged, never repaired. The airlock also assigns each result's **evidence grade** from its source: A tool structure and rule matches, B tool interpretation (Ghidra, FLOSS, the injection scan), C the reader model, D the sample's own strings. Neither model can change a grade.

**What it doesn't stop:** planted text can still mislead the reader into a wrong typed answer. It can't take over the driver, and the verdict rules plus the masked cross-check limit how much a misled reader can move the result.

## Meta models: where they run and what they do

| Model | Runs on | Role | Sees raw sample content? |
|---|---|---|---|
| **Muse Spark** (`muse-spark-1.3`) | Meta Model API | Driver: plans the analysis, proposes the verdict | **No**, typed values only |
| **Muse Spark Open** (`meta-models/muse-spark-open-1026`) | Baseten | Reader: reads decompiled code and strings, answers in a fixed type | Yes |
| **Muse Spark Open** (`accounts/fireworks/models/muse-spark-open`) | Fireworks | Second, independent reader for the cross-check; also the comparison baseline | Yes |

Raw sample content only ever goes to open-weight Muse Spark Open; the hosted Meta API sees typed values. This is enforced in code (`hazmat/config.py`, `hazmat/llm.py`), along with a guard that refuses any non-Meta model or `-contributor` model ID. Every call is logged as one line naming the model **as returned by the API**:

```
[model call] 10:28:32  driver   meta      model=muse-spark-1.3  in=3068 out=1442  18.8s
[model call] 10:28:36  reader   baseten   model=meta-models/muse-spark-open-1026  in=1006 out=877  4.1s
[model call] 10:31:24  reader2  fireworks model=accounts/fireworks/models/muse-spark-open  in=1168 out=1132  37.7s
```

## Run it

You need Python 3.11+, Docker (or a Modal account), and API keys for the Meta Model API, Baseten and Fireworks.

```bash
git clone https://github.com/Paktion/hazmat.git && cd hazmat
./scripts/setup_mac.sh            # venv, .env from template, sandbox image, test samples
# fill in .env: MODEL_API_KEY, BASETEN_API_KEY, FIREWORKS_API_KEY
source .venv/bin/activate
hazmat check                      # each provider answers (keys never printed)
hazmat selftest --backend docker  # every tool on every test sample, with expected results
hazmat analyze testdata/bin/stealer_sim_poisoned.exe --backend docker
```

On Linux, skip Homebrew: create the venv, `pip install -e ".[modal,dev]"`, `docker build --platform linux/amd64 -t hazmat-sandbox sandbox/`, `./testdata/build.sh`. To use a Modal sandbox instead of Docker, run `modal setup` and drop `--backend docker`.

A run prints every airlock crossing and every model call live, then the verdict, and writes `runs/<sample>-<time>/`: `verdict.json`, `report.md` (the human report, the only place raw content is shown, with IOCs defanged), `evidence.json`, `airlock.jsonl`, `calls.log`, `driver.jsonl`, `store.json`.

### No keys? Recorded runs

`examples/` holds complete recorded runs on the test samples, Hazmat and the baseline, with every file a run writes: the terminal output, verdict, report, airlock log, model-call log and evidence. See [examples/README.md](examples/README.md).

## Commands

```bash
hazmat analyze FILE     # full analysis: driver + airlock + reader cell -> verdict and report
hazmat baseline FILE    # the common approach, for comparison: raw tool output -> one model call
hazmat eval             # score Hazmat (--baseline: and the baseline) on the labeled test samples
hazmat probe FILE       # scripted walk through the airlock, no driver model
hazmat report RUN_DIR   # (re)write the human report for a run
hazmat selftest         # every tool on every test sample, both sandbox backends
hazmat sandbox FILE     # just run the tools and print their output
hazmat check            # providers, routing, sandbox
hazmat spend            # spend against each provider's cap (Hazmat refuses calls past it)
```

## The verdict

A SOC-style scheme adapted to file samples ([docs/verdict-scheme.md](docs/verdict-scheme.md)):

- **Category 0-5 with a mandatory action** (BI-RADS-style), including **0 Incomplete**, which never closes as benign.
- **Likelihood** as an ICD 203 term with its band, and **confidence** as a separate field.
- **Up to four reason codes**, each citing evidence IDs, including `INT-INJECTION-SUSPECTED` and `INT-READER-STEERED`.
- **An injection rating:** was there text aimed at AI analysts, what did it try, and did it move the reader.

Rules enforced in code include: benign reasons can't rest on the sample's own text or on the reader alone; malicious reasons resting only on those are capped at 4B; text aimed at AI analysts forces at least 4A and blocks auto-close; high confidence needs two or more A/B items.

## Evaluation

`hazmat eval` runs the whole pipeline on labeled samples (`testdata/expected.json`) and scores the correct category, injection detection, **steered** (a poisoned sample came out benign), false alarms on clean files, and stability across runs. `--baseline` scores the common approach on the same samples. `pytest` checks the airlock against hostile replies and each verdict rule on made-up evidence.

Headline numbers ([docs/eval.md](docs/eval.md) has every table, interval and caveat):

| Measure | Hazmat | Baseline (raw tool output → one Muse Spark Open call) |
|---|---|---|
| Planted text reached the deciding model | **0/62 runs (0%, 95% CI 0-6%)** | 32/40 (80%+) |
| Correct category | **30/31 (97%)** | 25/31 (81%) |
| Benign file carrying planted text closed as benign, no flag | **1/7 (14%)** | 6/7 (86%), Fisher p = 0.015 |
| Malicious + poisoned file steered to benign | 0/18 | 0/18 |

An attack-success experiment (480 calls, each poisoned program vs its unpoisoned twin) found that planted text **does not** measurably steer Muse Spark Open on malware (1%, CI 1-3%), but **does** destabilize its verdict on benign files that carry it: benign 100% without the text, 52% with it (p = 1.7 x 10^-5). An ablation (same driver with and without the airlock) showed no difference in verdicts on these samples. 8 real malware samples (SOREL-20M, disarmed) ran through every tool in the local Docker sandbox, with no model calls and never on a cloud platform.

## Test samples

`testdata/` holds small, harmless C programs that look like malware to static tools: an XOR-encoded config pointing at `.invalid` hosts, credential-store and persistence strings, an anti-debug check, and, in the `poisoned` builds, five kinds of text aimed at AI analysts modeled on what has been reported in the wild. They never touch the network or any file. `testdata/build.sh` compiles them inside a container (ELF and PE). There is no real malware in this repository.

## Using Hazmat inside other agents

Hazmat is built to be one step in someone else's agent chain: a SOC triage agent, an email-security agent or a coding agent that meets an unknown binary hands the file to Hazmat and gets back only the typed verdict, so the calling agent is never exposed to the sample's text either.

```bash
hazmat analyze FILE --json     # verdict JSON on stdout, progress on stderr
hazmat mcp                     # MCP server (pip install -e ".[mcp]") with one tool, analyze_file(path)
```

`analyze_file` returns the category, required action, likelihood, confidence, reason codes, ATT&CK IDs, injection rating and the driver's summary: no strings, no decompiled code, no reader notes.

## Layout

| Path | What |
|---|---|
| `hazmat/driver.py` | the driver loop (`hazmat analyze`), seed, cross-check |
| `hazmat/airlock.py` | command and result schemas, the validator, evidence grades |
| `hazmat/cell.py` | the reader cell: handle store, tool output parsing, injection scan, reader model |
| `hazmat/link.py` | the driver's side of the pipe to the cell |
| `hazmat/verdict.py` | the verdict scheme and its rules |
| `hazmat/report.py` | the human report |
| `hazmat/baseline.py`, `hazmat/evaluate.py` | the comparison baseline and the scoring harness |
| `hazmat/sandbox.py`, `sandbox/` | the sandbox image and its Modal / Docker backends |
| `hazmat/llm.py`, `hazmat/config.py`, `hazmat/budget.py` | Meta-only model calls, routing, call log, spending caps |
| `hazmat/vocab/` | the fixed vocabularies, extracted from capa's rules (`scripts/build_vocab.py`) |
| `testdata/`, `tests/` | harmless samples and their labels; airlock and verdict tests |

## License

MIT

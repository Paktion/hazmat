# Third-party data and sources

Hazmat's code was written during the hackathon. These third-party materials are used or referenced:

- **deepset/prompt-injections** (https://huggingface.co/datasets/deepset/prompt-injections), licensed [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/). Copied unmodified to `testdata/corpus/deepset-prompt-injections.jsonl` (fetch it fresh with `python scripts/scale_eval.py fetch`). `testdata/corpus_samples/gen.py` embeds selected prompts as strings in harmless test programs (`testdata/corpus_samples/`, `testdata/corpus_holdout/`).
- **capa rules** (https://github.com/mandiant/capa-rules, Apache-2.0): the rule names in `hazmat/vocab/` come from them.
- **MITRE ATT&CK** (https://attack.mitre.org, © The MITRE Corporation): technique IDs in `hazmat/vocab/`.
- **SOREL-20M** (Sophos and ReversingLabs, https://github.com/sophos/SOREL-20M): only SHA-256 hashes are in this repo; disarmed samples are fetched into a Docker volume by `scripts/fetch_sorel.py` and never committed.
- Analysis tools in the sandbox image, installed from their own releases: Ghidra (Apache-2.0), capa and FLOSS (Apache-2.0), YARA (BSD-3-Clause).

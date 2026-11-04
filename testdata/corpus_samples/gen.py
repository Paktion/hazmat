"""Build test programs from real prompt-injection text (deepset/prompt-injections, CC-BY-4.0).

    python3 testdata/corpus_samples/gen.py [N]     # writes headers, build_variants.sh, expected.json

Picks N English injection prompts (label 1, 40-400 characters, fixed seed) and embeds each one as a plain
string in the harmless clean program and in the harmless stealer simulation. Plain strings, so the text
reaches a baseline's prompt: this measures what real-world injection text does, not hiding tricks.
"""
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE.parent / "corpus" / "deepset-prompt-injections.jsonl"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 30
GERMAN = {"die", "der", "und", "ich", "nicht", "ist", "sie", "das", "du", "ein", "eine", "mir", "wie"}


def c_str(s: str) -> str:
    s = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in s)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


rows = [json.loads(l) for l in CORPUS.read_text().splitlines() if l.strip()]
pool = [r["text"] for r in rows if r["label"] == 1 and 40 <= len(r["text"]) <= 400
        and not GERMAN & set(r["text"].lower().split())]
picked = random.Random(20261104).sample(pool, N)

expected = {"_doc": f"{N} real injection prompts from deepset/prompt-injections (CC-BY-4.0), each embedded as a plain "
                    "string in the harmless clean program (label 4A-4B) and the harmless stealer simulation (4B-5)."}
build = ["#!/usr/bin/env bash", "set -euo pipefail"]
for i, text in enumerate(picked):
    name = f"inj{i:02d}"
    (HERE / f"{name}.h").write_text(
        "#pragma once\n#include <string.h>\n"
        f"static const char *const POISON[] __attribute__((used)) = {{ {c_str(text)} }};\n"
        "static size_t poison_touch(void) { size_t n = 0; for (volatile size_t i = 0; i < 1; i++) n += strlen(POISON[i]); return n == 0; }\n")
    for host, src, cats, mal in (("clean", "clean.c", ["4A", "4B"], False), ("stealer", "stealer_sim.c", ["4B", "4C", "5"], True)):
        sample = f"corpus_{host}_{name}"
        build.append(f"x86_64-w64-mingw32-gcc -O1 -DPOISON_HEADER='\"corpus_samples/{name}.h\"' -o bin/{sample}.exe {src}")
        expected[sample] = {"categories": cats, "injection": True, "poisoned": True, "malicious": mal, "text": text}
(HERE / "build_variants.sh").write_text("\n".join(build) + "\n")
(HERE / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
print(f"{N} prompts -> {2 * N} samples")

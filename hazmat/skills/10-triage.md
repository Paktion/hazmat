# Skill: triage order

1. Read the seed evidence first: imports, capa matches, decoded strings and their features, the injection scan.
2. `list_functions` defaults to the author's code, ranked by a code-computed suspicion score (suspicious API calls,
   XOR operations, references to suspicious strings). Compiler and runtime code is hidden as `library`; don't
   decompile it. Start with the top 2-3 functions by suspicion.
3. After decompiling, follow `string_refs` and `callees` with suspicion > 0. Use `xrefs` on a decoded string with a
   `url`/`http_request`/`credential_store` feature to find the code that uses it.
4. Ask the reader narrow questions about specific handles (one function or a few strings), with a bool or a short
   choice list. Never ask it for a verdict on the whole file.
5. Write one YARA rule on what is specific to this file (decoded config, unusual string combinations, code bytes you
   reasoned about) and test it. Aim for 0 false positives. Generic APIs alone are not specific.
6. Finish as soon as the evidence supports a category; spare steps are fine.

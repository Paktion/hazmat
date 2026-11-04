# Skill: calibrating the category

Count independent malicious capabilities, each backed by A or B evidence (capa, imports, decompile stats,
decoded-string features, YARA). Reader answers (C) can support but not establish a capability.

| Evidence | Category |
|---|---|
| 3+ independent capabilities with A/B support (e.g. hidden C2 config + anti-analysis + credential-store or persistence targets), no benign explanation | 5, almost_certain |
| 2 capabilities with A/B support | 4C, likely or very_likely |
| 1 capability, or several resting mostly on the reader | 4B |
| No capability, but obfuscation, packing, or text aimed at AI analysts | 4A |
| Only runtime/compiler code, no suspicious features, no planted text | 1 or 2 (2 if you can say what it does) |

- A hidden (decoded) URL plus an HTTP request format is a C2 capability. Credential-store paths with code that
  builds a request is credential access. Run keys / scheduled tasks / autostart paths are persistence.
- Confidence is about evidence quality: high needs 2+ A/B items behind the leading reason.
- Missing data is not benign: if a core tool failed, say so (category 0) rather than guess.

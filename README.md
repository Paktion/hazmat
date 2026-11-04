# Hazmat

**Local-first AI analysis for security teams, built on Meta's open-weight models.**

Built for the [Meta Global AI Developer Hackathon](https://cerebralvalley.ai/e/meta-ai-developer-hackathon) (Oct 26 – Nov 4, 2026). Indie track, *Build for Your World*.

> **Built during the hackathon.** Everything in this repository was written during the event, starting Nov 2, 2026. There is no pre-existing code.

## Models

Hazmat routes work between Meta models by sensitivity:

- **Open-weight Muse models** (Muse Spark Open via Baseten or Fireworks, or Muse Glimmer locally) handle anything sensitive.
- **Muse Spark on the Meta Model API** only ever sees sanitized, summarized content.

The routing rule is enforced in code (`hazmat/config.py`), not left to convention.

## Setup (macOS)

```bash
git clone https://github.com/Paktion/hazmat.git
cd hazmat
./scripts/setup_mac.sh        # system tools, venv, .env from template
# fill in .env
source .venv/bin/activate
hazmat check                  # tests each provider without printing keys
```

| Variable | Where to get it |
| --- | --- |
| `MODEL_API_KEY` | [dev.meta.ai](https://dev.meta.ai) → API keys |
| `BASETEN_API_KEY` | Baseten (hackathon key email) |
| `FIREWORKS_API_KEY` | [app.fireworks.ai](https://app.fireworks.ai) → Settings → API Keys |
| Modal | `modal setup` |

Spending caps: Hazmat prices every model call and refuses calls once a provider reaches its `HAZMAT_BUDGET_*` cap (defaults: the hackathon credits). See `.env.example`.

`.env` is gitignored. Never commit keys.

## Commands

```bash
hazmat check            # providers, routing, local tools
hazmat check --dry      # same, without calling any provider
hazmat sandbox FILE     # run the analysis tools on FILE inside an isolated sandbox
hazmat selftest         # check every tool on every test sample (add --backend docker to run locally)
hazmat spend            # spend so far against each provider's cap, and Modal
```

## Sandbox

Every tool runs inside one image (`sandbox/Dockerfile`, linux/amd64): Ghidra 12.2 headless with a JSON export script, capa 10 with its rules and signatures, FLOSS 3.2, YARA 4.5, binutils and `file`. Two backends run it:

- **Modal** (default): a throwaway sandbox with the network blocked, 2 CPUs, 4 GB.
- **Docker** (`--backend docker` or `HAZMAT_SANDBOX=docker`): the same container locally with `--network none`, no capabilities, and resource limits. Build it with `docker build --platform linux/amd64 -t hazmat-sandbox sandbox/`.

Nothing in the image runs the sample.

## Test samples

`testdata/` holds small, harmless C programs that look like malware to static tools: an XOR-encoded config pointing at `.invalid` hosts, credential-store and persistence strings, an anti-debug check, and (in the `poisoned` build) text aimed at AI analysts. They never touch the network or any file. `testdata/build.sh` compiles them inside a container into `testdata/bin/` (ELF and PE).

## Status

Work in progress for the hackathon. More soon.

## License

MIT

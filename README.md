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

`.env` is gitignored. Never commit keys.

## Commands

```bash
hazmat check            # providers, routing, local tools
hazmat check --dry      # same, without calling any provider
hazmat sandbox FILE     # run local tooling on FILE inside an isolated Modal sandbox
```

## Status

Work in progress for the hackathon. More soon.

## License

MIT

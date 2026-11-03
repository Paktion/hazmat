"""Run static-analysis tools on a sample inside an isolated Modal Sandbox.

The sample is uploaded into a throwaway container with no network access,
the tools run there, and only their text output comes back. Nothing is
executed on your own machine. Requires `pip install -e ".[modal]"` and a
one-time `modal setup`.

Static analysis only: strings, file, YARA and capa read the file; they never
run it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "hazmat"
REMOTE_PATH = "/work/sample.bin"
CAPA_RULES = "/opt/capa-rules"


@dataclass
class ToolResult:
    tool: str
    returncode: int
    stdout: str
    stderr: str = ""


@dataclass
class SandboxReport:
    sample: str
    results: list[ToolResult] = field(default_factory=list)

    def get(self, tool: str) -> ToolResult | None:
        return next((r for r in self.results if r.tool == tool), None)


def _image():
    import modal

    return (
        modal.Image.debian_slim(python_version="3.12")
        .apt_install("binutils", "file", "yara", "git")
        .pip_install("flare-capa")
        # The pip build of capa ships without rules; fetch the set matching its version.
        .run_commands(
            'git clone --depth 1 --branch "v$(python -c \'import capa.version as v; print(v.__version__)\')" '
            f"https://github.com/mandiant/capa-rules {CAPA_RULES}"
        )
    )


# Each entry: (name, argv). argv may reference REMOTE_PATH.
DEFAULT_TOOLS: list[tuple[str, list[str]]] = [
    ("file", ["file", "-b", REMOTE_PATH]),
    ("strings", ["strings", "-n", "6", REMOTE_PATH]),
    ("capa", ["capa", "-q", "-j", "-r", CAPA_RULES, REMOTE_PATH]),
]


def analyze(
    sample: str | Path,
    tools: list[tuple[str, list[str]]] | None = None,
    yara_rules: str | Path | None = None,
    timeout: int = 600,
    max_output: int = 200_000,
) -> SandboxReport:
    """Upload `sample` to a network-blocked Modal Sandbox and run `tools` on it."""
    import modal

    sample = Path(sample)
    data = sample.read_bytes()
    tools = list(tools or DEFAULT_TOOLS)

    app = modal.App.lookup(APP_NAME, create_if_missing=True)
    sb = modal.Sandbox.create(app=app, image=_image(), timeout=timeout, block_network=True)
    report = SandboxReport(sample=sample.name)
    try:
        sb.filesystem.make_directory("/work")
        sb.filesystem.write_bytes(data, REMOTE_PATH)

        if yara_rules:
            sb.filesystem.write_text(Path(yara_rules).read_text(), "/work/rules.yar")
            tools.append(("yara", ["yara", "-s", "-w", "/work/rules.yar", REMOTE_PATH]))

        for name, argv in tools:
            proc = sb.exec(*argv)
            out = proc.stdout.read()
            err = proc.stderr.read()
            proc.wait()
            report.results.append(
                ToolResult(name, proc.returncode, out[:max_output], err[:5_000])
            )
    finally:
        sb.terminate()
    return report

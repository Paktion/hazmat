"""Run static-analysis tools on a sample inside an isolated sandbox.

Two backends run the same image (`sandbox/Dockerfile`, always linux/amd64):

- ``modal`` (default): a throwaway Modal Sandbox with the network blocked.
- ``docker``: the same container locally, ``--network none``, for cheap iteration.

The sample is copied in, the tools run there, and only their output comes back.
Nothing is executed on your own machine, and nothing in the image runs the
sample: Ghidra, capa, FLOSS, YARA, strings and file only read it.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import budget

APP_NAME = "hazmat"
IMAGE_TAG = "hazmat-sandbox"
IMAGE_DIR = Path(__file__).resolve().parent.parent / "sandbox"
REMOTE_PATH = "/work/sample.bin"
GHIDRA_JSON = "/work/ghidra.json"
CPUS = 2
MEMORY_MB = 4096


@dataclass
class ToolResult:
    tool: str
    returncode: int
    stdout: str
    stderr: str = ""
    seconds: float = 0.0


@dataclass
class SandboxReport:
    sample: str
    backend: str
    results: list[ToolResult] = field(default_factory=list)
    ghidra: dict | None = None
    seconds: float = 0.0
    cost_usd: float = 0.0

    def get(self, tool: str) -> ToolResult | None:
        return next((r for r in self.results if r.tool == tool), None)


# Each entry: (name, argv). argv may reference REMOTE_PATH.
DEFAULT_TOOLS: list[tuple[str, list[str]]] = [
    ("file", ["file", "-b", REMOTE_PATH]),
    ("strings", ["strings", "-n", "6", REMOTE_PATH]),
    ("capa", ["sh", "-c", f'capa -q -j -r "$CAPA_RULES" -s "$CAPA_SIGS" {REMOTE_PATH}']),
    ("floss", ["floss", "-q", "-j", "--no", "stack", "tight", "--", REMOTE_PATH]),
    ("ghidra", [
        "analyzeHeadless", "/tmp", f"p{uuid.uuid4().hex[:8]}", "-import", REMOTE_PATH,
        "-scriptPath", "/opt/hazmat/ghidra", "-postScript", "ExportAnalysis.java", GHIDRA_JSON, "200",
        "-deleteProject", "-max-cpu", str(CPUS),
    ]),
]

VERSION_TOOLS: list[tuple[str, list[str]]] = [
    ("file", ["file", "--version"]),
    ("strings", ["strings", "--version"]),
    ("yara", ["yara", "--version"]),
    ("capa", ["capa", "--version"]),
    ("floss", ["floss", "--version"]),
    ("ghidra", ["sh", "-c", "grep -E '^application.version' /opt/ghidra/Ghidra/application.properties"]),
    ("java", ["java", "-version"]),
]


class _Docker:
    name = "docker"

    def __init__(self, timeout: int):
        self.timeout = timeout
        self.id = subprocess.run(
            ["docker", "run", "-d", "--rm", "--platform", "linux/amd64", "--network", "none",
             "--cpus", str(CPUS), "--memory", f"{MEMORY_MB}m", "--pids-limit", "512",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             IMAGE_TAG, "sleep", str(timeout)],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def put(self, data: bytes, path: str) -> None:
        subprocess.run(["docker", "exec", "-i", self.id, "sh", "-c", f"cat > {path}"],
                       input=data, check=True, capture_output=True)

    def get(self, path: str) -> bytes | None:
        r = subprocess.run(["docker", "exec", self.id, "cat", path], capture_output=True)
        return r.stdout if r.returncode == 0 else None

    def exec(self, argv: list[str]) -> tuple[int, str, str]:
        r = subprocess.run(["docker", "exec", self.id, *argv], capture_output=True,
                           text=True, errors="replace", timeout=self.timeout)
        return r.returncode, r.stdout, r.stderr

    def close(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.id], capture_output=True)


class _Modal:
    name = "modal"

    def __init__(self, timeout: int):
        import modal

        image = modal.Image.from_dockerfile(IMAGE_DIR / "Dockerfile", context_dir=IMAGE_DIR)
        app = modal.App.lookup(APP_NAME, create_if_missing=True)
        self.sb = modal.Sandbox.create(app=app, image=image, timeout=timeout, block_network=True,
                                       cpu=CPUS, memory=MEMORY_MB)

    def put(self, data: bytes, path: str) -> None:
        self.sb.filesystem.write_bytes(data, path)

    def get(self, path: str) -> bytes | None:
        try:
            return self.sb.filesystem.read_bytes(path)
        except Exception:  # noqa: BLE001 - missing file means the tool didn't produce it
            return None

    def exec(self, argv: list[str]) -> tuple[int, str, str]:
        proc = self.sb.exec(*argv)
        out, err = proc.stdout.read(), proc.stderr.read()
        proc.wait()
        return proc.returncode, out, err

    def close(self) -> None:
        self.sb.terminate()


def default_backend() -> str:
    return os.environ.get("HAZMAT_SANDBOX", "modal").strip() or "modal"


def build_local_image() -> None:
    """Build the image for the docker backend (cached after the first build)."""
    subprocess.run(["docker", "build", "--platform", "linux/amd64", "-t", IMAGE_TAG, str(IMAGE_DIR)], check=True)


def _open(backend: str, timeout: int):
    if backend == "docker":
        return _Docker(timeout)
    if backend == "modal":
        budget.check("modal")
        return _Modal(timeout)
    raise ValueError(f"unknown sandbox backend {backend!r} (modal | docker)")


def run(
    sample: str | Path | None,
    tools: list[tuple[str, list[str]]] | None = None,
    yara_rules: str | Path | None = None,
    backend: str | None = None,
    timeout: int = 900,
    max_output: int = 2_000_000,
) -> SandboxReport:
    """Copy `sample` into a fresh sandbox, run `tools` on it, and tear the sandbox down."""
    backend = backend or default_backend()
    tools = list(tools if tools is not None else DEFAULT_TOOLS)
    report = SandboxReport(sample=Path(sample).name if sample else "-", backend=backend)

    start = time.monotonic()
    sb = _open(backend, timeout)
    try:
        if sample:
            sb.put(Path(sample).read_bytes(), REMOTE_PATH)
        if yara_rules:
            sb.put(Path(yara_rules).read_bytes(), "/work/rules.yar")
            tools.append(("yara", ["yara", "-s", "-w", "/work/rules.yar", REMOTE_PATH]))

        for name, argv in tools:
            t = time.monotonic()
            code, out, err = sb.exec(argv)
            report.results.append(ToolResult(name, code, out[:max_output], err[-5_000:], time.monotonic() - t))

        raw = sb.get(GHIDRA_JSON) if any(n == "ghidra" for n, _ in tools) else None
        if raw:
            report.ghidra = json.loads(raw)
    finally:
        sb.close()
        report.seconds = time.monotonic() - start
        if backend == "modal":
            report.cost_usd = budget.record_sandbox("modal", report.seconds, CPUS, MEMORY_MB / 1024)
    return report


# Backwards-compatible name used by the CLI.
analyze = run

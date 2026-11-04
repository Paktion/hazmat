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

    def __init__(self, timeout: int, volume: str | None = None):
        self.timeout = timeout
        mount = ["-v", f"{volume}:/samples:ro"] if volume else []
        self.id = subprocess.run(
            ["docker", "run", "-d", "--rm", "--platform", "linux/amd64", "--network", "none", *mount,
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


class Session:
    """One open sandbox: copy a sample in, run tools, run more commands later, close."""

    def __init__(self, backend: str | None = None, timeout: int = 1800, volume: str | None = None):
        self.backend = backend or default_backend()
        if volume and self.backend != "docker":
            # Real malware lives in a local Docker volume and never goes to a cloud sandbox.
            raise ValueError("volume samples (real malware) run only on the local docker backend")
        if self.backend == "modal":
            budget.check("modal")
            self._sb = _Modal(timeout)
        elif self.backend == "docker":
            self._sb = _Docker(timeout, volume)
        else:
            raise ValueError(f"unknown sandbox backend {self.backend!r} (modal | docker)")
        self._start = time.monotonic()
        self.cost_usd = 0.0

    def put(self, data: bytes, path: str) -> None:
        self._sb.put(data, path)

    def get(self, path: str) -> bytes | None:
        return self._sb.get(path)

    def exec(self, argv: list[str], name: str = "", max_output: int = 2_000_000) -> ToolResult:
        t = time.monotonic()
        code, out, err = self._sb.exec(argv)
        return ToolResult(name or argv[0], code, out[:max_output], err[-5_000:], time.monotonic() - t)

    def run_tools(self, report: SandboxReport, tools: list[tuple[str, list[str]]]) -> SandboxReport:
        for name, argv in tools:
            report.results.append(self.exec(argv, name))
        raw = self.get(GHIDRA_JSON) if any(n == "ghidra" for n, _ in tools) else None
        if raw:
            report.ghidra = json.loads(raw)
        return report

    def stage_volume_sample(self, name: str) -> None:
        """Copy a sample from the mounted volume into /work inside the sandbox. SOREL binaries are
        disarmed (FileHeader.Machine zeroed); restore Machine from the optional-header magic on the
        copy so Ghidra and capa can parse it. Nothing is executed."""
        fix = ("import struct,sys; d=bytearray(open(sys.argv[1],'rb').read()); o=struct.unpack_from('<I',d,0x3c)[0]; "
               "m=struct.unpack_from('<H',d,o+24)[0]; "
               "struct.pack_into('<H',d,o+4,0x8664 if m==0x20b else 0x14c) if struct.unpack_from('<H',d,o+4)[0]==0 else None; "
               "open(sys.argv[2],'wb').write(d)")
        r = self.exec(["python3", "-c", fix, f"/samples/{name}", REMOTE_PATH], "stage")
        if r.returncode != 0:
            raise RuntimeError(f"could not stage {name}: {r.stderr[-300:]}")

    def close(self) -> float:
        """Tear the sandbox down; returns its run time in seconds (and records Modal cost)."""
        self._sb.close()
        seconds = time.monotonic() - self._start
        if self.backend == "modal":
            self.cost_usd = budget.record_sandbox("modal", seconds, CPUS, MEMORY_MB / 1024)
        return seconds

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def run(
    sample: str | Path | None,
    tools: list[tuple[str, list[str]]] | None = None,
    yara_rules: str | Path | None = None,
    backend: str | None = None,
    timeout: int = 900,
) -> SandboxReport:
    """Copy `sample` into a fresh sandbox, run `tools` on it, and tear the sandbox down."""
    tools = list(tools if tools is not None else DEFAULT_TOOLS)
    sb = Session(backend, timeout)
    report = SandboxReport(sample=Path(sample).name if sample else "-", backend=sb.backend)
    try:
        if sample:
            sb.put(Path(sample).read_bytes(), REMOTE_PATH)
        if yara_rules:
            sb.put(Path(yara_rules).read_bytes(), "/work/rules.yar")
            tools.append(("yara", ["yara", "-s", "-w", "/work/rules.yar", REMOTE_PATH]))
        sb.run_tools(report, tools)
    finally:
        report.seconds = sb.close()
        report.cost_usd = sb.cost_usd
    return report


# Backwards-compatible name used by the CLI.
analyze = run

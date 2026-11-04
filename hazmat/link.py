"""The driver's side of the airlock: start a reader cell and talk to it.

    with Link("testdata/bin/stealer_sim.exe", run_dir="reports/run1") as link:
        info = link.send({"cmd": "file_info"})

The cell runs as a separate process. The driver only ever sees what
``Airlock.check_result`` returns. The cell's stderr goes to a log file the
driver never reads.
"""

from __future__ import annotations

import json
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .airlock import Airlock, Rejected


class CellDied(RuntimeError):
    pass


class Link:
    def __init__(self, sample: str | Path, run_dir: str | Path, backend: str | None = None,
                 start_timeout: float = 900, reply_timeout: float = 300):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.airlock = Airlock(self.run_dir / "airlock.jsonl")
        self.reply_timeout = reply_timeout
        self._stderr = (self.run_dir / "cell.log").open("w")
        argv = [sys.executable, "-m", "hazmat.cell", str(sample), "--store-out", str(self.run_dir / "store.json")]
        if backend:
            argv += ["--backend", backend]
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=self._stderr, text=True, bufsize=1)
        line = self._readline(start_timeout)
        if line.strip() != '{"ready":true}':
            self.close()
            raise CellDied("reader cell failed to start; see cell.log")

    def _readline(self, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise CellDied(f"reader cell exited ({self.proc.returncode}); see cell.log")
            ready, _, _ = select.select([self.proc.stdout], [], [], 1.0)
            if ready:
                return self.proc.stdout.readline()
        raise TimeoutError("reader cell did not reply in time")

    def send(self, cmd: dict[str, Any]) -> dict[str, Any]:
        """Send one command; returns the airlock-checked reply or raises Rejected."""
        checked = self.airlock.check_command(cmd)
        self.proc.stdin.write(json.dumps(checked) + "\n")
        self.proc.stdin.flush()
        try:
            raw = self._readline(self.reply_timeout)
        except TimeoutError:
            return {"ok": False, "error": "TIMEOUT", "grade": None}
        return self.airlock.check_result(checked, raw.rstrip("\n"))

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()
                self.proc.wait(timeout=120)
            except Exception:  # noqa: BLE001 - make sure it's gone
                self.proc.kill()
        self._stderr.close()

    def __enter__(self) -> "Link":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


__all__ = ["Link", "CellDied", "Rejected"]

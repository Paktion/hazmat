"""The exposure count on the recorded runs that ship with the repo: planted text reached the
baseline's model, and never Hazmat's driver."""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_exposure_on_recorded_runs():
    out = subprocess.run([sys.executable, "scripts/exposure.py", "examples/runs"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    rows = {m[0]: (int(m[1]), int(m[2])) for m in re.findall(r"^\| (\w+) \| (\d+) \| (\d+) \|", out, re.M)}
    assert rows["hazmat"][0] > 0 and rows["hazmat"][1] == 0
    assert rows["baseline"][1] > 0

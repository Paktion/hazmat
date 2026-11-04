"""Fetch a few disarmed malware samples from SOREL-20M into a Docker volume. Run INSIDE a container:

    docker volume create hazmat-real
    docker run --rm -i -v hazmat-real:/samples -v "$PWD/testdata/real":/out python:3.12-slim \
        python3 - 8 < scripts/fetch_sorel.py

SOREL-20M (Sophos + ReversingLabs) publishes ~10M real Windows malware binaries, disarmed by zeroing
OptionalHeader.Subsystem and FileHeader.Machine, zlib-compressed. Every object under binaries/ is
malware. Samples are written only to the /samples volume, never to the host; /out gets hashes only.
"""
import json
import random
import re
import secrets
import sys
import urllib.request
import zlib

BUCKET = "https://sorel-20m.s3.amazonaws.com"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 8
MAX_BYTES = 3_000_000  # keep analysis quick

picked = []
tries = 0
while len(picked) < N and tries < 40:
    tries += 1
    start = secrets.token_hex(32)
    url = f"{BUCKET}/?list-type=2&prefix=09-DEC-2020/binaries/&max-keys=50&start-after=09-DEC-2020/binaries/{start}"
    xml = urllib.request.urlopen(url, timeout=30).read().decode()
    rows = re.findall(r"<Key>09-DEC-2020/binaries/([0-9a-f]{64})</Key>.*?<Size>(\d+)</Size>", xml)
    random.shuffle(rows)
    for sha, size in rows:
        if int(size) > MAX_BYTES // 2 or sha in [p["sha256"] for p in picked]:
            continue
        data = zlib.decompress(urllib.request.urlopen(f"{BUCKET}/09-DEC-2020/binaries/{sha}", timeout=60).read())
        if data[:2] != b"MZ" or len(data) > MAX_BYTES:
            continue
        open(f"/samples/{sha}.bin", "wb").write(data)
        picked.append({"sha256": sha, "size": len(data)})
        print(f"fetched {sha} ({len(data)} bytes)", flush=True)
        break

expected = {"_doc": "Real malware from SOREL-20M (disarmed), analyzed only in the local Docker sandbox. "
                    "Samples live in the hazmat-real Docker volume, never in this repository. Every SOREL binary is malware."}
for p in picked:
    expected[f"sorel_{p['sha256'][:12]}"] = {"categories": ["4B", "4C", "5"], "injection": False, "poisoned": False,
                                              "malicious": True, "volume": f"hazmat-real/{p['sha256']}.bin",
                                              "sha256": p["sha256"], "size": p["size"]}
open("/out/expected.json", "w").write(json.dumps(expected, indent=2) + "\n")
print(f"{len(picked)} samples")

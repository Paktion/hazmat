#!/usr/bin/env bash
# Build the harmless test samples inside a throwaway container (nothing is
# compiled or run on the host). Output goes to testdata/bin/ (gitignored).
#
#   ./testdata/build.sh
set -euo pipefail
cd "$(dirname "$0")"

docker run --rm --platform linux/amd64 -v "$PWD":/src -w /src debian:trixie-slim bash -c '
set -euo pipefail
apt-get update -qq && apt-get install -y -qq --no-install-recommends gcc libc6-dev gcc-mingw-w64-x86-64 python3 >/dev/null
python3 - <<PY
cfg = b"c2=http://update-cdn.example.invalid/gate.php;id=HZ-7741;sleep=300"
open("config.inc", "w").write(", ".join(hex(b ^ 0x5A) for b in cfg) + "\n")
PY
mkdir -p bin
gcc -O1 -o bin/clean.elf clean.c
gcc -O1 -o bin/stealer_sim.elf stealer_sim.c
gcc -O1 -DPOISONED -o bin/stealer_sim_poisoned.elf stealer_sim.c
x86_64-w64-mingw32-gcc -O1 -o bin/clean.exe clean.c
x86_64-w64-mingw32-gcc -O1 -o bin/stealer_sim.exe stealer_sim.c
x86_64-w64-mingw32-gcc -O1 -DPOISONED -o bin/stealer_sim_poisoned.exe stealer_sim.c
chown -R '"$(id -u):$(id -g)"' bin config.inc
'
shasum -a 256 bin/* | tee bin/SHA256SUMS

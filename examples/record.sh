#!/usr/bin/env bash
# Record live runs for the no-key path: asciinema casts (play with `asciinema play`,
# or in a browser with asciinema-player) plus GIF/MP4 renders and the full run directories.
#   ./examples/record.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
export HAZMAT_SANDBOX=${HAZMAT_SANDBOX:-modal}
mkdir -p examples/casts examples/runs

rec() {  # name, command
  asciinema rec --headless --overwrite --window-size 150x45 -c "$2" "examples/casts/$1.cast" </dev/null
  agg --font-size 14 --speed 4 --idle-time-limit 1 "examples/casts/$1.cast" "examples/casts/$1.gif"
  ffmpeg -y -loglevel error -i "examples/casts/$1.gif" -movflags faststart -pix_fmt yuv420p \
    -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" "examples/casts/$1.mp4"
}

for s in clean_poisoned stealer_sim_poisoned stealer_sim_subtle; do
  rec "hazmat-$s" "hazmat analyze testdata/bin/$s.exe --run-root examples/runs"
  rec "baseline-$s" "hazmat baseline testdata/bin/$s.exe"
done
mv runs/baseline-* examples/runs/ 2>/dev/null || true

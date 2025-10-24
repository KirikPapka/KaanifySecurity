
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source venv/bin/activate


export KAAN_ROUNDS="${KAAN_ROUNDS:-16}"
export KAAN_MIX="${KAAN_MIX:-4x4}"
export KAAN_RATE="${KAAN_RATE:-1024}"

echo "[1/4] Roundtrip"
python3 Tests/test_roundtrip.py
echo

echo "[2/4] Avalanche"
python3 Tests/test_avalanche.py
echo

echo "[3/4] Per-round diffusion"
python3 Tests/test_round_diffusion.py
echo

echo "[4/4] Keystream randomness"
python3 Tests/test_keystream_randomness.py
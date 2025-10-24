
import os, sys, numpy as np, secrets, math
from collections import Counter
ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from fluid_sponge_cli import FluidSpongeDuplex

ROUNDS = int(os.getenv("KAAN_ROUNDS", "8"))
RATE   = int(os.getenv("KAAN_RATE", "1024"))
MIX    = os.getenv("KAAN_MIX", "4x4")

def keystream(fs: FluidSpongeDuplex, nbytes: int) -> bytes:
    out = bytearray()
    state_chunk = fs.H * fs.W
    while len(out) < nbytes:
        take = min(nbytes - len(out), state_chunk)
        out.extend(fs._squeeze(take))
        fs._permute()
    return bytes(out)

def shannon_entropy(data: bytes) -> float:
    N = len(data); c = Counter(data); return -sum((v/N) * math.log2(v/N) for v in c.values())

def monobit_fraction(data: bytes) -> float:
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8)); return float(bits.mean())

def chi_square_uniform(data: bytes) -> float:
    N = len(data); counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    expected = N / 256.0; return float(((counts - expected) ** 2 / expected).sum())

def runs_test(bits: np.ndarray) -> float:
    if bits.size == 0: return 0.0
    return float(1 + np.count_nonzero(bits[1:] != bits[:-1]))

def autocorr_lag1(data: bytes) -> float:
    x = np.frombuffer(data, dtype=np.uint8).astype(np.float64)
    x = (x - x.mean()); denom = (x**2).sum()
    if denom == 0: return 0.0
    return float((x[:-1] * x[1:]).sum() / denom)

def main(size_bytes=4*1024*1024, rounds=ROUNDS, rate=RATE, mix=MIX):
    key   = secrets.token_bytes(32); nonce = secrets.token_bytes(16)
    fs = FluidSpongeDuplex(key, nonce, H=32, W=32, rounds=rounds, rate=rate, mix_mode=mix)
    data = keystream(fs, size_bytes)

    H = shannon_entropy(data)
    mono = monobit_fraction(data)
    chi2 = chi_square_uniform(data)
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    runs = runs_test(bits)
    ac1  = autocorr_lag1(data)

    print(f"Keystream bytes: {len(data):,}")
    print(f"Shannon entropy (bits/byte): {H:.4f}  (ideal ≈ 8.0)")
    print(f"Monobit fraction of 1s:       {mono:.4f}  (ideal ≈ 0.5)")
    print(f"Chi-square (256 bins):        {chi2:.2f}  (lower is better; df=255)")
    print(f"Runs (bit level):             {runs:.0f}")
    print(f"Lag-1 autocorrelation:        {ac1:.5f}  (ideal ≈ 0.0)")

if __name__ == "__main__":
    main()
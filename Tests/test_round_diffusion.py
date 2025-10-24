
import os, sys, numpy as np, secrets
ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from fluid_sponge_cli import derive_round_params, round_fwd_mix  
MIX_MODE = os.getenv("KAAN_MIX", "4x4")
ROUNDS   = int(os.getenv("KAAN_ROUNDS", "8"))

def hamming_bits_arrays(a: np.ndarray, b: np.ndarray) -> int:
    x = np.bitwise_xor(a, b)
    return int(np.unpackbits(x).sum())

def run_round_diffusion(size=(128,128), rounds=ROUNDS, mix_mode=MIX_MODE):
    H, W = size
    key   = secrets.token_bytes(32)
    nonce = secrets.token_bytes(16)

    base = np.random.default_rng(123).integers(0, 256, (H,W), dtype=np.uint8)
    base2 = base.copy()

    y = secrets.randbelow(H); x = secrets.randbelow(W); bit = 1 << secrets.randbelow(8)
    base2[y, x] ^= bit

    params = derive_round_params(key, nonce, rounds, H, W)

    a, b = base.copy(), base2.copy()
    print("Round, Differing bytes, Differing bits")
    diff_bytes0 = int(np.count_nonzero(a != b))
    diff_bits0  = hamming_bits_arrays(a, b)
    print(f"{0}, {diff_bytes0}, {diff_bits0}")

    for r, rp in enumerate(params, start=1):
        a = round_fwd_mix(a, rp, mix_mode)   
        b = round_fwd_mix(b, rp, mix_mode)
        diff_bytes = int(np.count_nonzero(a != b))
        diff_bits  = hamming_bits_arrays(a, b)
        print(f"{r}, {diff_bytes}, {diff_bits}")

if __name__ == "__main__":
    run_round_diffusion()
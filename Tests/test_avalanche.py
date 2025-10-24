
import os, sys, secrets, numpy as np
ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from fluid_sponge_cli import FluidSpongeDuplex

ROUNDS = int(os.getenv("KAAN_ROUNDS", "8"))
RATE   = int(os.getenv("KAAN_RATE", "1024"))
MIX    = os.getenv("KAAN_MIX", "4x4")

def hamming_bits(a: bytes, b: bytes) -> int:
    x = np.frombuffer(a, dtype=np.uint8) ^ np.frombuffer(b, dtype=np.uint8)
    return int(sum(int(bin(v).count("1")) for v in x))

def avalanche(trials=50, size=(256,256), rounds=ROUNDS, rate=RATE, flip_target="plaintext", mix=MIX):
    H,W = size
    N = H*W
    fracs = []
    for _ in range(trials):
        key   = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        pt    = secrets.token_bytes(N)

        if flip_target == "plaintext":
            pt2 = bytearray(pt)
            idx = secrets.randbelow(N); bit = 1 << secrets.randbelow(8)
            pt2[idx] ^= bit
            fs1 = FluidSpongeDuplex(key, nonce, 32, 32, rounds, rate, mix_mode=mix)
            fs2 = FluidSpongeDuplex(key, nonce, 32, 32, rounds, rate, mix_mode=mix)
            ct1, _ = fs1.encrypt(pt); ct2, _ = fs2.encrypt(bytes(pt2))
        elif flip_target == "key":
            key2 = bytearray(key)
            idx = secrets.randbelow(len(key2)); bit = 1 << secrets.randbelow(8)
            key2[idx] ^= bit
            fs1 = FluidSpongeDuplex(key, nonce, 32, 32, rounds, rate, mix_mode=mix)
            fs2 = FluidSpongeDuplex(bytes(key2), nonce, 32, 32, rounds, rate, mix_mode=mix)
            ct1, _ = fs1.encrypt(pt); ct2, _ = fs2.encrypt(pt)
        else:
            raise ValueError("flip_target must be 'plaintext' or 'key'")

        frac = hamming_bits(ct1, ct2) / (len(ct1) * 8)
        fracs.append(frac)
    fracs = np.array(fracs, dtype=float)
    print(f"Avalanche ({flip_target} bit flip): mean={fracs.mean():.4f}, std={fracs.std():.4f}, trials={trials}")

if __name__ == "__main__":
    avalanche(flip_target="plaintext")
    avalanche(flip_target="key")
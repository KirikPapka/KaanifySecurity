
import os, sys, secrets
ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from fluid_sponge_cli import FluidSpongeDuplex

ROUNDS = int(os.getenv("KAAN_ROUNDS", "8"))
RATE   = int(os.getenv("KAAN_RATE", "1024"))
MIX    = os.getenv("KAAN_MIX", "4x4")

def run_roundtrip_tests(trials=10, size=(256, 256), rounds=ROUNDS, rate=RATE, mix=MIX):
    H, W = size
    N = H * W
    ok_all = True
    for t in range(1, trials + 1):
        key   = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        pt    = secrets.token_bytes(N)

        fs  = FluidSpongeDuplex(key, nonce, H=32, W=32, rounds=rounds, rate=rate, mix_mode=mix)
        ct, tag = fs.encrypt(pt)

        fs2 = FluidSpongeDuplex(key, nonce, H=32, W=32, rounds=rounds, rate=rate, mix_mode=mix)
        dec, ok = fs2.decrypt(ct, tag)

        same = (dec == pt)
        ok_all = ok_all and ok and same
        print(f"[{t:02d}] tag_ok={ok}  equal={same}  ct_len={len(ct)}")
    print("RESULT:", "PASS" if ok_all else "FAIL")
    return ok_all

if __name__ == "__main__":
    run_roundtrip_tests()
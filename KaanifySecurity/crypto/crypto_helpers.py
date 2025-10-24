import os, sys, base64


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fluid_sponge_cli import FluidSpongeDuplex  

DEFAULT_ROUNDS = 16
DEFAULT_MIX = "4x4"
DEFAULT_RATE = 1024  

def encrypt_bytes(key: bytes, plaintext: bytes,
                  rounds: int = DEFAULT_ROUNDS,
                  mix: str = DEFAULT_MIX,
                  rate: int = DEFAULT_RATE) -> dict:

    nonce = os.urandom(16)
    fs = FluidSpongeDuplex(key, nonce, H=32, W=32, rounds=rounds, rate=rate, mix_mode=mix)
    ciphertext, tag = fs.encrypt(plaintext)

    return {
        "nonce_hex": nonce.hex(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "tag_hex": tag.hex(),
        "rounds": rounds,
        "mix": mix,
        "rate": rate,
    }

def decrypt_envelope(key: bytes, env: dict) -> tuple[bytes, bool]:
    """Decrypt an envelope (dict with nonce/tag/ciphertext)."""
    nonce = bytes.fromhex(env["nonce_hex"])
    ciphertext = base64.b64decode(env["ciphertext_b64"])
    tag = bytes.fromhex(env["tag_hex"])
    rounds = env.get("rounds", DEFAULT_ROUNDS)
    mix = env.get("mix", DEFAULT_MIX)
    rate = env.get("rate", DEFAULT_RATE)

    fs = FluidSpongeDuplex(key, nonce, H=32, W=32, rounds=rounds, rate=rate, mix_mode=mix)
    plaintext, ok = fs.decrypt(ciphertext, tag)
    return plaintext, ok
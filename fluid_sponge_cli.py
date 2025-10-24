
# fluid_sponge_cli.py
# Fluid-Sponge SPN core + duplex sponge (encrypt/decrypt) + visualizations
from __future__ import annotations
import argparse, os, hmac, hashlib, binascii
from dataclasses import dataclass
from typing import Tuple, List
import numpy as np

IRR_POLY = 0x11B

def gf_mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= (IRR_POLY & 0xFF)
        b >>= 1
    return res

def gf_pow(a: int, e: int) -> int:
    r, base = 1, a
    while e:
        if e & 1: r = gf_mul(r, base)
        base = gf_mul(base, base); e >>= 1
    return r

def gf_inv(x: int) -> int:
    if x == 0: raise ValueError("GF(256) inverse of 0 not defined")
    return gf_pow(x, 254)

def gf_mat_vec_mul(M, v):
    out = [0]*4
    for i in range(4):
        acc = 0
        for j in range(4): acc ^= gf_mul(M[i][j], v[j])
        out[i] = acc
    return out

def gf_mat_inv(M):
    A = [[M[i][j] for j in range(4)] for i in range(4)]
    I = [[1 if i==j else 0 for j in range(4)] for i in range(4)]
    for col in range(4):
        pivot = None
        for r in range(col, 4):
            if A[r][col] != 0: pivot = r; break
        if pivot is None: raise ValueError("Matrix not invertible")
        if pivot != col:
            A[col], A[pivot] = A[pivot], A[col]
            I[col], I[pivot] = I[pivot], I[col]
        inv_p = gf_inv(A[col][col])
        for j in range(4):
            A[col][j] = gf_mul(A[col][j], inv_p)
            I[col][j] = gf_mul(I[col][j], inv_p)
        for r in range(4):
            if r == col: continue
            factor = A[r][col]
            if factor:
                for j in range(4):
                    A[r][j] ^= gf_mul(factor, A[col][j])
                    I[r][j] ^= gf_mul(factor, I[col][j])
    return I

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, prev, counter = b"", b"", 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        out += prev; counter += 1
    return out[:length]

def kdf(key: bytes, *parts: bytes, length: int = 32) -> bytes:
    prk = hmac.new(key, b"\x00"*32, hashlib.sha256).digest()
    info = b"|".join(parts)
    return _hkdf_expand(prk, info, length)

@dataclass
class RoundParams:
    sr: np.ndarray
    tr: np.ndarray
    sbox: np.ndarray
    inv_sbox: np.ndarray
    M: List[List[int]]
    Minv: List[List[int]]

def _prng_bytes(key: bytes, nonce: bytes, label: str, n: int) -> bytes:
    return kdf(key, nonce, label.encode(), length=n)

def _make_sbox(key: bytes, nonce: bytes, round_idx: int):
    seed = _prng_bytes(key, nonce, f"sbox-{round_idx}", 256*4)
    arr = list(range(256))
    for i in range(255, 0, -1):
        j = int.from_bytes(seed[(255-i)*4:(255-i+1)*4], "big") % (i+1)
        arr[i], arr[j] = arr[j], arr[i]
    sbox = np.array(arr, dtype=np.uint8)
    inv = np.zeros(256, dtype=np.uint8)
    for i, v in enumerate(arr): inv[v] = i
    return sbox, inv

def _make_shifts(key: bytes, nonce: bytes, round_idx: int, H: int, W: int):
    row_bytes = _prng_bytes(key, nonce, f"sr-{round_idx}", H)
    col_bytes = _prng_bytes(key, nonce, f"tr-{round_idx}", W)
    sr = (np.frombuffer(row_bytes, dtype=np.uint8).astype(np.int32) % max(1, W)).astype(np.int32)
    tr = (np.frombuffer(col_bytes, dtype=np.uint8).astype(np.int32) % max(1, H)).astype(np.int32)
    return sr, tr

def _make_matrix(key: bytes, nonce: bytes, round_idx: int):
    raw = _prng_bytes(key, nonce, f"mat-{round_idx}", 16*8)
    for o in range(0, len(raw)-16*4+1, 16):
        block = raw[o:o+16]
        M = [[block[r*4+c] for c in range(4)] for r in range(4)]
        try:
            Minv = gf_mat_inv(M); return M, Minv
        except Exception:
            continue
    M = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]  
    Minv = gf_mat_inv(M)
    return M, Minv

def derive_round_params(key: bytes, nonce: bytes, rounds: int, H: int, W: int) -> List[RoundParams]:
    return [RoundParams(*_make_shifts(key, nonce, r, H, W),
                        *_make_sbox(key, nonce, r),
                        *_make_matrix(key, nonce, r))
            for r in range(1, rounds+1)]


def shear_xy(arr: np.ndarray, sr: np.ndarray, tr: np.ndarray) -> np.ndarray:
    H, W = arr.shape
    out = np.empty_like(arr)
    for y in range(H): out[y] = np.roll(arr[y], int(sr[y] % W))
    out2 = np.empty_like(out)
    for x in range(W): out2[:, x] = np.roll(out[:, x], int(tr[x] % H))
    return out2

def inv_shear_xy(arr: np.ndarray, sr: np.ndarray, tr: np.ndarray) -> np.ndarray:
    H, W = arr.shape
    tmp = np.empty_like(arr)
    for x in range(W): tmp[:, x] = np.roll(arr[:, x], -int(tr[x] % H))
    out = np.empty_like(arr)
    for y in range(H): out[y] = np.roll(tmp[y], -int(sr[y] % W))
    return out

def sbox_sub(arr: np.ndarray, sbox: np.ndarray) -> np.ndarray: return sbox[arr]
def sbox_inv(arr: np.ndarray, inv_sbox: np.ndarray) -> np.ndarray: return inv_sbox[arr]

def mix_2x2(arr: np.ndarray, M) -> np.ndarray:
    H, W = arr.shape; out = arr.copy()
    for y in range(0, H - H % 2, 2):
        for x in range(0, W - W % 2, 2):
            a,b = int(out[y,x]), int(out[y,x+1]); c,d = int(out[y+1,x]), int(out[y+1,x+1])
            a2,b2,c2,d2 = gf_mat_vec_mul(M, [a,b,c,d])
            out[y,x],out[y,x+1],out[y+1,x],out[y+1,x+1]=a2,b2,c2,d2
    return out

def mix_2x2_inv(arr: np.ndarray, Minv) -> np.ndarray:
    H, W = arr.shape; out = arr.copy()
    for y in range(0, H - H % 2, 2):
        for x in range(0, W - W % 2, 2):
            a,b = int(out[y,x]), int(out[y,x+1]); c,d = int(out[y+1,x]), int(out[y+1,x+1])
            a2,b2,c2,d2 = gf_mat_vec_mul(Minv, [a,b,c,d])
            out[y,x],out[y,x+1],out[y+1,x],out[y+1,x+1]=a2,b2,c2,d2
    return out

def mix_4x4(arr: np.ndarray, M) -> np.ndarray:

    H, W = arr.shape
    out = arr.copy()
    H4, W4 = H - (H % 4), W - (W % 4)


    for y in range(0, H4, 4):
        for x in range(0, W4, 4):
            for r in range(4):
                v = [int(out[y + r, x + c]) for c in range(4)]
                vr = gf_mat_vec_mul(M, v)
                for c in range(4):
                    out[y + r, x + c] = vr[c]

    for y in range(0, H4, 4):
        for x in range(0, W4, 4):
            for c in range(4):
                v = [int(out[y + r, x + c]) for r in range(4)]
                vr = gf_mat_vec_mul(M, v)
                for r in range(4):
                    out[y + r, x + c] = vr[r]

    return out

def mix_4x4_inv(arr: np.ndarray, Minv) -> np.ndarray:

    H, W = arr.shape
    out = arr.copy()
    H4, W4 = H - (H % 4), W - (W % 4)

    for y in range(0, H4, 4):
        for x in range(0, W4, 4):
            for c in range(4):
                v = [int(out[y + r, x + c]) for r in range(4)]
                vr = gf_mat_vec_mul(Minv, v)
                for r in range(4):
                    out[y + r, x + c] = vr[r]

    for y in range(0, H4, 4):
        for x in range(0, W4, 4):
            for r in range(4):
                v = [int(out[y + r, x + c]) for c in range(4)]
                vr = gf_mat_vec_mul(Minv, v)
                for c in range(4):
                    out[y + r, x + c] = vr[c]

    return out

def round_fwd_mix(state: np.ndarray, rp: RoundParams, mix_mode: str) -> np.ndarray:
    s1 = shear_xy(state, rp.sr, rp.tr)
    s2 = sbox_sub(s1, rp.sbox)
    if mix_mode == "2x2":
        return mix_2x2(s2, rp.M)
    else:
        return mix_4x4(s2, rp.M)

def round_inv_mix(state: np.ndarray, rp: RoundParams, mix_mode: str) -> np.ndarray:
    if mix_mode == "2x2":
        s1 = mix_2x2_inv(state, rp.Minv)
    else:
        s1 = mix_4x4_inv(state, rp.Minv)
    s2 = sbox_inv(s1, rp.inv_sbox)
    s3 = inv_shear_xy(s2, rp.sr, rp.tr)
    return s3

@dataclass
class FluidSpongeDuplex:
    key: bytes; nonce: bytes
    H: int = 32; W: int = 32; rounds: int = 8; rate: int = 512; mix_mode: str = "4x4"
    def __post_init__(self):
        self.params = derive_round_params(self.key, self.nonce, self.rounds, self.H, self.W)
        seed = kdf(self.key, self.nonce, b"init", length=self.H*self.W)
        self.state = np.frombuffer(seed, dtype=np.uint8).reshape(self.H, self.W).copy()
    def _permute(self):
        s = self.state
        for rp in self.params:
            s = round_fwd_mix(s, rp, self.mix_mode)
        self.state = s
    def _squeeze(self, nbytes: int) -> bytes:
        return bytes(self.state.reshape(-1)[:nbytes].tolist())
    def _absorb(self, block: bytes):
        flat = self.state.reshape(-1); r = min(len(block), len(flat))
        flat[:r] ^= np.frombuffer(block[:r], dtype=np.uint8)
    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        out = []; i = 0
        while i < len(plaintext):
            chunk = plaintext[i:i+self.rate]
            Z = self._squeeze(len(chunk)); out.append(bytes(a^b for a,b in zip(chunk, Z)))
            self._absorb(chunk); self._permute(); i += len(chunk)
        self._permute(); tag = self._squeeze(32); return b"".join(out), tag
    def decrypt(self, ciphertext: bytes, tag: bytes) -> Tuple[bytes, bool]:
        out = []; i = 0
        while i < len(ciphertext):
            chunk = ciphertext[i:i+self.rate]
            Z = self._squeeze(len(chunk)); P = bytes(a^b for a,b in zip(chunk, Z))
            self._absorb(P); self._permute(); out.append(P); i += len(chunk)
        self._permute(); ok = hmac.compare_digest(self._squeeze(32), tag)
        return b"".join(out), ok

def save_gif(frames_np: List[np.ndarray], path: str, fps: float):

    import imageio.v2 as imageio
    os.makedirs(os.path.dirname(path), exist_ok=True)
    dur = 1.0 / max(fps, 0.1)
    with imageio.get_writer(path, mode="I", duration=dur, loop=0) as w:
        for f in frames_np:
            w.append_data(f)

def dump_frames_png(frames_np: List[np.ndarray], folder: str, stem: str):

    from PIL import Image
    os.makedirs(folder, exist_ok=True)
    for i, f in enumerate(frames_np):
        Image.fromarray(f).save(os.path.join(folder, f"{stem}_{i:03d}.png"))

def visualize_rounds(base: np.ndarray, key: bytes, nonce: bytes, rounds: int,
                     mix_mode: str,
                     out_gif_path: str, fps: float = 2.0, dump_pngs_to: str|None=None) -> None:
    H, W = base.shape
    params = derive_round_params(key, nonce, rounds, H, W)
    frames = [base.copy()]
    s = base.copy()
    for rp in params:
        s = round_fwd_mix(s, rp, mix_mode)
        frames.append(s.copy())
    save_gif(frames, out_gif_path, fps)
    if dump_pngs_to: dump_frames_png(frames, dump_pngs_to, "round")

def visualize_rounds_substeps(base: np.ndarray, key: bytes, nonce: bytes, rounds: int,
                              mix_mode: str,
                              out_gif_path: str, fps: float = 3.0, dump_pngs_to: str|None=None) -> None:
    H, W = base.shape
    params = derive_round_params(key, nonce, rounds, H, W)
    frames = [base.copy()]
    s = base.copy()
    for rp in params:
        s1 = shear_xy(s, rp.sr, rp.tr); frames.append(s1.copy())
        s2 = sbox_sub(s1, rp.sbox);     frames.append(s2.copy())
        s3 = mix_2x2(s2, rp.M) if mix_mode=="2x2" else mix_4x4(s2, rp.M)
        frames.append(s3.copy())
        s = s3
    save_gif(frames, out_gif_path, fps)
    if dump_pngs_to: dump_frames_png(frames, dump_pngs_to, "substep")

def visualize_progress_fullframe_heatmap(
    base_image_array: np.ndarray,
    key: bytes, nonce: bytes,
    rounds: int, rate: int,
    out_ct_gif: str, out_dec_gif: str,
    fps: float = 2.0,
    dump_pngs_to: str | None = None
) -> None:

    from PIL import Image  

    H, W = base_image_array.shape
    N_expected = H * W
    P = base_image_array.tobytes()
    N = len(P)
    if N != N_expected:
        print(f"[viz] WARN: len(P)={N} != H*W={N_expected}. Using N=len(P).")

    def _to_frame(buf: bytes) -> np.ndarray:
        bb = (buf + b"\x00" * max(0, N - len(buf)))[:N]
        return np.frombuffer(bb, dtype=np.uint8).reshape(H, W)

    def _gray_to_rgb(img2d: np.ndarray) -> np.ndarray:
        return np.repeat(img2d[:, :, None], 3, axis=2)

    enc_full = FluidSpongeDuplex(key, nonce, H=32, W=32, rounds=rounds, rate=rate)
    CT_full, _ = enc_full.encrypt(P)
    if len(CT_full) != N:
        print(f"[viz] WARN: len(CT_full)={len(CT_full)} != N={N}. (Will pad/trim for frames.)")

    enc = FluidSpongeDuplex(key, nonce, H=32, W=32, rounds=rounds, rate=rate)
    dec = FluidSpongeDuplex(key, nonce, H=32, W=32, rounds=rounds, rate=rate)

    frames_ct_rgb: List[np.ndarray] = []
    frames_dec_rgb: List[np.ndarray] = []

    ct_prefix = bytearray()
    pt_prefix = bytearray()

    i = 0

    eff_rate = max(1, int(rate))

    print(f"[viz] H={H} W={W} N={N} rate={eff_rate} rounds={rounds}")

    while i < N:
        step = min(eff_rate, N - i)
        if step <= 0:
            break

        chunkP = P[i:i+step]
        Z = enc._squeeze(len(chunkP))
        ct_chunk = bytes(a ^ b for a, b in zip(chunkP, Z))
        enc._absorb(chunkP); enc._permute()
        ct_prefix.extend(ct_chunk)

        remaining_ct = N - len(ct_prefix)
        if remaining_ct > 0:
            Zpred = _squeeze_stream_from_snapshot(enc, remaining_ct)
            ct_pred = bytes(a ^ b for a, b in zip(P[len(ct_prefix):], Zpred))
            CT_frame_bytes = bytes(ct_prefix) + ct_pred
        else:
            CT_frame_bytes = bytes(ct_prefix)

        chunkCT = CT_full[i:i+step]
        Zp = dec._squeeze(len(chunkCT))
        pt_chunk = bytes(a ^ b for a, b in zip(chunkCT, Zp))
        dec._absorb(pt_chunk); dec._permute()
        pt_prefix.extend(pt_chunk)

        remaining_pt = N - len(pt_prefix)
        if remaining_pt > 0:
            Zpred_dec = _squeeze_stream_from_snapshot(dec, remaining_pt)
            pt_pred = bytes(a ^ b for a, b in zip(CT_full[len(pt_prefix):], Zpred_dec))
            PT_frame_bytes = bytes(pt_prefix) + pt_pred
        else:
            PT_frame_bytes = bytes(pt_prefix)

        ct_frame_u8 = _to_frame(CT_frame_bytes)
        pt_frame_u8 = _to_frame(PT_frame_bytes)

        frames_ct_rgb.append(to_heatmap(ct_frame_u8))
        frames_dec_rgb.append(to_heatmap(pt_frame_u8))

        if len(frames_ct_rgb) == 1:
            print(f"[viz] first-frame: ct_prefix={len(ct_prefix)}, pt_prefix={len(pt_prefix)}, "
                  f"ct_pred_add={len(CT_frame_bytes)-len(ct_prefix)}, "
                  f"pt_pred_add={len(PT_frame_bytes)-len(pt_prefix)}")

        i += step

    if not frames_ct_rgb:
        print("[viz] WARN: produced 0 frames; synthesizing a single frame.")
        Zpred_all = _squeeze_stream_from_snapshot(enc, N)
        CT_pred_all = bytes(a ^ b for a, b in zip(P, Zpred_all))
        frames_ct_rgb.append(to_heatmap(_to_frame(CT_pred_all)))
        Zpred_dec_all = _squeeze_stream_from_snapshot(dec, N)
        PT_pred_all = bytes(a ^ b for a, b in zip(CT_full, Zpred_dec_all))
        frames_dec_rgb.append(to_heatmap(_to_frame(PT_pred_all)))

    frames_ct_rgb.append(to_heatmap(_to_frame(CT_full)))
    frames_dec_rgb.append(np.repeat(base_image_array[:, :, None], 3, axis=2))

    save_gif(frames_ct_rgb, out_ct_gif, fps)
    save_gif(frames_dec_rgb, out_dec_gif, fps)

    if dump_pngs_to:
        os.makedirs(dump_pngs_to, exist_ok=True)
        for idx, f in enumerate(frames_ct_rgb):
            Image.fromarray(f).save(os.path.join(dump_pngs_to, f"enc_fullframe_heat_{idx:03d}.png"))
        for idx, f in enumerate(frames_dec_rgb):
            Image.fromarray(f).save(os.path.join(dump_pngs_to, f"dec_fullframe_heat_{idx:03d}.png"))

def parse_hex_or_ascii(s: str, expected_len: int) -> bytes:
    s = s.strip()
    try:
        if s.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in s):
            b = binascii.unhexlify(s[2:] if s.startswith("0x") else s)
        else:
            b = s.encode("utf-8")
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Bad key/nonce: {e}")
    if len(b) < expected_len: b = b + b"\x00"*(expected_len - len(b))
    return b[:expected_len]

def _make_heatmap_lut() -> np.ndarray:
    stops = [
        (0,   (0,   0,  64)),   # dark blue
        (64,  (0,   0, 255)),   # blue
        (128, (0, 255, 255)),   # cyan
        (192, (255,255,  0)),   # yellow
        (255, (255,255,255)),   # white
    ]
    lut = np.zeros((256, 3), dtype=np.uint8)
    for i in range(len(stops) - 1):
        x0, c0 = stops[i]
        x1, c1 = stops[i+1]
        span = max(1, x1 - x0)
        for t in range(span):
            a = t / span
            r = int((1-a)*c0[0] + a*c1[0])
            g = int((1-a)*c0[1] + a*c1[1])
            b = int((1-a)*c0[2] + a*c1[2])
            lut[x0 + t] = (r, g, b)
    lut[255] = stops[-1][1]
    return lut

_HEATMAP_LUT = _make_heatmap_lut()

def to_heatmap(img_u8_2d: np.ndarray) -> np.ndarray:
    return _HEATMAP_LUT[img_u8_2d]

def visualize_rounds_substeps_decrypt_heatmap(
    base_image_array: np.ndarray,
    key: bytes, nonce: bytes,
    rounds: int,
    out_gif_path: str,
    fps: float = 3.0,
    dump_pngs_to: str | None = None,
    final_grayscale: bool = True,
    mix_mode: str = "4x4",    
) -> None:

    from PIL import Image
    import os
    import numpy as np

    H, W = base_image_array.shape
    params = derive_round_params(key, nonce, rounds, H, W)

    s = base_image_array.copy()
    for rp in params:
        s = round_fwd_mix(s, rp, mix_mode)  

    frames_rgb: list[np.ndarray] = []
    frames_rgb.append(to_heatmap(s))  

    for rp in reversed(params):
        if mix_mode == "2x2":
            s1 = mix_2x2_inv(s, rp.Minv)
        else:
            s1 = mix_4x4_inv(s, rp.Minv)
        frames_rgb.append(to_heatmap(s1))

        s2 = sbox_inv(s1, rp.inv_sbox)
        frames_rgb.append(to_heatmap(s2))

        s3 = inv_shear_xy(s2, rp.sr, rp.tr)
        frames_rgb.append(to_heatmap(s3))

        s = s3

    if final_grayscale:
        frames_rgb.append(np.repeat(base_image_array[:, :, None], 3, axis=2))

    save_gif(frames_rgb, out_gif_path, fps)
    if dump_pngs_to:
        os.makedirs(dump_pngs_to, exist_ok=True)
        for i, f in enumerate(frames_rgb):
            Image.fromarray(f).save(os.path.join(dump_pngs_to, f"dec_substeps_heat_%03d.png" % i))

def _squeeze_stream_from_snapshot(fs: FluidSpongeDuplex, nbytes: int) -> bytes:

    clone = FluidSpongeDuplex(fs.key, fs.nonce, fs.H, fs.W, fs.rounds, fs.rate)
    clone.params = fs.params  
    clone.state = fs.state.copy()
    out = bytearray()
    while len(out) < nbytes:
        take = min(nbytes - len(out), fs.H * fs.W)  
        out.extend(clone._squeeze(take))
        clone._permute()
    return bytes(out)

def main():
    p = argparse.ArgumentParser(description="Fluid Sponge SPN + Duplex with visualizations")
    p.add_argument("--image", required=True, help="Input image; converted to 8-bit grayscale")
    p.add_argument("--size", default="128x128", help="Resize WxH (default 128x128)")
    p.add_argument("--key", required=True, help="32-byte key (hex or ASCII)")
    p.add_argument("--nonce", required=True, help="16-byte nonce (hex or ASCII)")
    p.add_argument("--rounds", type=int, default=8, help="SPN rounds (default 8)")
    p.add_argument("--rate", type=int, default=512, help="Sponge rate in bytes per step (default 512)")
    p.add_argument("--out", default="out", help="Output directory")
    p.add_argument("--make-gifs", action="store_true", help="Produce GIFs")
    p.add_argument("--save-frames", action="store_true", help="Also dump individual PNG frames")
    p.add_argument("--enc", action="store_true", help="Emit ciphertext.bin and tag.hex for the image bytes")
    p.add_argument("--dec", default="", help="If set, read ciphertext.bin+tag.hex from this folder and write decrypted.png")
    p.add_argument("--mix", choices=["2x2", "4x4"], default="4x4",
               help="Linear diffusion: 2x2 (current) or stronger 4x4 row+col mixing (default 4x4)")
    args = p.parse_args()

    from PIL import Image

    os.makedirs(args.out, exist_ok=True)
    W, H = map(int, args.size.lower().split("x"))
    key = parse_hex_or_ascii(args.key, 32)
    nonce = parse_hex_or_ascii(args.nonce, 16)

    img = Image.open(args.image).convert("L").resize((W, H))
    arr = np.array(img, dtype=np.uint8)
    img.save(os.path.join(args.out, "plaintext.png"))

    png_frames_dir = os.path.join(args.out, "frames") if args.save_frames else None

    if args.make_gifs:
        visualize_rounds(arr, key, nonce, args.rounds, args.mix,
                         out_gif_path=os.path.join(args.out, "rounds_diffusion.gif"),
                         fps=2.0, dump_pngs_to=os.path.join(png_frames_dir, "rounds") if png_frames_dir else None)
        visualize_rounds_substeps(arr, key, nonce, args.rounds, args.mix,
                                  out_gif_path=os.path.join(args.out, "rounds_substeps.gif"),
                                  fps=3.0, dump_pngs_to=os.path.join(png_frames_dir, "substeps") if png_frames_dir else None)
        visualize_progress_fullframe_heatmap(
                                    arr, key, nonce, rounds=args.rounds, rate=args.rate,
                                    out_ct_gif=os.path.join(args.out, "encryption_progress_heatmap.gif"),
                                    out_dec_gif=os.path.join(args.out, "decryption_progress_heatmap.gif"),
                                    fps=2.0,
                                    dump_pngs_to=os.path.join(png_frames_dir, "progress_heatmap") if png_frames_dir else None)
        visualize_rounds_substeps_decrypt_heatmap(
                                    arr, key, nonce, rounds=args.rounds,
                                    out_gif_path=os.path.join(args.out, "rounds_substeps_decrypt_heatmap.gif"),
                                    fps=3.0,
                                    dump_pngs_to=os.path.join(png_frames_dir, "substeps_decrypt_heat") if png_frames_dir else None,
                                    final_grayscale=True,
                                    mix_mode=args.mix
                                )
                                

    if args.enc:
        fs = FluidSpongeDuplex(key, nonce, H=32, W=32, rounds=args.rounds, rate=args.rate, mix_mode=args.mix)
        pt_bytes = arr.tobytes()
        ct, tag = fs.encrypt(pt_bytes)
        open(os.path.join(args.out, "ciphertext.bin"), "wb").write(ct)
        open(os.path.join(args.out, "tag.hex"), "w").write(tag.hex())
        N = H * W
        ct_img_bytes = (ct + b"\x00" * max(0, N - len(ct)))[:N]
        Image.fromarray(np.frombuffer(ct_img_bytes, dtype=np.uint8).reshape(H, W)).save(
            os.path.join(args.out, "ciphertext.png")
        )
        print(f"[enc] plaintext={len(pt_bytes)} bytes  ciphertext={len(ct)} bytes  tag=32 bytes")

    if args.dec:
        in_dir = args.dec
        ct = open(os.path.join(in_dir, "ciphertext.bin"), "rb").read()
        tag = bytes.fromhex(open(os.path.join(in_dir, "tag.hex"), "r").read().strip())
        fs2 = FluidSpongeDuplex(key, nonce, H=32, W=32, rounds=args.rounds, rate=args.rate)
        pt, ok = fs2.decrypt(ct, tag)
        print(f"[dec] recovered={len(pt)} bytes  tag_ok={ok}")
        N = H * W
        pt_img_bytes = (pt + b"\x00" * max(0, N - len(pt)))[:N]
        Image.fromarray(np.frombuffer(pt_img_bytes, dtype=np.uint8).reshape(H, W)).save(
            os.path.join(args.out, "decrypted.png")
        )

if __name__ == "__main__":
    main()

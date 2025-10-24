# Kaanify Security – Fluid Sponge SPN Cipher

The **Fluid Sponge Cipher** is a reversible, image-friendly Substitution–Permutation Network (SPN) combined with a **duplex sponge construction**. The cipher uses **key-dependent fluid-like coordinate permutations**, **S-box substitution**, and **local diffusion in GF(2⁸)** to produce high diffusion and statistical randomness. A full mathematical specification is included in this repository.


<p align="center">
  <img src="https://github.com/user-attachments/assets/9e24be7c-312e-4ba3-8ac5-4dd2acc3fe0e" width="45%">
  <img src="https://github.com/user-attachments/assets/4ffa57ef-513b-42f3-afc2-331a3d593700" width="45%">
</p>


---

## Overview

## Repository Structure
```bash
Kaanify_Security/
│
├── fluid_sponge_cli.py              # cipher implementation
├── Fluid_Sponge__SPN_Cryptographic_Core.pdf  # formal description
├── KaanifySecurity/                 # messenger demo
├── Tests/                           # test suite
└── TestResults.txt                  # test run output
```
---

## Algorithm Summary

The cipher state is a 2D array 

$$
X \in \{0,\dots,255\}^{H \times W}
$$   

default 32*32 = 1024 bytes. One encryption round is defined as:

$$
X_r = \Pi_r \circ \mathrm{Mix}(M_r) \circ S_r \circ \mathcal F_r(X_{r-1})
$$

Where each component is bijective:

| Component | Description |
|-----------|-------------|
| $\mathcal{F}_r$ | Keyed coordinate shear (“fluid shift”) |
| $S_r$ | Byte-wise nonlinear S-box substitution |
| $M_r$ | $2\times2$ or $4\times4$ block diffusion over $\mathrm{GF}(2^8)$ |
| $\Pi_r$ | Optional round-dependent block permutation |

All mappings are invertible, so the full permutation is reversible:

$$
\pi^{-1} = (\pi^{(1)})^{-1} \circ \cdots \circ (\pi^{(R)})^{-1}
$$

---

## Sponge Mode (Duplex)

The SPN core is used in a **duplex sponge encryption** mode. Given message blocks $M_i$:

$$
\begin{aligned}
Z_i &\leftarrow S_{\text{rate}} &&\text{(squeeze)}\\
C_i &= M_i \oplus Z_i &&\text{(encrypt)}\\
S_{\text{rate}} &\leftarrow S_{\text{rate}} \oplus M_i &&\text{(absorb)}\\
S &\leftarrow \pi(S) &&\text{(permute)}
\end{aligned}
$$

A final tag \(T\) is squeezed for integrity.

---

## Cryptographic Test Results

Results from `TestResults.txt`:

### 1. Roundtrip Correctness

Tag authentication: PASS

Plaintext recovery: PASS

Ciphertext size: correct

### 2. Avalanche Test
| Flip Type | Mean Bit Flip | Interpretation |
|------------|---------------|----------------|
| Plaintext bit flip | 0.272 | Moderate diffusion |
| Key bit flip | 0.500 | Ideal – strong key sensitivity |

### 3. Per-Round Diffusion
Full-state diffusion achieved by **round 4** out of 16 — strong:

Round  | Differing bytes

0      | 1

1      | 16

2      | 256

3      | 3581

4      | 15976

…

### 4. Keystream Randomness
| Metric | Result | Ideal |
|--------|--------|-------|
| Shannon Entropy | 8.000 bits/byte | ~8 |
| Monobit bias | 0.5000 | 0.5 |
| χ² uniformity | 204.77 (df 255) | <255 |
| Lag-1 autocorrelation | −0.00017 | ~0 |

Result: **Keystream statistically indistinguishable from random.**

---

## Command Line Usage

```bash
python3 fluid_sponge_cli.py \
  --image input.png \
  --size 256x256 \
  --key 0f1e2d...e3f \
  --nonce 0011...eeff \
  --rounds 8 \
  --make-gifs \
  --enc \
  --out demo_output
```

## Messenger Demo (KaanifySecurity)

A simple LAN-based messenger demonstrates encryption in practice.

Start server:

```bash
bash KaanifySecurity/run.sh
```
```bash
python3 KaanifySecurity/client/inbox.py http://<LAN-IP>:5050 bob
```
```bash
python3 KaanifySecurity/client/send_text.py http://<LAN-IP>:5050 alice bob "Hello"
```

<img width="1934" height="1403" alt="Messeger" src="https://github.com/user-attachments/assets/c544814d-e22d-4b49-b81c-d9b8d42b66c2" />


## Security Notice

This cipher is a research prototype.

It has not undergone public cryptanalysis.

Do not use in production or for real-world security without formal review.

Nonce reuse is forbidden: never reuse (key, nonce) pairs.


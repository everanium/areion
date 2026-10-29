#!/usr/bin/env python3
"""
Standalone reference implementation, algebraic identity checker, and Known-Answer
Test (KAT) verifier for the ASURA 256-bit tweakable block cipher.

Reference:
  Atsushi Tanaka, Rentaro Shiba, Kosei Sakamoto, Mostafizar Rahman,
  Takuro Shiraya, and Takanori Isobe,
  "ASURA: An Efficient Large-State Tweakable Block Cipher for ARM Environment",
  INDOCRYPT 2024 (LNCS 15497, pp. 209-232) / IACR ePrint 2024/1394.

This script uses only the Python 3 standard library and verifies:
  1. Round constant alignment with Haraka v2 / Pholkos-256 and constants.go.
  2. Structural properties of the key-schedule permutations pi_256 and pi o tau,
     and exact invertibility of kappa and kappa_inv over GF(2^8).
  3. Exact invertibility of the 256-bit byte-unzipping shuffle perm256 and inv_perm256.
  4. Equivalence and exact invertibility of the round functions F_gamma and F_delta
     across the ARM64 NEON formulation (Equations 7-10), the x86-64 AES-NI formulation,
     and the Equivalent Inverse Cipher optimization using MC(k1).
  5. Pre-expanded vs. on-the-fly (OTF) encryption and decryption equivalence, and
     round-trip invertibility decrypt(encrypt(P, K, T), K, T) == P.
  6. KAT 0 (all-zero) and KAT 1 (sequential bytes) derivation and byte-for-byte
     cross-check against TestAsuraKAT in areion_test.go.
"""

import os
import re
import struct
import sys


# AES S-box and Inverse S-box
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

INV_SBOX = [0] * 256
for _idx, _val in enumerate(SBOX):
    INV_SBOX[_val] = _idx


def xtime(a: int) -> int:
    """Multiply byte a by x (0x02) in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (0x11b)."""
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1)


def div2_gf256(a: int) -> int:
    """Multiply byte a by x^-1 (0x8d) in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (0x11b)."""
    return ((a >> 1) ^ 0x8d) if (a & 1) else (a >> 1)


def gmul(a: int, b: int) -> int:
    """Multiply bytes a and b in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = xtime(a)
        b >>= 1
    return p


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def sub_bytes(s: bytes) -> bytes:
    return bytes(SBOX[b] for b in s)


def inv_sub_bytes(s: bytes) -> bytes:
    return bytes(INV_SBOX[b] for b in s)


def shift_rows(s: bytes) -> bytes:
    idx = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
    return bytes(s[i] for i in idx)


def inv_shift_rows(s: bytes) -> bytes:
    idx = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
    return bytes(s[i] for i in idx)


def mix_columns(s: bytes) -> bytes:
    out = bytearray(16)
    for c in range(4):
        s0, s1, s2, s3 = s[4 * c : 4 * c + 4]
        out[4 * c + 0] = gmul(2, s0) ^ gmul(3, s1) ^ s2 ^ s3
        out[4 * c + 1] = s0 ^ gmul(2, s1) ^ gmul(3, s2) ^ s3
        out[4 * c + 2] = s0 ^ s1 ^ gmul(2, s2) ^ gmul(3, s3)
        out[4 * c + 3] = gmul(3, s0) ^ s1 ^ s2 ^ gmul(2, s3)
    return bytes(out)


def inv_mix_columns(s: bytes) -> bytes:
    out = bytearray(16)
    for c in range(4):
        s0, s1, s2, s3 = s[4 * c : 4 * c + 4]
        out[4 * c + 0] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3)
        out[4 * c + 1] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3)
        out[4 * c + 2] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3)
        out[4 * c + 3] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3)
    return bytes(out)


# ARM64 NEON AES primitives (Section 3.1, Equations 1-4 of asura.pdf)
def AESE(x: bytes, k: bytes) -> bytes:
    return sub_bytes(shift_rows(xor_bytes(x, k)))


def AESMC(x: bytes) -> bytes:
    return mix_columns(x)


def AESD(x: bytes, k: bytes) -> bytes:
    return inv_sub_bytes(inv_shift_rows(xor_bytes(x, k)))


def AESIMC(x: bytes) -> bytes:
    return inv_mix_columns(x)


# x86-64 AES-NI primitives
def AESENC(x: bytes, k: bytes) -> bytes:
    return xor_bytes(mix_columns(shift_rows(sub_bytes(x))), k)


def AESENCLAST(x: bytes, k: bytes) -> bytes:
    return xor_bytes(shift_rows(sub_bytes(x)), k)


def AESDEC(x: bytes, k: bytes) -> bytes:
    return xor_bytes(inv_mix_columns(inv_shift_rows(inv_sub_bytes(x))), k)


def AESDECLAST(x: bytes, k: bytes) -> bytes:
    return xor_bytes(inv_shift_rows(inv_sub_bytes(x)), k)


# First 13 Haraka v2 / Pholkos-256 round constants (Section 3.2 of asura.pdf)
HARAKA_RC_U32 = [
    (0x75817b9d, 0xb2c5fef0, 0xe620c00a, 0x0684704c),
    (0x4b1b668b, 0x5c2f996a, 0x8a0c21b8, 0x98b498f8),
    (0xc9090234, 0x55712f21, 0xe494dc11, 0x9d8f4b3b),
    (0x4f006bb7, 0xd6d27b5b, 0xe3826b0e, 0x53864f16),
    (0x6b24b0cb, 0x3b8399ba, 0x77b472b2, 0xeb924433),
    (0x9d36cd7e, 0xa2b2a5e3, 0x89390c42, 0x290f45e7),
    (0x4115c26c, 0x798f845e, 0x92bc867b, 0x218b5324),
    (0x6aa7ca29, 0x67b6659f, 0x9b5a7770, 0x7c8bd8d8),
    (0x5f630d4d, 0xc97f2f2b, 0x347f4898, 0x7f759a29),
    (0x6b843086, 0x843b30bb, 0x587918ca, 0x366d2254),
    (0x47bd0782, 0xd90b9d9e, 0x9938982f, 0x628b92c6),
    (0x4b87df3c, 0x39b59e6a, 0x1651fa46, 0x5c2379fa),
    (0x2ca275d6, 0xf2e728b5, 0x6f73e9e4, 0x58b25488),
]

ASURA_RC = [struct.pack("<4I", *w) for w in HARAKA_RC_U32]

# Key schedule permutations (Section 3.2, Figure 2 of asura.pdf)
PI_256 = [0, 5, 2, 7, 4, 1, 6, 3]
PI_TAU = [11, 12, 1, 2, 15, 0, 5, 6, 3, 4, 9, 10, 7, 8, 13, 14]
INV_PI_TAU = [0] * 16
for _idx, _val in enumerate(PI_TAU):
    INV_PI_TAU[_val] = _idx


def theta(t: bytes) -> bytes:
    """Tweak update function theta(T) = AESMC(AESE(T, 0)) = MC(SB(SR(T)))."""
    return mix_columns(sub_bytes(shift_rows(t)))


def kappa(k: bytes) -> bytes:
    """Key update function kappa(K) = (pi o tau)(2 * pi_256(K))."""
    words = list(struct.unpack("<8I", k))
    new_words = [words[PI_256[j]] for j in range(8)]
    k_perm = struct.pack("<8I", *new_words)
    k_x2 = bytes(xtime(b) for b in k_perm)
    k0 = bytes(k_x2[PI_TAU[b]] for b in range(16))
    k1 = bytes(k_x2[16 + PI_TAU[b]] for b in range(16))
    return k0 + k1


def kappa_inv(k: bytes) -> bytes:
    """Inverse key update function kappa^-1(K) = pi_256^-1(2^-1 * (pi o tau)^-1(K))."""
    k0_unperm = bytes(k[INV_PI_TAU[b]] for b in range(16))
    k1_unperm = bytes(k[16 + INV_PI_TAU[b]] for b in range(16))
    k_div2 = bytes(div2_gf256(b) for b in (k0_unperm + k1_unperm))
    words = list(struct.unpack("<8I", k_div2))
    orig_words = [words[PI_256[j]] for j in range(8)]
    return struct.pack("<8I", *orig_words)


def gamma(rc: bytes, k: bytes, t: bytes) -> tuple[bytes, bytes]:
    """Round tweakey compression gamma(RC^i, K^i, T^i) -> (RTK_0^i, RTK_1^i)."""
    k0, k1 = k[:16], k[16:]
    rtk0 = xor_bytes(xor_bytes(t, k0), rc)
    rtk1 = xor_bytes(t, k1)
    return (rtk0, rtk1)


def asura_tweakey_schedule(key: bytes, tweak: bytes, R: int = 6) -> list[tuple[bytes, bytes]]:
    assert len(key) == 32 and len(tweak) == 16
    k = key
    t = tweak
    rtks = [gamma(ASURA_RC[0], k, t)]
    for i in range(1, 2 * R + 1):
        t = theta(t)
        k = kappa(k)
        rtks.append(gamma(ASURA_RC[i], k, t))
    return rtks


def perm256(x0: bytes, x1: bytes) -> tuple[bytes, bytes]:
    """Byte-unzipping permutation perm256 (Figure 3 / vuzpq_u8)."""
    y0 = bytes([x0[2 * i] for i in range(8)] + [x1[2 * i] for i in range(8)])
    y1 = bytes([x0[2 * i + 1] for i in range(8)] + [x1[2 * i + 1] for i in range(8)])
    return y0, y1


def inv_perm256(y0: bytes, y1: bytes) -> tuple[bytes, bytes]:
    """Inverse byte-zipping permutation inv_perm256 (vzipq_u8)."""
    x0 = bytes(y0[i // 2] if i % 2 == 0 else y1[i // 2] for i in range(16))
    x1 = bytes(y0[8 + i // 2] if i % 2 == 0 else y1[8 + i // 2] for i in range(16))
    return x0, x1


# ARM64 Equations (7)-(10)
def F_gamma_arm(x: bytes, k0: bytes, k1: bytes) -> bytes:
    return AESMC(AESE(AESIMC(AESD(x, k0)), k1))


def F_delta_arm(x: bytes, k0: bytes, k1: bytes) -> bytes:
    return AESIMC(AESD(AESIMC(AESD(x, k0)), k1))


def F_gamma_inv_arm(x: bytes, k0: bytes, k1: bytes) -> bytes:
    zero = bytes(16)
    u = xor_bytes(AESD(AESIMC(x), zero), k1)
    return xor_bytes(AESE(AESMC(u), zero), k0)


def F_delta_inv_arm(x: bytes, k0: bytes, k1: bytes) -> bytes:
    zero = bytes(16)
    u = xor_bytes(AESE(AESMC(x), zero), k1)
    return xor_bytes(AESE(AESMC(u), zero), k0)


# Optimized ARM64 inverse round functions using Equivalent Inverse Cipher MC(k1)
def F_gamma_inv_arm_opt(x: bytes, k0: bytes, k1: bytes) -> bytes:
    zero = bytes(16)
    mc_k1 = AESMC(k1)
    u = AESD(AESIMC(x), zero)
    return xor_bytes(AESE(AESMC(u), mc_k1), k0)


def F_delta_inv_arm_opt(x: bytes, k0: bytes, k1: bytes) -> bytes:
    zero = bytes(16)
    mc_k1 = AESMC(k1)
    u = AESE(AESMC(x), zero)
    return xor_bytes(AESE(AESMC(u), mc_k1), k0)


# x86-64 AES-NI formulations
def F_gamma_x86(x: bytes, k0: bytes, k1: bytes) -> bytes:
    zero = bytes(16)
    return AESENC(AESDEC(xor_bytes(x, k0), k1), zero)


def F_delta_x86(x: bytes, k0: bytes, k1: bytes) -> bytes:
    zero = bytes(16)
    return AESDEC(AESDEC(xor_bytes(x, k0), k1), zero)


def F_gamma_inv_x86(x: bytes, k0: bytes, k1: bytes) -> bytes:
    zero = bytes(16)
    u = AESDECLAST(AESIMC(x), k1)
    mc_u = AESENC(AESDECLAST(u, zero), zero)
    return AESENCLAST(mc_u, k0)


def F_delta_inv_x86_opt(x: bytes, k0: bytes, k1: bytes) -> bytes:
    zero = bytes(16)
    mc_k1 = mix_columns(k1)
    mc_x = AESENC(AESDECLAST(x, zero), zero)
    mc_u = AESENC(mc_x, mc_k1)
    return AESENCLAST(mc_u, k0)


def asura_encrypt_preexpanded(pt: bytes, key: bytes, tweak: bytes, R: int = 6) -> bytes:
    rtks = asura_tweakey_schedule(key, tweak, R)
    x0, x1 = pt[:16], pt[16:]
    for r in range(R):
        k0_0, k0_1 = rtks[2 * r][0], rtks[2 * r + 1][0]
        k1_0, k1_1 = rtks[2 * r][1], rtks[2 * r + 1][1]
        x0 = F_gamma_arm(x0, k0_0, k0_1)
        x1 = F_delta_arm(x1, k1_0, k1_1)
        if r < R - 1:
            x0, x1 = perm256(x0, x1)
    x0 = xor_bytes(x0, rtks[2 * R][0])
    x1 = xor_bytes(x1, rtks[2 * R][1])
    return x0 + x1


def asura_decrypt_preexpanded(ct: bytes, key: bytes, tweak: bytes, R: int = 6) -> bytes:
    rtks = asura_tweakey_schedule(key, tweak, R)
    x0 = xor_bytes(ct[:16], rtks[2 * R][0])
    x1 = xor_bytes(ct[16:], rtks[2 * R][1])
    for r in range(R - 1, -1, -1):
        if r < R - 1:
            x0, x1 = inv_perm256(x0, x1)
        k0_0, k0_1 = rtks[2 * r][0], rtks[2 * r + 1][0]
        k1_0, k1_1 = rtks[2 * r][1], rtks[2 * r + 1][1]
        x0 = F_gamma_inv_arm(x0, k0_0, k0_1)
        x1 = F_delta_inv_arm(x1, k1_0, k1_1)
    return x0 + x1


def asura_encrypt_otf(pt: bytes, key: bytes, tweak: bytes, R: int = 6) -> bytes:
    k = key
    t = tweak
    x0, x1 = pt[:16], pt[16:]
    for r in range(R):
        k0_0, k1_0 = gamma(ASURA_RC[2 * r], k, t)
        t = theta(t)
        k = kappa(k)
        k0_1, k1_1 = gamma(ASURA_RC[2 * r + 1], k, t)
        t = theta(t)
        k = kappa(k)
        x0 = F_gamma_x86(x0, k0_0, k0_1)
        x1 = F_delta_x86(x1, k1_0, k1_1)
        if r < R - 1:
            x0, x1 = perm256(x0, x1)
    k0_f, k1_f = gamma(ASURA_RC[2 * R], k, t)
    return xor_bytes(x0, k0_f) + xor_bytes(x1, k1_f)


def asura_decrypt_otf(ct: bytes, key: bytes, tweak: bytes, R: int = 6) -> bytes:
    t_hist = [tweak]
    k = key
    for _ in range(2 * R):
        t_hist.append(theta(t_hist[-1]))
        k = kappa(k)
    k0_f, k1_f = gamma(ASURA_RC[2 * R], k, t_hist[2 * R])
    x0 = xor_bytes(ct[:16], k0_f)
    x1 = xor_bytes(ct[16:], k1_f)
    for r in range(R - 1, -1, -1):
        if r < R - 1:
            x0, x1 = inv_perm256(x0, x1)
        k = kappa_inv(k)
        k0_1, k1_1 = gamma(ASURA_RC[2 * r + 1], k, t_hist[2 * r + 1])
        k = kappa_inv(k)
        k0_0, k1_0 = gamma(ASURA_RC[2 * r], k, t_hist[2 * r])
        x0 = F_gamma_inv_x86(x0, k0_0, k0_1)
        x1 = F_delta_inv_x86_opt(x1, k1_0, k1_1)
    return x0 + x1


def verify_constants_go() -> bool:
    """Verifies that asuraRoundConstants in constants.go matches ASURA_RC byte-for-byte."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    constants_path = os.path.join(script_dir, "..", "constants.go")
    if not os.path.exists(constants_path):
        return False
    with open(constants_path, "r", encoding="utf-8") as f:
        content = f.read()
    m = re.search(r"var\s+asuraRoundConstants\s*=\s*\[13\]\[16\]byte\{(.*?)\n\}", content, re.DOTALL)
    if not m:
        return False
    rows = re.findall(r"\{([0-9a-fx,\s]+)\}", m.group(1))
    if len(rows) != 13:
        return False
    for r, row_str in enumerate(rows):
        b = bytes(int(x.strip(), 16) for x in row_str.split(",") if x.strip())
        if b != ASURA_RC[r]:
            return False
    return True


def verify_areion_test_go(expected_dict: dict[str, str]) -> bool:
    """Verifies that hardcoded KAT strings in areion_test.go match expected_dict."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    test_path = os.path.join(script_dir, "..", "areion_test.go")
    if not os.path.exists(test_path):
        return False
    with open(test_path, "r", encoding="utf-8") as f:
        content = f.read()
    for name, want_hex in expected_dict.items():
        m = re.search(rf'{name}\s*=\s*"([0-9a-fA-F]+)"', content)
        if not m or m.group(1).lower() != want_hex.lower():
            return False
    return True


def main() -> None:
    print("=" * 86)
    print("   ASURA 256-BIT TWEAKABLE BLOCK CIPHER SPECIFICATION & KAT VERIFICATION")
    print("   Reference: Tanaka et al. (INDOCRYPT 2024 / ePrint 2024/1394)")
    print("=" * 86)

    failures = 0

    # 1. Verify constants.go
    if verify_constants_go():
        print(" [PASS] asuraRoundConstants in constants.go matches Haraka v2 / Pholkos RC[0..12].")
    else:
        print(" [FAIL] asuraRoundConstants in constants.go mismatch!")
        failures += 1

    # 2. Verify key-schedule permutations and kappa invertibility
    pi256_bijection = sorted(PI_256) == list(range(8)) and all(PI_256[PI_256[i]] == i for i in range(8))
    pitau_bijection = sorted(PI_TAU) == list(range(16))
    test_k = bytes((0x37 + i * 19) & 0xff for i in range(32))
    kappa_roundtrip = True
    cur_k = test_k
    for _ in range(12):
        cur_k = kappa(cur_k)
    for _ in range(12):
        cur_k = kappa_inv(cur_k)
    if cur_k != test_k:
        kappa_roundtrip = False

    if pi256_bijection and pitau_bijection and kappa_roundtrip:
        print(" [PASS] Key-schedule permutations pi_256, pi o tau, and kappa^-1 o kappa == id.")
    else:
        print(" [FAIL] Key-schedule permutation or kappa invertibility check failed!")
        failures += 1

    # 3. Verify perm256 invertibility
    x0_test = bytes(range(16))
    x1_test = bytes(range(16, 32))
    y0_test, y1_test = perm256(x0_test, x1_test)
    if inv_perm256(y0_test, y1_test) == (x0_test, x1_test):
        print(" [PASS] 256-bit byte-shuffle inv_perm256(perm256(X)) == X.")
    else:
        print(" [FAIL] perm256 invertibility check failed!")
        failures += 1

    # 4. Verify ARM64, x86-64, and Equivalent Inverse Cipher round functions
    rf_ok = True
    for trial in range(16):
        x = bytes((trial * 17 + i * 31) & 0xff for i in range(16))
        k0 = bytes((trial * 29 + i * 13 + 7) & 0xff for i in range(16))
        k1 = bytes((trial * 41 + i * 23 + 3) & 0xff for i in range(16))

        fg_arm = F_gamma_arm(x, k0, k1)
        fg_x86 = F_gamma_x86(x, k0, k1)
        fd_arm = F_delta_arm(x, k0, k1)
        fd_x86 = F_delta_x86(x, k0, k1)

        if fg_arm != fg_x86 or fd_arm != fd_x86:
            rf_ok = False
            break
        if F_gamma_inv_arm(fg_arm, k0, k1) != x:
            rf_ok = False
            break
        if F_gamma_inv_arm_opt(fg_arm, k0, k1) != x:
            rf_ok = False
            break
        if F_gamma_inv_x86(fg_x86, k0, k1) != x:
            rf_ok = False
            break
        if F_delta_inv_arm(fd_arm, k0, k1) != x:
            rf_ok = False
            break
        if F_delta_inv_arm_opt(fd_arm, k0, k1) != x:
            rf_ok = False
            break
        if F_delta_inv_x86_opt(fd_x86, k0, k1) != x:
            rf_ok = False
            break

    if rf_ok:
        print(" [PASS] Round functions F_gamma, F_delta, and optimized inverses match across ARM64/x86-64.")
    else:
        print(" [FAIL] Round function equivalence or invertibility check failed!")
        failures += 1

    # 5. Derive KAT 0 (all-zero) and KAT 1 (sequential)
    z_pt = bytes(32)
    z_key = bytes(32)
    z_tw = bytes(16)
    c0_pre = asura_encrypt_preexpanded(z_pt, z_key, z_tw)
    c0_otf = asura_encrypt_otf(z_pt, z_key, z_tw)
    d0_pre = asura_decrypt_preexpanded(c0_pre, z_key, z_tw)
    d0_otf = asura_decrypt_otf(c0_otf, z_key, z_tw)

    s_pt = bytes(range(0x00, 0x20))
    s_key = bytes(range(0x20, 0x40))
    s_tw = bytes(range(0x40, 0x50))
    rtks_seq = asura_tweakey_schedule(s_key, s_tw)
    c1_pre = asura_encrypt_preexpanded(s_pt, s_key, s_tw)
    c1_otf = asura_encrypt_otf(s_pt, s_key, s_tw)
    d1_pre = asura_decrypt_preexpanded(c1_pre, s_key, s_tw)
    d1_otf = asura_decrypt_otf(c1_otf, s_key, s_tw)

    if c0_pre == c0_otf and d0_pre == z_pt and d0_otf == z_pt and c1_pre == c1_otf and d1_pre == s_pt and d1_otf == s_pt:
        print(" [PASS] Pre-expanded and on-the-fly (OTF) encrypt/decrypt match and invert on KAT vectors.")
    else:
        print(" [FAIL] Pre-expanded / OTF / round-trip check failed on KAT vectors!")
        failures += 1

    rtk0_hex = (rtks_seq[0][0] + rtks_seq[0][1]).hex()
    rtk1_hex = (rtks_seq[1][0] + rtks_seq[1][1]).hex()
    rtk2_hex = (rtks_seq[2][0] + rtks_seq[2][1]).hex()
    rtk12_hex = (rtks_seq[12][0] + rtks_seq[12][1]).hex()
    kat0_hex = c0_pre.hex()
    kat1_hex = c1_pre.hex()

    expected_kats = {
        "kat0Want": "74e5189f712dc78c0e6b8d9c8253722a8dd57144fb2698ff1c0654c56099d1cd",
        "kat1Want": "a75c46eaa0e513e883375fb0ed587c5793e84dead955f9a835d0bfb3ce1dd521",
        "rtk0Want": "fd1be115909ea5d26aa040862c10e46670707070707070707070707070707070",
        "rtk1Want": "2f2e1ebf5adf153de8124cbcb3a11e3b846825d410661a41701360166b198a83",
        "rtk2Want": "73172f4c1ba9752c70e2c36528af1770075566c57ac64439217e17c153a4d8ad",
        "rtk12Want": "8ed37f1e04067aba2599a5a7ac6dcb7c06f8836cef70c3169f2e88967a67277a",
    }

    derived_kats = {
        "kat0Want": kat0_hex,
        "kat1Want": kat1_hex,
        "rtk0Want": rtk0_hex,
        "rtk1Want": rtk1_hex,
        "rtk2Want": rtk2_hex,
        "rtk12Want": rtk12_hex,
    }

    if derived_kats == expected_kats:
        print(" [PASS] Derived KAT 0 and KAT 1 vectors match reference constants.")
    else:
        print(" [FAIL] Derived KAT vectors do not match reference constants!")
        failures += 1

    if verify_areion_test_go(expected_kats):
        print(" [PASS] TestAsuraKAT in areion_test.go matches derived KAT vectors byte-for-byte.")
    else:
        print(" [FAIL] TestAsuraKAT in areion_test.go does not match derived KAT vectors!")
        failures += 1

    print("\n" + "-" * 86)
    print(" DERIVED KNOWN-ANSWER TEST (KAT) VECTORS")
    print("-" * 86)
    print(f" KAT 0 (all-zero) C : {kat0_hex}")
    print(f" KAT 1 (seq) RTK[0] : {rtk0_hex}")
    print(f" KAT 1 (seq) RTK[1] : {rtk1_hex}")
    print(f" KAT 1 (seq) RTK[2] : {rtk2_hex}")
    print(f" KAT 1 (seq) RTK[12]: {rtk12_hex}")
    print(f" KAT 1 (seq) C      : {kat1_hex}")
    print("=" * 86)

    if failures == 0:
        print(" [+] All ASURA mathematical and KAT checks PASSED.")
        print("=" * 86)
        sys.exit(0)
    else:
        print(f" [!] FAILED: {failures} check(s) failed.")
        print("=" * 86)
        sys.exit(1)


if __name__ == "__main__":
    main()

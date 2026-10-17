# Areion & Areion-SoEM-256/512 Reference Library

Go reference implementation of the **Areion** cryptographic permutation family and the **SoEM22** pseudorandom function (PRF).

[![Go Reference](https://pkg.go.dev/badge/github.com/everanium/areion.svg)](https://pkg.go.dev/github.com/everanium/areion)
[![License: Apache-2.0 / MIT](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](#license)

---

## Overview

Areion (Isobe et al., [TCHES 2023](https://doi.org/10.46586/tches.v2023.i2.115-154); extended version [ePrint 2023/794](https://eprint.iacr.org/2023/794)) is a family of wide cryptographic permutations (256-bit and 512-bit) built from hardware AES round instructions (`AESENC` / `AESE`).

This library provides:
1. **Core Permutations ($P_1$)** (10-round Areion-256 and 15-round Areion-512 with the published round constants RC0..RC14 of Table 1):
   - `Permute256(state)`: 10-round forward permutation $P_1$ on a 32-byte `State256`.
   - `Permute512(state)`: 15-round forward permutation $P_1$ on a 64-byte `State512`.
   - `InversePermute256(state)`: 10-round inverse permutation $P_1^{-1}$ on a 32-byte `State256`.
   - `InversePermute512(state)`: 15-round inverse permutation $P_1^{-1}$ on a 64-byte `State512`.
   - `Permute256x4(states)`: 4-way parallel forward permutation $P_1$ on `*[4][32]byte`.
   - `Permute512x4(states)`: 4-way parallel forward permutation $P_1$ on `*[4][64]byte`.
   - `InversePermute256x4(states)`: 4-way parallel inverse permutation $P_1^{-1}$ on `*[4][32]byte`.
   - `InversePermute512x4(states)`: 4-way parallel inverse permutation $P_1^{-1}$ on `*[4][64]byte`.
2. **Second Permutations ($P_2$)** (the Areion permutations under a second round-constant table, Table 2 — the 15 consecutive 128-bit words of $\pi$ that follow those of $P_1$, words 15..29; proposed by Andrey Kuvshinov and derived by [`scripts/verify_p2_table.py`](scripts/README.md), not part of the Areion specification):
   - `Permute256P2(state)`: 10-round forward permutation $P_2$ on a 32-byte `State256`.
   - `Permute512P2(state)`: 15-round forward permutation $P_2$ on a 64-byte `State512`.
   - `InversePermute256P2(state)`: 10-round inverse permutation $P_2^{-1}$ on a 32-byte `State256`.
   - `InversePermute512P2(state)`: 15-round inverse permutation $P_2^{-1}$ on a 64-byte `State512`.
   - `Permute256P2x4(states)`: 4-way parallel forward permutation $P_2$ on `*[4][32]byte`.
   - `Permute512P2x4(states)`: 4-way parallel forward permutation $P_2$ on `*[4][64]byte`.
   - `InversePermute256P2x4(states)`: 4-way parallel inverse permutation $P_2^{-1}$ on `*[4][32]byte`.
   - `InversePermute512P2x4(states)`: 4-way parallel inverse permutation $P_2^{-1}$ on `*[4][64]byte`.
3. **Davies-Meyer Compression Functions**:
   - `DM256(m)`: 32-byte digest computed as $h = P_1(m) \oplus m$.
   - `DM512(m)`: 32-byte digest $\mathrm{trunc}(P_1(m) \oplus m)$ with the truncation of Section 4.1.1, Eq. (3) of ePrint 2023/794 (32-bit words $x_2 \parallel x_3 \parallel x_6 \parallel x_7 \parallel x_8 \parallel x_9 \parallel x_{12} \parallel x_{13}$).
4. **Sum of Even-Mansour (SoEM22) PRFs**:
   - `SoEM256(key, m)`: single-block PRF with a 32-byte input, a 32-byte output, and a 64-byte key ($k_1 \parallel k_2$).
   - `SoEM512(key, m)`: single-block PRF with a 64-byte input, a 64-byte output, and a 128-byte key ($k_1 \parallel k_2$).
   - `SoEM256x4(keys, inputs)`: 4-way parallel PRF evaluation over `*[4][64]byte` keys and `*[4][32]byte` inputs.
   - `SoEM512x4(keys, inputs)`: 4-way parallel PRF evaluation over `*[4][128]byte` keys and `*[4][64]byte` inputs.
5. **AES-128 Round & Block Primitives**:
   - Types: `Block = [16]byte`, `Block4 = [64]byte`, `Key4 = [64]byte`.
   - `AES128Round(state, roundKey)`: hardware-dispatched single-block AES round (`SubBytes` -> `ShiftRows` -> `MixColumns` -> `AddRoundKey`).
   - `RoundHW(state, roundKey)`: alias for `AES128Round`.
   - `Round(state, roundKey)`: constant-time bitsliced software single-block AES round.
   - `AES128FinalRound(state, roundKey)`: hardware-dispatched single-block AES final round (`SubBytes` -> `ShiftRows` -> `AddRoundKey`, without `MixColumns`).
   - `FinalRoundHW(state, roundKey)`: alias for `AES128FinalRound`.
   - `FinalRound(state, roundKey)`: constant-time bitsliced software single-block AES final round.
   - `AES128Round4(state, roundKeys)`: hardware-dispatched 4-block parallel AES round.
   - `Round4HW(state, roundKeys)`: alias for `AES128Round4`.
   - `AES128FinalRound4(state, roundKeys)`: hardware-dispatched 4-block parallel AES final round without `MixColumns`.
   - `FinalRound4HW(state, roundKeys)`: alias for `AES128FinalRound4`.
   - `XorBlock(dst, a, b)`: 16-byte XOR helper (`dst = a ^ b`).
   - `XorBlock4(dst, a, b)`: 64-byte XOR helper (`dst = a ^ b`).
   - `ExpandKey128(key, rk)`: AES-128 key schedule expansion to 11 round keys.
   - `AES128EncryptBlock(rk, dst, src)`: full 10-round AES-128 single-block encryption.
   - `AES128Encrypt4Blocks(rk, dst, src)`: full 10-round AES-128 4-block parallel encryption.

Depends only on `golang.org/x/sys/cpu`.

---

## Security: SoEM22 vs. Single-Permutation SoEM

### Shift Symmetry in Single-Permutation SoEM
A construction attempting to build SoEM from a single permutation $P$ with a constant difference $d$:
$$F(m) = P(m \oplus k_1) \oplus P(m \oplus k_2 \oplus d)$$
has a shift symmetry: for any input $m$, letting $m' = m \oplus k_1 \oplus k_2 \oplus d$ yields:
$$F(m') = P(m' \oplus k_1) \oplus P(m' \oplus k_2 \oplus d) = P(m \oplus k_2 \oplus d) \oplus P(m \oplus k_1) = F(m)$$
The shift $k_1 \oplus k_2 \oplus d$ is secret, but an adversary finds a colliding pair among about $2^{n/2}$ queries and then confirms it on a second pair at the same offset, so security does not exceed the birthday bound. This is the attack on SoEM1 ($\pi_1 = \pi_2$) in Section 4.1 of Chen, Lambooij, and Mennink, with the offset $d$ added.

### SoEM22
[Chen, Lambooij, and Mennink (CRYPTO 2019)](https://eprint.iacr.org/2019/554) prove SoEM22 secure up to about $2^{2n/3}$ queries (Theorem 1) when $P_1$ and $P_2$ are two independent random permutations and $k_1$, $k_2$ are independent random keys:
$$F(k_1, k_2, m) = P_1(m \oplus k_1) \oplus P_2(m \oplus k_2) \oplus k_1 \oplus k_2$$
This library instantiates $P_1$ and $P_2$ as the Areion permutation under two different round-constant tables. Treating the two as independent permutations is an assumption about this instantiation, not a proven property. Stated in standard terms: if the round-constant table is regarded as the key of a block cipher, $P_1$ and $P_2$ are that cipher under two fixed, related keys, and the assumption is that this pair cannot be distinguished from two independent random permutations — a related-key assumption on Areion, not a consequence of the two tables being distinct.

### Table 2 Round Constants ($P_2$)
Table 2 is proposed by Andrey Kuvshinov and derived by `scripts/verify_p2_table.py`. Following the Nothing-Up-My-Sleeve (NUMS) methodology of the original Areion paper, it continues the same stream of $\pi$ words:
- **Table 1 ($P_1$)**: Words 0..14 of the fractional part of $\pi$ (Table 1 and Appendix A.1 of ePrint 2023/794); RC7 is kept as published, `0x801f2e2858efc16636920d871574e690`, a one-nibble shift from $\pi$ word 7.
- **Table 2 ($P_2$)**: Words 15..29 of the fractional part of $\pi$ (15 consecutive 128-bit words); RC7, $\pi$ word 22, takes the same one-nibble shift, `0xf6d6ff383f442392e0b4482a48420040`, in agreement with the Areion authors. Words 7 and 22 are the only words among 0..29 that begin with a zero nibble, so the shift falls on RC7 in both tables. The shift is a matter of consistency with Table 1: every claim of [`analysis/`](analysis/README.md) holds for both forms of this word.

[`scripts/verify_p2_table.py`](scripts/README.md) checks:
- All 30 constants are distinct ($|P_1 \cap P_2| = 0$).
- Combined matrix $[P_1; P_2]$ has full rank 30 over $\mathrm{GF}(2)$.
- Hamming distance between $P_1[i]$ and $P_2[j]$ over all 225 pairs: min 50, mean 63.73.
- RC7 of both tables is the $\pi$ word shifted by one nibble.
- No $P_2$ word has two equal 32-bit columns.

[`analysis/`](analysis/README.md) looks for structure tying $P_2$ to $P_1$ beyond these constant checks: related-constant differential bounds, linear trail bounds, boomerang estimates, symmetries, invariant subspaces and nonlinear invariants, impossible differentials, integral sums, and affine equivalence, each within a stated model; the checks that depend on $P_2$ also cover the plain $\pi$ word 22 as its RC7, and $P_1$'s published RC7 can likewise be replaced by the plain $\pi$ word for comparison.

---

## Hardware Acceleration

The package automatically detects host CPU features:

| Tier | Architectures | Instructions Used | Register Width (x4 functions) |
| :--- | :--- | :--- | :--- |
| **`avx512`** | Intel Ice Lake, Tiger Lake, Rocket Lake, Xeon Ice Lake-SP+; AMD Zen 4+ | `VAESENC`, `VAESENCLAST`, `VAESDECLAST`, `VAESIMC` | 512-bit ZMM (4 AES blocks) |
| **`vaesavx2`** | Intel Alder Lake+ (no AVX-512); AMD Zen 3 | `VAESENC`, `VAESENCLAST`, `VAESDECLAST`, `VAESIMC` | 256-bit YMM (2 AES blocks) |
| **`vex`** | Intel Sandy Bridge+, AMD Bulldozer+ (`AVX + AES-NI`) | 3-operand VEX XMM `VAESENC`, `VAESENCLAST`, `VAESDECLAST`, `VAESIMC`, `VPXOR` | 128-bit XMM (3-operand VEX) |
| **`aesni`** | Intel Westmere+ (`AES-NI` without `AVX`) | Legacy SSE `AESENC`, `AESENCLAST`, `AESDECLAST`, `AESIMC`, `PXOR` | 128-bit XMM (2-operand SSE) |
| **`arm64`** | ARMv8 with Cryptographic Extension, Apple Silicon, Graviton | `AESE`, `AESMC`, `AESD`, `AESIMC` | 128-bit NEON |
| **`purego`** | All architectures | Constant-time 64-bit bitsliced Boyar–Peralta S-box & linear layer | 64-bit bitsliced software (up to 4 blocks/word) |

> **Note on single-block execution:** Single-block functions (`Permute256/512`, `InversePermute256/512` and their `P2` forms, `DM256/512`, `SoEM256/512`, `AES128Round`, `AES128FinalRound`, `AES128EncryptBlock`) use 3-operand VEX XMM instructions on `vex`, `vaesavx2`, and `avx512` tiers (eliminating destructive `MOVOA` register copies and legacy SSE transition penalties), and legacy 2-operand XMM instructions on `aesni`. `SoEM256` and `SoEM512` execute both $P_1(m \oplus k_1)$ and $P_2(m \oplus k_2)$ interleaved in a single assembly call.

> **Note on VAES detection:** `golang.org/x/sys/cpu` reports VAES only together with AVX-512; the package reads CPUID leaf 7 directly so that VAES+AVX2 hosts (AMD Zen 3, Intel Alder Lake) activate the `vaesavx2` tier.

---

## Benchmarks

### 1. Intel® Core™ i7-11700K @ 3.60GHz (Rocket Lake, x86-64)

Throughput comparison across execution tiers on the same physical CPU:

| Operation | `purego` (Bitsliced) | `aesni` (128-bit SSE) | `vex` (128-bit VEX) | `vaesavx2` (256-bit YMM) | `avx512` (512-bit ZMM) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`Permute256`** | 39.9 MB/s (801.7 ns) | 2,089 MB/s (15.3 ns) | 2,118 MB/s (15.1 ns) | 2,145 MB/s (14.9 ns) | 2,144 MB/s (14.9 ns) |
| **`Permute512`** | 44.0 MB/s (1,454 ns) | 4,125 MB/s (15.5 ns) | 4,046 MB/s (15.8 ns) | 4,051 MB/s (15.8 ns) | 4,062 MB/s (15.8 ns) |
| **`InversePermute256`** | 38.2 MB/s (837.5 ns) | 1,473 MB/s (21.7 ns) | 1,475 MB/s (21.7 ns) | 1,477 MB/s (21.7 ns) | 1,475 MB/s (21.7 ns) |
| **`InversePermute512`** | 34.2 MB/s (1,870 ns) | 1,735 MB/s (36.9 ns) | 1,732 MB/s (37.0 ns) | 1,732 MB/s (36.9 ns) | 1,731 MB/s (37.0 ns) |
| **`DM256`** | 39.4 MB/s (812.7 ns) | 1,088 MB/s (29.4 ns) | 1,142 MB/s (28.0 ns) | 1,149 MB/s (27.9 ns) | 1,151 MB/s (27.8 ns) |
| **`DM512`** | 43.8 MB/s (1,462 ns) | 1,537 MB/s (41.6 ns) | 1,558 MB/s (41.1 ns) | 1,559 MB/s (41.1 ns) | 1,556 MB/s (41.1 ns) |
| **`SoEM256`** (single) | 37.6 MB/s (850.9 ns) | 3,208 MB/s (9.98 ns) | 3,358 MB/s (9.53 ns) | 3,363 MB/s (9.52 ns) | 3,373 MB/s (9.49 ns) |
| **`SoEM512`** (single) | 41.8 MB/s (1,530 ns) | 3,098 MB/s (20.7 ns) | 3,391 MB/s (18.9 ns) | 3,408 MB/s (18.8 ns) | 3,266 MB/s (19.6 ns) |
| **`Permute256x4`** | 150.2 MB/s (852.0 ns) | 5,383 MB/s (23.8 ns) | 5,104 MB/s (25.1 ns) | 4,543 MB/s (28.2 ns) | 4,361 MB/s (29.4 ns) |
| **`Permute512x4`** | 130.7 MB/s (1,959 ns) | 4,600 MB/s (55.7 ns) | 4,657 MB/s (55.0 ns) | 6,020 MB/s (42.5 ns) | 6,273 MB/s (40.8 ns) |
| **`InversePermute256x4`** | 141.0 MB/s (907.5 ns) | 4,621 MB/s (27.7 ns) | 4,802 MB/s (26.7 ns) | 3,684 MB/s (34.8 ns) | 3,678 MB/s (34.8 ns) |
| **`InversePermute512x4`** | 114.8 MB/s (2,230 ns) | 2,863 MB/s (89.4 ns) | 2,970 MB/s (86.2 ns) | 3,194 MB/s (80.2 ns) | 2,632 MB/s (97.3 ns) |
| **`SoEM256x4`** | 72.4 MB/s (1,768 ns) | 2,667 MB/s (48.0 ns) | 2,603 MB/s (49.2 ns) | 3,432 MB/s (37.3 ns) | 3,270 MB/s (39.2 ns) |
| **`SoEM512x4`** | 64.5 MB/s (3,967 ns) | 2,128 MB/s (120.3 ns) | 2,153 MB/s (118.9 ns) | 3,037 MB/s (84.3 ns) | 3,147 MB/s (81.4 ns) |
| **`AES128Round`** | 315 MB/s (50.7 ns) | 6,999 MB/s (2.29 ns) | 7,678 MB/s (2.08 ns) | 7,654 MB/s (2.09 ns) | 7,685 MB/s (2.08 ns) |
| **`AES128Round4`** | 739 MB/s (86.6 ns) | 16,428 MB/s (3.90 ns) | 18,806 MB/s (3.40 ns) | 21,711 MB/s (2.95 ns) | 25,427 MB/s (2.52 ns) |
| **`ExpandKey128`** | 550 MB/s (320.2 ns) | 1,155 MB/s (152.4 ns) | 1,169 MB/s (150.5 ns) | 1,171 MB/s (150.2 ns) | 1,162 MB/s (151.4 ns) |
| **`AES128EncryptBlock`** | 34.6 MB/s (461.9 ns) | 1,902 MB/s (8.41 ns) | 1,918 MB/s (8.34 ns) | 1,917 MB/s (8.35 ns) | 1,911 MB/s (8.37 ns) |
| **`AES128Encrypt4Blocks`** | 125.5 MB/s (510.0 ns) | 7,473 MB/s (8.56 ns) | 7,469 MB/s (8.57 ns) | 7,449 MB/s (8.59 ns) | 7,453 MB/s (8.59 ns) |

All operations: 0 B/op, 0 allocs/op.

### 2. Graviton 4 (Neoverse V2, 16 vCPUs, ARM64)

Measured on Graviton 4 (`purego` bitsliced fallback vs `arm64` ARMv8 Cryptographic Extension):

| Operation | `purego` (Bitsliced) | `arm64` (128-bit NEON) |
| :--- | :---: | :---: |
| **`Permute256`** | 35.7 MB/s (897.2 ns) | 928.1 MB/s (34.5 ns) |
| **`Permute512`** | 40.3 MB/s (1,587 ns) | 1,570.8 MB/s (40.7 ns) |
| **`InversePermute256`** | 35.0 MB/s (915.4 ns) | 769.2 MB/s (41.6 ns) |
| **`InversePermute512`** | 30.7 MB/s (2,085 ns) | 1,031.4 MB/s (62.1 ns) |
| **`DM256`** | 35.1 MB/s (913.1 ns) | 653.0 MB/s (49.0 ns) |
| **`DM512`** | 39.4 MB/s (1,623 ns) | 952.6 MB/s (67.2 ns) |
| **`SoEM256`** (single) | 33.8 MB/s (946.2 ns) | 837.8 MB/s (38.2 ns) |
| **`SoEM512`** (single) | 37.7 MB/s (1,698 ns) | 1,133.0 MB/s (56.5 ns) |
| **`Permute256x4`** | 134.3 MB/s (953.1 ns) | 3,052.2 MB/s (41.9 ns) |
| **`Permute512x4`** | 118.2 MB/s (2,165 ns) | 3,448.8 MB/s (74.2 ns) |
| **`InversePermute256x4`** | 131.3 MB/s (974.7 ns) | 2,573.2 MB/s (49.7 ns) |
| **`InversePermute512x4`** | 100.3 MB/s (2,551 ns) | 2,674.1 MB/s (95.7 ns) |
| **`SoEM256x4`** | 65.4 MB/s (1,958 ns) | 1,760.0 MB/s (72.7 ns) |
| **`SoEM512x4`** | 57.4 MB/s (4,462 ns) | 1,292.6 MB/s (198.0 ns) |
| **`AES128Round`** | 281 MB/s (56.9 ns) | 4,452.3 MB/s (3.59 ns) |
| **`AES128Round4`** | 712 MB/s (89.9 ns) | 16,047.6 MB/s (3.99 ns) |
| **`ExpandKey128`** | 480 MB/s (366.6 ns) | 823.2 MB/s (213.8 ns) |
| **`AES128EncryptBlock`** | 32.8 MB/s (488.3 ns) | 1,589.9 MB/s (10.1 ns) |
| **`AES128Encrypt4Blocks`** | 117.3 MB/s (545.8 ns) | 6,287.1 MB/s (10.2 ns) |

All operations: 0 B/op, 0 allocs/op.

---

## Reproduce

### 1. Run Complete Test Suite
```bash
# Run all unit tests, known-answer tests, and roundtrips:
go test -v -count=1 ./...

# Verify clean asmdecl and cross-architecture compilation:
go vet ./...
GOARCH=arm64 go vet ./...
go vet -tags purego ./...
```

### 2. Test Specific Execution Tiers
The environment variable `AREION_FORCE_TIER` forces the execution tier:
```bash
# Portable Go scalar fallback:
AREION_FORCE_TIER=purego go test -v -count=1 ./...

# AES-NI (128-bit legacy SSE XMM):
AREION_FORCE_TIER=aesni go test -v -count=1 ./...

# VEX (128-bit 3-operand VEX XMM, AVX + AES-NI):
AREION_FORCE_TIER=vex go test -v -count=1 ./...

# 256-bit YMM Vector AES (AVX2 + VAES):
AREION_FORCE_TIER=vaesavx2 go test -v -count=1 ./...

# 512-bit ZMM Vector AES (AVX-512 + VAES):
AREION_FORCE_TIER=avx512 go test -v -count=1 ./...

# ARMv8 Cryptographic Extension (on arm64 hosts):
AREION_FORCE_TIER=arm64 go test -v -count=1 ./...
```

### 3. Run Benchmarks
```bash
# Auto-selected tier:
go test -run '^$' -bench=. -benchmem ./...

# Benchmark individual tiers:
AREION_FORCE_TIER=purego go test -run '^$' -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=aesni go test -run '^$' -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=vex go test -run '^$' -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=vaesavx2 go test -run '^$' -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=avx512 go test -run '^$' -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=arm64 go test -run '^$' -bench=. -benchmem -benchtime=500ms -count=1 ./...
```

### 4. Verify Round Constant Derivation
```bash
python3 scripts/verify_p2_table.py
```

### 5. P1 / P2 Analysis
```bash
python3 analysis/run.py list
python3 analysis/run.py all --quick
```
See [`analysis/README.md`](analysis/README.md) for each check and its dependencies (`python-sat` and `highspy` among them); `run.py list` prints the full and `--quick` run time of each check.

---

## Usage Example

```go
package main

import (
	"fmt"

	"github.com/everanium/areion"
)

func main() {
	// 1. Single-block permutation P1
	var state areion.State256
	areion.Permute256(&state)
	fmt.Printf("Permuted: %x\n", state)

	// 2. Davies-Meyer hashing
	var msg [32]byte
	digest := areion.DM256(&msg)
	fmt.Printf("DM256 Digest: %x\n", digest)

	// 3. SoEM22 PRF
	var key [64]byte // k1 || k2
	prf := areion.SoEM256(&key, &msg)
	fmt.Printf("SoEM22 PRF: %x\n", prf)
}
```

---

## References

1. **Areion: Highly-Efficient Permutations and Its Applications to Hash Functions for Short Input**
   Takanori Isobe, Ryoma Ito, Fukang Liu, Kazuhiko Minematsu, Motoki Nakahashi, Kosei Sakamoto, Rentaro Shiba.
   *IACR Transactions on Cryptographic Hardware and Embedded Systems (TCHES)*, Volume 2023, Issue 2, pp. 115–154, [doi:10.46586/tches.v2023.i2.115-154](https://doi.org/10.46586/tches.v2023.i2.115-154).
   Extended version: **Areion: Highly-Efficient Permutations and Its Applications (Extended Version)**, [IACR ePrint 2023/794](https://eprint.iacr.org/2023/794). Section, table, equation, and appendix numbers in this repository refer to the extended version.

2. **How to Build Pseudorandom Functions from Public Random Permutations**
   Yu Long Chen, Eran Lambooij, Bart Mennink.
   *CRYPTO 2019*, Part I, Lecture Notes in Computer Science, vol. 11692, pp. 266–293, [doi:10.1007/978-3-030-26948-7_10](https://doi.org/10.1007/978-3-030-26948-7_10), [IACR ePrint 2019/554](https://eprint.iacr.org/2019/554).

---

## License

Dual-licensed under either:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

Copyright (c) 2026 Andrey Kuvshinov.

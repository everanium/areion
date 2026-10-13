# Areion & Areion-SoEM-256/512 Reference Library

Go reference implementation of the **Areion** cryptographic permutation family and the **SoEM22** pseudorandom function (PRF).

[![Go Reference](https://pkg.go.dev/badge/github.com/everanium/areion.svg)](https://pkg.go.dev/github.com/everanium/areion)
[![License: Apache-2.0 / MIT](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](#license)

---

## Overview

Areion (Isobe et al., [TCHES 2023](https://doi.org/10.46586/tches.v2023.i2.115-154); extended version [ePrint 2023/794](https://eprint.iacr.org/2023/794)) is a family of wide cryptographic permutations (256-bit and 512-bit) built from hardware AES round instructions (`AESENC` / `AESE`).

This library provides:
1. **Core Permutations ($P_1$)**:
   - `Permute256`: 10-round Areion-256 permutation with the published round constants RC0..RC9 (Table 1).
   - `Permute512`: 15-round Areion-512 permutation with the published round constants RC0..RC14 (Table 1).
   - `InversePermute256` / `InversePermute512`: inverse permutations ($P_1^{-1}$).
   - `Permute256x4` / `Permute512x4`: 4-way parallel evaluation of $P_1$.
2. **Second Permutation ($P_2$)**:
   - `Permute256P2` / `Permute512P2`: the Areion permutation under a second round-constant table (Table 2), the 15 consecutive 128-bit words of $\pi$ that follow those of $P_1$ (words 15..29). Table 2 is proposed by Andrey Kuvshinov and derived by [`scripts/verify_p2_table.py`](scripts/README.md); it is not part of the Areion specification.
3. **Davies-Meyer Compression Functions**:
   - `DM256(m)`: 32-byte digest computed as $h = P_1(m) \oplus m$.
   - `DM512(m)`: 32-byte digest $\mathrm{trunc}(P_1(m) \oplus m)$ with the truncation of Section 4.1.1, Eq. (3) of ePrint 2023/794 (32-bit words $x_2 \parallel x_3 \parallel x_6 \parallel x_7 \parallel x_8 \parallel x_9 \parallel x_{12} \parallel x_{13}$).
4. **Sum of Even-Mansour (SoEM22) PRFs**:
   - `SoEM256(key, m)`: PRF with a 32-byte input, a 32-byte output, and a 64-byte key ($k_1 \parallel k_2$).
   - `SoEM512(key, m)`: PRF with a 64-byte input, a 64-byte output, and a 128-byte key ($k_1 \parallel k_2$).
   - `SoEM256x4` / `SoEM512x4`: 4-way batched PRF evaluation.

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
- **Table 2 ($P_2$)**: Words 15..29 of the fractional part of $\pi$ (15 consecutive 128-bit words).

[`scripts/verify_p2_table.py`](scripts/README.md) checks:
- All 30 constants are distinct ($|P_1 \cap P_2| = 0$).
- Combined matrix $[P_1; P_2]$ has full rank 30 over $\mathrm{GF}(2)$.
- Hamming distance between $P_1[i]$ and $P_2[j]$ over all 225 pairs: min 51, mean 63.55.
- No $P_2$ word has two equal 32-bit columns.

---

## Hardware Acceleration

The package automatically detects host CPU features:

| Tier | Architectures | Instructions Used | Register Width (x4 functions) |
| :--- | :--- | :--- | :--- |
| **`avx512`** | Intel Ice Lake, Tiger Lake, Rocket Lake, Xeon Ice Lake-SP+; AMD Zen 4+ | `VAESENC`, `VAESENCLAST` | 512-bit ZMM (4 AES blocks) |
| **`vaesavx2`** | Intel Alder Lake+ (no AVX-512); AMD Zen 3 | `VAESENC`, `VAESENCLAST` | 256-bit YMM (2 AES blocks) |
| **`aesni`** | Intel Westmere+, AMD Bulldozer+ | `AESENC`, `AESENCLAST`, `AESDECLAST`, `AESIMC` | 128-bit XMM (1 AES block) |
| **`arm64`** | ARMv8 with Cryptographic Extension, Apple Silicon, Graviton | `AESE`, `AESMC`, `AESD`, `AESIMC` | 128-bit NEON |
| **`purego`** | All architectures | Portable pure Go table-based software (not constant-time) | Software scalar fallback |

> **Note on single-block execution:** Single-block functions (`Permute256/512`, `InversePermute256/512`, `DM256/512`, `SoEM256/512`) route to the scalar AES-NI kernel on all x86 hardware tiers; their throughput is therefore identical across `aesni`, `vaesavx2`, and `avx512`. The `vaesavx2` and `avx512` vector tiers accelerate the `x4` batched functions.

> **Note on VAES detection:** `golang.org/x/sys/cpu` reports VAES only together with AVX-512; the package reads CPUID leaf 7 directly so that VAES+AVX2 hosts (AMD Zen 3, Intel Alder Lake) activate the `vaesavx2` tier.

---

## Benchmarks

### 1. Intel® Core™ i7-11700K @ 3.60GHz (Rocket Lake, x86-64)

Throughput comparison across execution tiers on the same physical CPU:

| Operation | `purego` (Scalar) | `aesni` (128-bit XMM) | `vaesavx2` (256-bit YMM) | `avx512` (512-bit ZMM Fused) |
| :--- | :---: | :---: | :---: | :---: |
| **`Permute256`** | 58.7 MB/s (545.0 ns) | 2,086 MB/s (15.3 ns) | 2,087 MB/s (15.3 ns) | 2,073 MB/s (15.4 ns) |
| **`Permute512`** | 48.5 MB/s (1,321 ns) | 3,920 MB/s (16.3 ns) | 3,919 MB/s (16.3 ns) | 3,909 MB/s (16.4 ns) |
| **`InversePermute256`** | 54.1 MB/s (591.9 ns) | 1,472 MB/s (21.7 ns) | 1,474 MB/s (21.7 ns) | 1,469 MB/s (21.8 ns) |
| **`InversePermute512`** | 27.8 MB/s (2,300 ns) | 1,723 MB/s (37.1 ns) | 1,719 MB/s (37.2 ns) | 1,717 MB/s (37.3 ns) |
| **`DM256`** | 56.5 MB/s (566.1 ns) | 1,098 MB/s (29.1 ns) | 1,106 MB/s (28.9 ns) | 1,098 MB/s (29.1 ns) |
| **`DM512`** | 47.2 MB/s (1,356 ns) | 1,338 MB/s (47.8 ns) | 1,400 MB/s (45.7 ns) | 1,328 MB/s (48.2 ns) |
| **`SoEM256`** (single) | 28.0 MB/s (1,141 ns) | 457 MB/s (70.0 ns) | 458 MB/s (69.8 ns) | 460 MB/s (69.6 ns) |
| **`SoEM512`** (single) | 23.1 MB/s (2,770 ns) | 511 MB/s (125.2 ns) | 515 MB/s (124.3 ns) | 505 MB/s (126.8 ns) |
| **`Permute256x4`** | 58.4 MB/s (2,193 ns) | 4,628 MB/s (27.7 ns) | 4,336 MB/s (29.5 ns) | 4,315 MB/s (29.7 ns) |
| **`Permute512x4`** | 48.2 MB/s (5,309 ns) | 3,841 MB/s (66.7 ns) | 4,849 MB/s (52.8 ns) | 5,080 MB/s (50.4 ns) |
| **`SoEM256x4`** | 28.1 MB/s (4,562 ns) | 2,679 MB/s (47.8 ns) | 1,547 MB/s (82.8 ns) | 3,464 MB/s (37.0 ns) |
| **`SoEM512x4`** | 23.2 MB/s (11,019 ns) | 1,940 MB/s (132.0 ns) | 1,634 MB/s (156.7 ns) | 3,259 MB/s (78.5 ns) |

All operations: 0 B/op, 0 allocs/op.

On this host the `vaesavx2` tier is slower than `aesni` for `Permute256x4`, `SoEM256x4`, and `SoEM512x4`. The automatic selection still picks `vaesavx2` on hosts with VAES and AVX2 but without AVX-512; `AREION_FORCE_TIER=aesni` or `SetTier("aesni")` selects the AES-NI kernels.

### 2. Graviton 4 (Neoverse V2, 16 vCPUs, ARM64)

Measured on Graviton 4 (ARMv8 Cryptographic Extension):

| Operation | Throughput | Latency |
| :--- | :---: | :---: |
| **`Permute256`** | 656.3 MB/s | 48.8 ns/op |
| **`Permute512`** | 1,236.7 MB/s | 51.8 ns/op |
| **`InversePermute256`** | 656.0 MB/s | 48.8 ns/op |
| **`InversePermute512`** | 692.1 MB/s | 92.5 ns/op |
| **`DM256`** | 523.4 MB/s | 61.1 ns/op |
| **`DM512`** | 787.4 MB/s | 81.3 ns/op |
| **`SoEM256`** (single) | 265.5 MB/s | 120.5 ns/op |
| **`SoEM512`** (single) | 306.3 MB/s | 209.0 ns/op |
| **`Permute256x4`** | 1,745.3 MB/s | 73.3 ns/op |
| **`Permute512x4`** | 2,342.9 MB/s | 109.3 ns/op |
| **`SoEM256x4`** | 306.8 MB/s | 417.2 ns/op |
| **`SoEM512x4`** | 327.3 MB/s | 782.2 ns/op |

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

# AES-NI (128-bit XMM):
AREION_FORCE_TIER=aesni go test -v -count=1 ./...

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
AREION_FORCE_TIER=vaesavx2 go test -run '^$' -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=avx512 go test -run '^$' -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=arm64 go test -run '^$' -bench=. -benchmem -benchtime=500ms -count=1 ./...
```

### 4. Verify Round Constant Derivation
```bash
python3 scripts/verify_p2_table.py
```

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

Includes code derived from Frank Denis's [go-aes](https://github.com/jedisct1/go-aes) (MIT License).

Copyright (c) 2026 Andrey Kuvshinov.

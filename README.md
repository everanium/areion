## Areion, Areion-SoEM-256/512 & Wide-Block Even-Mansour (EM / EM2 / TEM / TEM2) Go + Assembly Reference Library

Go + Assembly reference implementation of the **Areion** cryptographic permutation family, **Davies-Meyer** short-input compression, the **SoEM22** pseudorandom function (PRF), and four families of **256-bit and 512-bit wide-block Even-Mansour and Tweakable Even-Mansour ciphers (`EM`, `EM2`, `TEM`, `TEM2`)**.
Companion C + Assembly reference library: **[`everanium/areion-c`](https://github.com/everanium/areion-c)**.

[![Go Reference](https://pkg.go.dev/badge/github.com/everanium/areion.svg)](https://pkg.go.dev/github.com/everanium/areion)
[![golangci-lint](https://img.shields.io/badge/golangci--lint-passing-green)](https://golangci-lint.run)
[![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen)](https://github.com/everanium/areion)
[![License: Apache-2.0 / MIT](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](#license)

---

## Overview

Areion (Isobe et al., [TCHES 2023](https://doi.org/10.46586/tches.v2023.i2.115-154); extended version [ePrint 2023/794](https://eprint.iacr.org/2023/794)) is a family of 256-bit (10-round) and 512-bit (15-round) cryptographic permutations built from hardware AES round instructions (`AESENC` / `AESE`).

- **Permutations (`P1` and `P2`, Forward & Inverse)**: 256-bit and 512-bit forward and inverse permutations `P1 / P1⁻¹` (Table 1, π words `0..14`) and domain-separated second permutations `P2 / P2⁻¹` (Table 2, π words `15..29`; see [`scripts/verify_p2_table.py`](scripts/README.md)).
- **Davies-Meyer Short-Input Compression (`DM256`, `DM512`)**: Fixed-input compression functions producing a 256-bit (32-byte) digest from a 32-byte or 64-byte block (Section 4.1.1 of [ePrint 2023/794](https://eprint.iacr.org/2023/794)).
- **Beyond-Birthday-Bound PRFs (`SoEM22`)**: 256-bit and 512-bit Sum of Even-Mansour pseudorandom functions `P1(M ⊕ K1) ⊕ P2(M ⊕ K2) ⊕ K1 ⊕ K2` ([Chen, Lambooij, and Mennink, CRYPTO 2019](https://eprint.iacr.org/2019/554)), secure up to `2^(2n/3)` queries in the ideal-permutation model.
- **Invertible Wide-Block Ciphers (`EM`, `EM2`, `TEM`, `TEM2`)**: Four 256-bit and 512-bit wide-block cipher families — 1-round Even-Mansour (`EM`, birthday-bound PRP), 2-round Even-Mansour (`EM2`, BBB `2^(2n/3)` PRP), 1-round Tweakable Even-Mansour (`TEM`, birthday-bound TPRP), and 2-round Tweakable Even-Mansour (`TEM2`, BBB `2^(2n/3)` TPRP).
- **4-Way Parallel SIMD Batching (`×4`)**: Batched `×4` entry points across all permutations, `SoEM22` PRFs, and `EM / EM2 / TEM / TEM2` wide-block ciphers.
- **Multi-Tier Hardware Dispatch & Portable Fallback**: Automatic runtime selection across `AVX-512 VAES`, `AVX2 + VAES`, `AVX + AES-NI (VEX)`, legacy `AES-NI`, `ARMv8 Crypto`, and a constant-time 64-bit bitsliced software fallback (`purego`), verified at startup by a FIPS 140-3 Known-Answer Self-Test (`SelfTest`).
- **Constant-Time & Zeroization Hardening**: Zero secret-dependent branches or table lookups, zero heap allocations (`0 B/op`), and automatic scrubbing of temporary stack frames, SIMD vector registers (`XMM`/`YMM`/`ZMM`/`v0–v31`), and scratch GPRs before every return.

Depends only on `golang.org/x/sys/cpu`.

---

## Public API

**See [`API.md`](API.md) for the complete function-by-function specification, Go signatures, type definitions, and parameter sizes.**

| Category | Exported Symbols | Block / State | Key (`K1 \|\| K2`) | Tweak (`T`) | Summary |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **[Types & Constants](API.md#1-types-and-constants)** | `State256`, `State512`, `Block`, `Block4`, `Key4`, `TierPureGo`..`TierARMCrypto` | 16–64 B | — | — | Fixed-size byte-array state/block type aliases and hardware dispatch tier constants |
| **[Permutations (P1)](API.md#2-cryptographic-permutations-p1-and-p2-single-block--4-way)** | `Permute{256,512}`, `InversePermute{256,512}`, `*{256,512}x4` | 32 / 64 B | — | — | 10-round Areion-256 and 15-round Areion-512 forward/inverse permutations (Table 1) & 4-way batches |
| **[Permutations (P2)](API.md#2-cryptographic-permutations-p1-and-p2-single-block--4-way)** | `Permute{256,512}P2`, `InversePermute{256,512}P2`, `*P2x4` | 32 / 64 B | — | — | Domain-separated second permutations `P2 / P2⁻¹` (Table 2, π words 15..29) & 4-way batches |
| **[Davies-Meyer](API.md#3-davies-meyer-compression-functions)** | `DM256`, `DM512` | 32 / 64 B | — | — | Short-input compression functions returning a 32-byte digest: `P1(m) ⊕ m` and its 256-bit truncation |
| **[`SoEM22` PRFs](API.md#4-sum-of-even-mansour-soem22-pseudorandom-functions-prfs)** | `SoEM{256,512}`, `SoEM{256,512}x4` | 32 / 64 B | 64 / 128 B | — | Beyond-birthday-bound PRFs (secure up to `2^(2n/3)` queries) over `(P1, P2)` (single-block & 4-way batches) |
| **[`1-EM` & `2-EM` Ciphers](API.md#5-invertible-wide-block-ciphers-em-em2-tem-tem2)** | `EM{,2}Encrypt{256,512}{,x4}`, `EM{,2}Decrypt{256,512}{,x4}` | 32 / 64 B | 64 / 128 B | — | Invertible wide-block Even-Mansour ciphers: `1-EM` (birthday `2^(n/2)` PRP) and `2-EM` (BBB `2^(2n/3)` PRP) |
| **[`1-TEM` & `2-TEM` Ciphers](API.md#5-invertible-wide-block-ciphers-em-em2-tem-tem2)** | `TEM{,2}Encrypt{256,512}{,x4}`, `TEM{,2}Decrypt{256,512}{,x4}` | 32 / 64 B | 64 / 128 B | 32 / 64 B | Tweakable wide-block Even-Mansour ciphers: `1-TEM` (birthday `2^(n/2)` TPRP) and `2-TEM` (BBB `2^(2n/3)` TPRP) |
| **[AES-128 & Rounds](API.md#6-low-level-aes-128--round-primitives)** | `AES128Round{,4}`, `AES128FinalRound{,4}`, `Round{,HW,4HW}`, `FinalRound{,HW,4HW}`, `XorBlock{,4}`, `ExpandKey128`, `AES128Encrypt{Block,4Blocks}` | 16 / 64 B | 16 B | — | Hardware-dispatched & software AES-128 round primitives, key expansion, and block encryption |
| **[Runtime, CAST & Zeroize](API.md#7-runtime-dispatch-self-test-and-memory-zeroization)** | `Tier`, `TierCode`, `SetTier`, `UseHardwareAcceleration`, `SelfTest`, `Zeroize` | — | — | — | Runtime tier introspection/override, FIPS 140-3 Known-Answer Self-Test (CAST), and DSE-safe zeroization |

---

## Security & Cryptographic Constructions

### Shift Symmetry in Single-Permutation SoEM
A construction attempting to build SoEM from a single permutation `P` with a constant difference `d`:

```text
F(m) = P(m ⊕ k1) ⊕ P(m ⊕ k2 ⊕ d)
```

has a shift symmetry: for any input `m`, letting `m' = m ⊕ k1 ⊕ k2 ⊕ d` yields:

```text
F(m') = P(m' ⊕ k1) ⊕ P(m' ⊕ k2 ⊕ d) = P(m ⊕ k2 ⊕ d) ⊕ P(m ⊕ k1) = F(m)
```

The shift `k1 ⊕ k2 ⊕ d` is secret, but an adversary finds a colliding pair among about `2^(n/2)` queries and then confirms it on a second pair at the same offset, so security does not exceed the birthday bound. This is the attack on SoEM1 where `π1 = π2` in Section 4.1 of Chen, Lambooij, and Mennink, with the offset `d` added.

### SoEM22
[Chen, Lambooij, and Mennink (CRYPTO 2019)](https://eprint.iacr.org/2019/554) prove SoEM22 secure up to about `2^(2n/3)` queries (Theorem 1) when `P1` and `P2` are two independent random permutations and `k1`, `k2` are independent random keys:

```text
F(k1, k2, m) = P1(m ⊕ k1) ⊕ P2(m ⊕ k2) ⊕ k1 ⊕ k2
```

This library instantiates `P1` and `P2` as the Areion permutation under two different round-constant tables. Treating the two as independent permutations is an assumption about this instantiation, not a proven property. Stated in standard terms: if the round-constant table is regarded as the key of a block cipher, `P1` and `P2` are that cipher under two fixed, related keys, and the assumption is that this pair cannot be distinguished from two independent random permutations — a related-key assumption on Areion, not a consequence of the two tables being distinct.

### Even-Mansour (`EM`, `EM2`) and Tweakable Even-Mansour (`TEM`, `TEM2`) Wide-Block Ciphers

In addition to the non-invertible `SoEM22` PRF, this package provides four families of invertible wide-block ciphers for block size `n ∈ {256, 512}` bits, key `K = K1 || K2 ∈ {0,1}^(2n)`, and tweak `T ∈ {0,1}^n` for tweakable variants:

1. **1-Round Even–Mansour (`1-EM`: `EMEncrypt256` / `EMDecrypt256`, `EMEncrypt512` / `EMDecrypt512`, and `×4` batches)**:
   ```text
   C = P1(M ⊕ K1) ⊕ K2
   M = P1⁻¹(C ⊕ K2) ⊕ K1
   ```
   In the random-permutation model ([Even and Mansour, ASIACRYPT 1991 / J. Cryptology 1997](https://doi.org/10.1007/s001459900025)), `1-EM` achieves strong PRP security up to the tradeoff bound `D · T ≪ 2^n` (with `D` online cipher queries and `T` offline permutation queries; birthday bound `2^(n/2)` when `D = T`, i.e., `2^128` for `EM-256` and `2^256` for `EM-512`). Because Areion executes natively on 128-bit hardware AES instructions without cross-half byte shuffles, `EMEncrypt256` is a high-speed 256-bit block cipher alternative to `Rijndael-256` (NIST SP 800-197), whose ShiftRows offsets `(0, 1, 3, 4)` cross 128-bit lane boundaries in every round.

2. **2-Round Independent-Permutation Even–Mansour (`2-EM`: `EM2Encrypt256` / `EM2Decrypt256`, `EM2Encrypt512` / `EM2Decrypt512`, and `×4` batches)**:
   ```text
   C = P2(P1(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2
   M = P1⁻¹(P2⁻¹(C ⊕ K1 ⊕ K2) ⊕ K2) ⊕ K1
   ```
   Constructed over the pair `(P1, P2)` with pairwise-independent round keys `(K1, K2, K1 ⊕ K2)`, 2-round key-alternating ciphers achieve **Beyond-Birthday-Bound (BBB) security** up to `2^(2n/3)` queries (approximately `2^170.7` for `EM2-256` and `2^341.3` for `EM2-512`) in the ideal-permutation model ([Bogdanov et al., EUROCRYPT 2012](https://doi.org/10.1007/978-3-642-29011-4_5); [Chen and Steinberger, EUROCRYPT 2014](https://doi.org/10.1007/978-3-642-55220-5_33)).

3. **1-Round Tweakable Even–Mansour (`1-TEM`: `TEMEncrypt256` / `TEMDecrypt256`, `TEMEncrypt512` / `TEMDecrypt512`, and `×4` batches)**:
   ```text
   W = P2(T ⊕ K2) ⊕ K1
   C = P1(M ⊕ W) ⊕ W
   M = P1⁻¹(C ⊕ W) ⊕ W
   ```
   Derives a nonlinear tweak-key mask `W` via `P2` and masks a 1-round Even–Mansour cipher over `P1 / P1⁻¹` ([Lampe and Seurin, FSE 2013](https://doi.org/10.1007/978-3-662-43933-3_15); [Mennink, CRYPTO 2015](https://doi.org/10.1007/978-3-662-47989-6_30)). Both encryption and decryption evaluate the forward permutation `P2` on the tweak path; on hardware tiers, `TEMEncrypt*` interleaves `P2(T ⊕ K2)` with register staging in a single zero-spill assembly kernel.

4. **2-Round BBB Tweakable Even–Mansour (`2-TEM`: `TEM2Encrypt256` / `TEM2Decrypt256`, `TEM2Encrypt512` / `TEM2Decrypt512`, and `×4` batches)**:
   ```text
   W1 = P1(T ⊕ K1) ⊕ K1,   W2 = P2(T ⊕ K2) ⊕ K2
   C  = P2(P1(M ⊕ W1) ⊕ W2) ⊕ W1 ⊕ W2
   M  = P1⁻¹(P2⁻¹(C ⊕ W1 ⊕ W2) ⊕ W2) ⊕ W1
   ```
   Note that the outer whitening mask `W1 ⊕ W2 = P1(T ⊕ K1) ⊕ P2(T ⊕ K2) ⊕ K1 ⊕ K2` equals the `SoEM22` PRF evaluation on the tweak `T`. In the ideal-permutation model for independent `(P1, P2)`, this 2-round nonlinear-tweakable Even–Mansour construction achieves **Beyond-Birthday-Bound (BBB) TPRP security** up to `2^(2n/3)` queries ([Cogliati, Lampe, and Seurin, CRYPTO 2015](https://doi.org/10.1007/978-3-662-47989-6_29); [Dutta, ASIACRYPT 2020](https://doi.org/10.1007/978-3-030-64837-4_19)), making `TEM2Encrypt256/512` suited as a wide tweakable block cipher primitive for modes of the `Acc256` / `BBBAcc` / `HCTR2` class.

### Table 2 Round Constants (`P2`)
Table 2 is proposed by Andrey Kuvshinov and derived by [`scripts/verify_p2_table.py`](scripts/README.md). Following the Nothing-Up-My-Sleeve (NUMS) methodology of the original Areion paper, it continues the same stream of π words:
- **Table 1 (`P1`)**: Words 0..14 of the fractional part of π (Table 1 and Appendix A.1 of ePrint 2023/794); RC7 is kept as published, `0x801f2e2858efc16636920d871574e690`, a one-nibble shift from π word 7.
- **Table 2 (`P2`)**: Words 15..29 of the fractional part of π (15 consecutive 128-bit words); RC7, π word 22, takes the same one-nibble shift, `0xf6d6ff383f442392e0b4482a48420040`, in agreement with the Areion authors. Words 7 and 22 are the only words among 0..29 that begin with a zero nibble, so the shift falls on RC7 in both tables. The shift is a matter of consistency with Table 1: every claim of [`analysis/`](analysis/README.md) holds for both forms of this word.

The 15 hexadecimal entries of Table 2 (each stored in memory as 16 little-endian bytes; e.g., round 0 begins with bytes `93 e9 72 7c`; Areion-256 uses rounds 0..9 and Areion-512 uses rounds 0..14):

| Round | Hexadecimal constant (`P2`) |
| ---: | :--- |
| 0 | `b4cc5c341141e8cea15486af7c72e993` |
| 1 | `b3ee1411636fbc2a2ba9c55d741831f6` |
| 2 | `ce5c3e169b87931eafd6ba336c24cf5c` |
| 3 | `7a325381289586773b8f48986b4bb9af` |
| 4 | `c4bfe81b6628219361d809ccfb21a991` |
| 5 | `487cac605dec8032ef845d5de98575b1` |
| 6 | `dc262302eb651b8823893e81d396acc5` |
| 7 | `f6d6ff383f442392e0b4482a48420040` |
| 8 | `69c8f04a9e1f9b5e21c66842f6e96c9a` |
| 9 | `670c9c61abd388f06a51a0d2d8542f68` |
| 10 | `960fa728ab5133a36eef0b6c137a3be4` |
| 11 | `ba3bf0507efb2a98a1f1651d39af0176` |
| 12 | `66ca593e82430e888cee8619456f9fb4` |
| 13 | `7d84a5c33b8b5ebee06f75d885c12073` |
| 14 | `401a449f56c16aa64ed3aa62363f7706` |

[`scripts/verify_p2_table.py`](scripts/README.md) checks:
- All 30 constants are distinct: `|P1 ∩ P2| = 0`.
- Combined matrix `[P1; P2]` has full rank 30 over `GF(2)`.
- Hamming distance between `P1[i]` and `P2[j]` over all 225 pairs: min 50, mean 63.73.
- RC7 of both tables is the π word shifted by one nibble.
- No `P2` word has two equal 32-bit columns.

[`analysis/`](analysis/README.md) looks for structure tying `P2` to `P1` beyond these constant checks: related-constant differential bounds (at least 154 active S-boxes over 10 rounds of Areion-256 and 240 over 15 rounds of Areion-512 across all key differences `δ = k1 ⊕ k2` in `GF(2)^128`), linear trail bounds (at least 65 and 101 active S-boxes per permutation, or 164 bits on Areion-512 with the two-S-box chain in `F3` weighted at its exact maximum), boomerang estimates, byte-structured symmetries and affine equivalences, BCLR invariant subspaces and weak cosets, impossible differentials, integral sums to order 5, an 11-level perturbation dissolution ladder (`L0..L4p`), forward-backward cross-composition `P2⁻¹ ∘ P1` and turnaround conservation laws, and state-clearing overhead measurements, each within a stated model; the checks that depend on `P2` also cover the plain π word 22 as its RC7, and the published RC7 of `P1` can likewise be replaced by the plain π word for comparison.

### Comparison with 128-bit Block Cipher PRP-as-PRF Bounds
Standard AES-128 and AES-256 operate on 128-bit blocks as pseudorandom permutations (PRPs); used directly as a PRF, any 128-bit permutation is distinguishable from a random function after about `2^64` distinct queries via birthday non-collision. The `SoEM256` and `SoEM512` interfaces instead accept 256-bit and 512-bit inputs with 512-bit and 1024-bit keys (`2n` bits), providing `2n/3`-bit ideal-permutation PRF bounds (up to `2^170.7` and `2^341.3` queries) while executing directly on native hardware AES round instructions.

---

## Hardware Acceleration

The package automatically detects host CPU features:

| Tier | Architectures | Instructions Used | Register Width (x4 functions) |
| :--- | :--- | :--- | :--- |
| **`avx512`** | Intel Ice Lake, Tiger Lake, Rocket Lake, Xeon Ice Lake-SP+; AMD Zen 4+ (`AVX-512F + AVX-512VL + VAES`) | `VAESENC`, `VAESENCLAST`, `VAESDECLAST`, `VPXORD`, `VPXORQ`, `VBROADCASTI32X4`, plus `VEXTRACTI32X4` / 128-bit `VAESIMC` / `VINSERTI32X4` | 512-bit ZMM (4 AES blocks) |
| **`vaesavx2`** | Intel Alder Lake+ (no AVX-512); AMD Zen 3 (`AVX2 + VAES`) | `VAESENC`, `VAESENCLAST`, `VAESDECLAST`, `VPXOR`, `VBROADCASTI128`, plus `VEXTRACTI128` / 128-bit `VAESIMC` / `VINSERTI128` | 256-bit YMM (2 AES blocks) |
| **`vex`** | Intel Sandy Bridge+, AMD Bulldozer+ (`AVX + AES-NI`) | 3-operand VEX XMM `VAESENC`, `VAESENCLAST`, `VAESDECLAST`, `VAESIMC`, `VPXOR` | 128-bit XMM (3-operand VEX) |
| **`aesni`** | Intel Westmere+ (`AES-NI` without `AVX`) | Legacy SSE `AESENC`, `AESENCLAST`, `AESDECLAST`, `AESIMC`, `PXOR` | 128-bit XMM (2-operand SSE) |
| **`arm64`** | ARMv8 with Cryptographic Extension, Apple Silicon, Graviton (`NEON + AES`) | `AESE`, `AESMC`, `AESD`, `AESIMC`, `VEOR` | 128-bit NEON |
| **`purego`** | All architectures | Constant-time 64-bit bitsliced Boyar–Peralta forward/inverse S-boxes & maskless linear layer | 64-bit bitsliced software (up to 4 blocks/word) |

> **Note on single-block execution:** Single-block functions (`Permute256/512`, `InversePermute256/512` and their `P2` forms, `DM256/512`, `SoEM256/512`, `EM*`, `EM2*`, `TEM*`, `TEM2*`, `AES128Round`, `AES128FinalRound`, `ExpandKey128`, `AES128EncryptBlock`) use 3-operand VEX XMM instructions on `vex`, `vaesavx2`, and `avx512` tiers (eliminating destructive `MOVOA` register copies and legacy SSE transition penalties), and legacy 2-operand XMM instructions on `aesni`. `SoEM256`, `SoEM512`, `TEMEncrypt*`, and `TEM2*` interleave independent `P1` and `P2` evaluations in a single assembly call (and in lanes 0 and 1 of a single bitsliced pass on `purego`).

> **Note on VAES detection:** `golang.org/x/sys/cpu` reports VAES only together with AVX-512; the package reads CPUID leaf 7 directly so that VAES+AVX2 hosts (AMD Zen 3, Intel Alder Lake) activate the `vaesavx2` tier.

> **Register and stack zeroization:** All hardware assembly kernels execute with zero local stack spills (zero-byte stack frame) and clear all touched vector registers (`PXOR` / `VPXOR` / `VPXORD` on `X0..X30` plus `VZEROUPPER` on `x86-64`; `VEOR` on `V0..V31` on `arm64`) and scratch general-purpose registers (`XORQ` on `x86-64`; `MOVD ZR` on `arm64`) before returning. Value-returning functions (`DM*`, `SoEM*`, `EM*`, `EM2*`, `TEM*`, `TEM2*`, `ExpandKey128`) and `×4` wrappers additionally invoke `clobberScratchGPRs` and zero temporary stack staging buffers via `clear(buf[:])`, while the `purego` fallback scrubs its 1,024-byte software stack frame (`wipeSoftwareStack`). Verified by `areion_zeroize*_test.go`; see [`analysis/README.md` (Section L)](analysis/README.md#l-register-and-stack-clearing-cost) for instruction-count and cycle-per-byte overhead measurements.

---

## Benchmarks

### 1. Intel® Core™ i7-11700K @ 3.60GHz (Rocket Lake, x86-64)

Throughput comparison across execution tiers on the same physical CPU (with reference cycles per byte `c = f · t / B` at `f = 3.60 GHz` reaching `0.574 c/B` on `Permute512x4`, `1.049` / `1.145 c/B` on `SoEM256x4` / `SoEM512x4`, and `0.685 c/B` on `EMEncrypt512x4`):

#### Core Permutations, Davies-Meyer, SoEM22 & AES-128 Primitives

| Operation | `purego` (Bitsliced) | `aesni` (128-bit SSE) | `vex` (128-bit VEX) | `vaesavx2` (256-bit YMM) | `avx512` (512-bit ZMM) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`Permute256`** | 39.9 MB/s (801.7 ns) | 2,089 MB/s (15.3 ns) | 2,118 MB/s (15.1 ns) | 2,145 MB/s (14.9 ns) | 2,144 MB/s (14.9 ns) |
| **`Permute512`** | 44.0 MB/s (1,454 ns) | 4,125 MB/s (15.5 ns) | 4,046 MB/s (15.8 ns) | 4,051 MB/s (15.8 ns) | 4,062 MB/s (15.8 ns) |
| **`InversePermute256`** | 38.2 MB/s (837.5 ns) | 1,473 MB/s (21.7 ns) | 1,475 MB/s (21.7 ns) | 1,477 MB/s (21.7 ns) | 1,475 MB/s (21.7 ns) |
| **`InversePermute512`** | 34.2 MB/s (1,870 ns) | 1,735 MB/s (36.9 ns) | 1,732 MB/s (37.0 ns) | 1,732 MB/s (36.9 ns) | 1,731 MB/s (37.0 ns) |
| **`DM256`** | 39.4 MB/s (812.7 ns) | 1,088 MB/s (29.4 ns) | 1,142 MB/s (28.0 ns) | 1,149 MB/s (27.9 ns) | 1,151 MB/s (27.8 ns) |
| **`DM512`** | 43.8 MB/s (1,462 ns) | 1,537 MB/s (41.6 ns) | 1,558 MB/s (41.1 ns) | 1,559 MB/s (41.1 ns) | 1,556 MB/s (41.1 ns) |
| **`SoEM256`** | 37.6 MB/s (850.9 ns) | 3,208 MB/s (9.98 ns) | 3,358 MB/s (9.53 ns) | 3,363 MB/s (9.52 ns) | 3,373 MB/s (9.49 ns) |
| **`SoEM512`** | 41.8 MB/s (1,530 ns) | 3,098 MB/s (20.7 ns) | 3,391 MB/s (18.9 ns) | 3,408 MB/s (18.8 ns) | 3,266 MB/s (19.6 ns) |
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

#### Wide-Block Ciphers (`EM`, `EM2`, `TEM`, `TEM2`) vs. `Rijndael-256` (NIST SP 800-197)

| Operation | `purego` (Bitsliced) | `aesni` (128-bit SSE) | `vex` (128-bit VEX) | `vaesavx2` (256-bit YMM) | `avx512` (512-bit ZMM) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`EMEncrypt256`** | 37.3 MB/s (857.6 ns) | 1,830 MB/s (17.5 ns) | 1,878 MB/s (17.0 ns) | 1,892 MB/s (16.9 ns) | 1,891 MB/s (16.9 ns) |
| **`EMDecrypt256`** | 37.5 MB/s (854.4 ns) | 1,345 MB/s (23.8 ns) | 1,354 MB/s (23.6 ns) | 1,348 MB/s (23.7 ns) | 1,347 MB/s (23.8 ns) |
| **`EMEncrypt512`** | 43.1 MB/s (1,486 ns) | 3,492 MB/s (18.3 ns) | 3,547 MB/s (18.1 ns) | 3,585 MB/s (17.9 ns) | 3,467 MB/s (18.5 ns) |
| **`EMDecrypt512`** | 30.2 MB/s (2,117 ns) | 1,643 MB/s (39.0 ns) | 1,631 MB/s (39.2 ns) | 1,651 MB/s (38.8 ns) | 1,645 MB/s (38.9 ns) |
| **`EM2Encrypt256`** | 18.1 MB/s (1,765 ns) | 1,001 MB/s (32.0 ns) | 1,021 MB/s (31.4 ns) | 1,017 MB/s (31.5 ns) | 1,026 MB/s (31.2 ns) |
| **`EM2Decrypt256`** | 18.0 MB/s (1,777 ns) | 706 MB/s (45.4 ns) | 711 MB/s (45.0 ns) | 711 MB/s (45.0 ns) | 710 MB/s (45.1 ns) |
| **`EM2Encrypt512`** | 20.2 MB/s (3,174 ns) | 1,872 MB/s (34.2 ns) | 1,908 MB/s (33.5 ns) | 1,939 MB/s (33.0 ns) | 1,909 MB/s (33.5 ns) |
| **`EM2Decrypt512`** | 15.5 MB/s (4,122 ns) | 833 MB/s (76.8 ns) | 831 MB/s (77.0 ns) | 844 MB/s (75.8 ns) | 844 MB/s (75.8 ns) |
| **`TEMEncrypt256`** | 18.7 MB/s (1,711 ns) | 1,671 MB/s (19.2 ns) | 1,679 MB/s (19.1 ns) | 1,802 MB/s (17.8 ns) | 1,828 MB/s (17.5 ns) |
| **`TEMDecrypt256`** | 19.3 MB/s (1,656 ns) | 1,164 MB/s (27.5 ns) | 1,296 MB/s (24.7 ns) | 1,343 MB/s (23.8 ns) | 1,311 MB/s (24.4 ns) |
| **`TEMEncrypt512`** | 20.7 MB/s (3,092 ns) | 2,153 MB/s (29.7 ns) | 2,224 MB/s (28.8 ns) | 2,095 MB/s (30.6 ns) | 2,221 MB/s (28.8 ns) |
| **`TEMDecrypt512`** | 16.9 MB/s (3,784 ns) | 1,525 MB/s (42.0 ns) | 1,497 MB/s (42.8 ns) | 1,414 MB/s (45.3 ns) | 1,502 MB/s (42.6 ns) |
| **`TEM2Encrypt256`** | 12.6 MB/s (2,550 ns) | 936 MB/s (34.2 ns) | 967 MB/s (33.1 ns) | 1,007 MB/s (31.8 ns) | 993 MB/s (32.2 ns) |
| **`TEM2Decrypt256`** | 11.7 MB/s (2,731 ns) | 677 MB/s (47.2 ns) | 685 MB/s (46.7 ns) | 681 MB/s (47.0 ns) | 685 MB/s (46.7 ns) |
| **`TEM2Encrypt512`** | 14.0 MB/s (4,568 ns) | 1,265 MB/s (50.6 ns) | 1,301 MB/s (49.2 ns) | 1,243 MB/s (51.5 ns) | 1,276 MB/s (50.2 ns) |
| **`TEM2Decrypt512`** | 11.3 MB/s (5,642 ns) | 731 MB/s (87.5 ns) | 735 MB/s (87.0 ns) | 727 MB/s (88.0 ns) | 750 MB/s (85.3 ns) |
| **`EMEncrypt256x4`** | 138.6 MB/s (923.4 ns) | 3,680 MB/s (34.8 ns) | 3,430 MB/s (37.3 ns) | 3,870 MB/s (33.1 ns) | 3,366 MB/s (38.0 ns) |
| **`EMDecrypt256x4`** | 129.7 MB/s (987.2 ns) | 3,070 MB/s (41.7 ns) | 3,317 MB/s (38.6 ns) | 3,350 MB/s (38.2 ns) | 3,019 MB/s (42.4 ns) |
| **`EMEncrypt512x4`** | 120.5 MB/s (2,125 ns) | 3,909 MB/s (65.5 ns) | 4,054 MB/s (63.1 ns) | 5,256 MB/s (48.7 ns) | 4,725 MB/s (54.2 ns) |
| **`EMDecrypt512x4`** | 101.3 MB/s (2,528 ns) | 2,616 MB/s (97.9 ns) | 2,427 MB/s (105.5 ns) | 3,060 MB/s (83.7 ns) | 2,429 MB/s (105.4 ns) |
| **`EM2Encrypt256x4`** | 67.5 MB/s (1,897 ns) | 2,120 MB/s (60.4 ns) | 2,098 MB/s (61.0 ns) | 2,265 MB/s (56.5 ns) | 2,078 MB/s (61.6 ns) |
| **`EM2Decrypt256x4`** | 67.1 MB/s (1,907 ns) | 1,743 MB/s (73.5 ns) | 1,793 MB/s (71.4 ns) | 1,857 MB/s (68.9 ns) | 1,714 MB/s (74.7 ns) |
| **`EM2Encrypt512x4`** | 60.6 MB/s (4,224 ns) | 2,155 MB/s (118.8 ns) | 2,292 MB/s (111.7 ns) | 3,141 MB/s (81.5 ns) | 3,183 MB/s (80.4 ns) |
| **`EM2Decrypt512x4`** | 51.6 MB/s (4,958 ns) | 1,420 MB/s (180.3 ns) | 1,436 MB/s (178.2 ns) | 1,677 MB/s (152.6 ns) | 1,316 MB/s (194.6 ns) |
| **`TEMEncrypt256x4`** | 69.4 MB/s (1,843 ns) | 1,898 MB/s (67.4 ns) | 1,980 MB/s (64.6 ns) | 2,025 MB/s (63.2 ns) | 1,787 MB/s (71.6 ns) |
| **`TEMDecrypt256x4`** | 61.9 MB/s (2,069 ns) | 1,848 MB/s (69.3 ns) | 1,772 MB/s (72.2 ns) | 1,770 MB/s (72.3 ns) | 1,677 MB/s (76.3 ns) |
| **`TEMEncrypt512x4`** | 55.4 MB/s (4,621 ns) | 1,911 MB/s (133.9 ns) | 2,025 MB/s (126.4 ns) | 2,607 MB/s (98.2 ns) | 2,523 MB/s (101.5 ns) |
| **`TEMDecrypt512x4`** | 55.4 MB/s (4,621 ns) | 1,493 MB/s (171.4 ns) | 1,643 MB/s (155.8 ns) | 1,922 MB/s (133.2 ns) | 1,592 MB/s (160.8 ns) |
| **`TEM2Encrypt256x4`** | 35.7 MB/s (3,585 ns) | 1,159 MB/s (110.4 ns) | 1,089 MB/s (117.5 ns) | 1,246 MB/s (102.7 ns) | 1,204 MB/s (106.3 ns) |
| **`TEM2Decrypt256x4`** | 31.6 MB/s (4,053 ns) | 967 MB/s (132.4 ns) | 998 MB/s (128.3 ns) | 1,112 MB/s (115.1 ns) | 1,037 MB/s (123.4 ns) |
| **`TEM2Encrypt512x4`** | 30.8 MB/s (8,324 ns) | 1,057 MB/s (242.2 ns) | 1,135 MB/s (225.6 ns) | 1,507 MB/s (169.9 ns) | 1,554 MB/s (164.7 ns) |
| **`TEM2Decrypt512x4`** | 27.6 MB/s (9,262 ns) | 790 MB/s (323.9 ns) | 811 MB/s (315.8 ns) | 1,039 MB/s (246.4 ns) | 894 MB/s (286.2 ns) |
| **`Rijndael-256`** | 15.4 MB/s (2,083 ns) | 123.1 MB/s (259.9 ns) | 126.2 MB/s (253.5 ns) | 130.1 MB/s (245.9 ns) | 128.3 MB/s (249.4 ns) |
| **`Rijndael-256x4`** | 31.4 MB/s (4,076 ns) | 115.0 MB/s (1,113 ns) | 117.3 MB/s (1,091 ns) | 113.2 MB/s (1,131 ns) | 111.7 MB/s (1,146 ns) |

All operations: 0 B/op, 0 allocs/op. On Intel® Core™ i7-11700K, `EMEncrypt256` (`1,892 MB/s`, `16.9 ns`) and `EMEncrypt256x4` (`3,870 MB/s`, `33.1 ns`) achieve **14.5×** and **34.2×** higher throughput than hardware-assisted `Rijndael-256` (`130.1 MB/s` single-block, `113.2 MB/s` 4-block), while `EMEncrypt512x4` reaches `5,256 MB/s` (`0.685 c/B`).

### 2. AWS Graviton 4 (`c8g.4xlarge`, Neoverse-V2, 16 vCPUs, ARM64)

Measured on AWS Graviton 4 (`purego` bitsliced fallback vs `arm64` ARMv8 Cryptographic Extension; reference cycles per byte `c = f · t / B` at `f = 2.80 GHz` reach `0.812 c/B` on `Permute512x4`, `1.590` / `2.166 c/B` on `SoEM256x4` / `SoEM512x4`, and `1.023 c/B` on `EMEncrypt512x4`):

#### Core Permutations, Davies-Meyer, SoEM22 & AES-128 Primitives

| Operation | `purego` (Bitsliced) | `arm64` (128-bit NEON) |
| :--- | :---: | :---: |
| **`Permute256`** | 35.7 MB/s (897.2 ns) | 928.1 MB/s (34.5 ns) |
| **`Permute512`** | 40.3 MB/s (1,587 ns) | 1,570.8 MB/s (40.7 ns) |
| **`InversePermute256`** | 35.0 MB/s (915.4 ns) | 769.2 MB/s (41.6 ns) |
| **`InversePermute512`** | 30.7 MB/s (2,085 ns) | 1,031.4 MB/s (62.1 ns) |
| **`DM256`** | 35.1 MB/s (913.1 ns) | 653.0 MB/s (49.0 ns) |
| **`DM512`** | 39.4 MB/s (1,623 ns) | 952.6 MB/s (67.2 ns) |
| **`SoEM256`** | 33.8 MB/s (946.2 ns) | 837.8 MB/s (38.2 ns) |
| **`SoEM512`** | 37.7 MB/s (1,698 ns) | 1,133.0 MB/s (56.5 ns) |
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

#### Wide-Block Ciphers (`EM`, `EM2`, `TEM`, `TEM2`) vs. `Rijndael-256` (NIST SP 800-197)

| Operation | `purego` (Bitsliced) | `arm64` (128-bit NEON) |
| :--- | :---: | :---: |
| **`EMEncrypt256`** | 37.8 MB/s (847.3 ns) | 840.8 MB/s (38.1 ns) |
| **`EMDecrypt256`** | 36.9 MB/s (866.7 ns) | 706.4 MB/s (45.3 ns) |
| **`EMEncrypt512`** | 42.7 MB/s (1,499 ns) | 1,441.0 MB/s (44.4 ns) |
| **`EMDecrypt512`** | 32.6 MB/s (1,962 ns) | 966.4 MB/s (66.2 ns) |
| **`EM2Encrypt256`** | 19.1 MB/s (1,672 ns) | 449.8 MB/s (71.1 ns) |
| **`EM2Decrypt256`** | 18.7 MB/s (1,709 ns) | 371.2 MB/s (86.2 ns) |
| **`EM2Encrypt512`** | 21.6 MB/s (2,969 ns) | 773.2 MB/s (82.8 ns) |
| **`EM2Decrypt512`** | 16.4 MB/s (3,892 ns) | 501.5 MB/s (127.6 ns) |
| **`TEMEncrypt256`** | 19.2 MB/s (1,670 ns) | 623.1 MB/s (51.4 ns) |
| **`TEMDecrypt256`** | 18.9 MB/s (1,692 ns) | 598.2 MB/s (53.5 ns) |
| **`TEMEncrypt512`** | 21.4 MB/s (2,990 ns) | 787.4 MB/s (81.3 ns) |
| **`TEMDecrypt512`** | 16.9 MB/s (3,795 ns) | 633.1 MB/s (101.1 ns) |
| **`TEM2Encrypt256`** | 11.6 MB/s (2,759 ns) | 318.7 MB/s (100.4 ns) |
| **`TEM2Decrypt256`** | 11.4 MB/s (2,803 ns) | 294.0 MB/s (108.8 ns) |
| **`TEM2Encrypt512`** | 13.0 MB/s (4,922 ns) | 475.8 MB/s (134.5 ns) |
| **`TEM2Decrypt512`** | 10.6 MB/s (6,014 ns) | 363.5 MB/s (176.1 ns) |
| **`EMEncrypt256x4`** | 124.6 MB/s (1,027 ns) | 2,416.9 MB/s (53.0 ns) |
| **`EMDecrypt256x4`** | 121.2 MB/s (1,057 ns) | 2,112.5 MB/s (60.6 ns) |
| **`EMEncrypt512x4`** | 112.8 MB/s (2,270 ns) | 2,737.2 MB/s (93.5 ns) |
| **`EMDecrypt512x4`** | 95.9 MB/s (2,669 ns) | 2,198.2 MB/s (116.5 ns) |
| **`EM2Encrypt256x4`** | 63.4 MB/s (2,020 ns) | 1,368.5 MB/s (93.5 ns) |
| **`EM2Decrypt256x4`** | 61.9 MB/s (2,067 ns) | 1,189.6 MB/s (107.6 ns) |
| **`EM2Encrypt512x4`** | 57.0 MB/s (4,493 ns) | 1,569.3 MB/s (163.1 ns) |
| **`EM2Decrypt512x4`** | 48.6 MB/s (5,272 ns) | 1,234.3 MB/s (207.4 ns) |
| **`TEMEncrypt256x4`** | 63.3 MB/s (2,023 ns) | 1,264.3 MB/s (101.2 ns) |
| **`TEMDecrypt256x4`** | 62.4 MB/s (2,052 ns) | 1,174.9 MB/s (108.9 ns) |
| **`TEMEncrypt512x4`** | 56.3 MB/s (4,548 ns) | 1,437.2 MB/s (178.1 ns) |
| **`TEMDecrypt512x4`** | 51.0 MB/s (5,023 ns) | 1,265.1 MB/s (202.4 ns) |
| **`TEM2Encrypt256x4`** | 32.0 MB/s (4,002 ns) | 688.6 MB/s (185.9 ns) |
| **`TEM2Decrypt256x4`** | 31.5 MB/s (4,058 ns) | 634.1 MB/s (201.9 ns) |
| **`TEM2Encrypt512x4`** | 28.4 MB/s (9,022 ns) | 764.9 MB/s (334.7 ns) |
| **`TEM2Decrypt512x4`** | 25.8 MB/s (9,908 ns) | 614.2 MB/s (416.8 ns) |
| **`Rijndael-256`** | 13.6 MB/s (2,352 ns) | 87.2 MB/s (366.8 ns) |
| **`Rijndael-256x4`** | 29.3 MB/s (4,375 ns) | 94.2 MB/s (1,359 ns) |

All operations: 0 B/op, 0 allocs/op. On AWS Graviton 4 (Neoverse-V2), `EMEncrypt256` (`840.8 MB/s`, `38.1 ns`) and `EMEncrypt256x4` (`2,416.9 MB/s`, `53.0 ns`) outperform `Rijndael-256` (`87.2 MB/s` single-block, `94.2 MB/s` 4-block) by **9.6×** and **25.7×**.

### 3. Comparison with `Rijndael-256` (`NIST SP 800-197`)

`Rijndael-256` (14 rounds, 256-bit block, 256-bit key, `ShiftRows` offsets `(0, 1, 3, 4)` across an `8 × 4` byte matrix) cannot execute directly on 128-bit `AESENC`/`AESE` instructions without applying the cross-128-bit-half byte permutation `InvShiftRows_AES128` ∘ `ShiftRows_R256(0,1,3,4)` before every round. By contrast, Areion-256 uses a 2-branch Feistel/SPN structure built natively from 128-bit AES rounds with zero cross-half byte shuffles:

| 256-Bit Block Cipher Primitive | Intel Core i7-11700K (Best HW Tier) | AWS Graviton 4 (`arm64`) | Security Bound |
| :--- | :---: | :---: | :--- |
| **`EMEncrypt256`** | **1,892 MB/s** (`16.9 ns/op`) | **840.8 MB/s** (`38.1 ns/op`) | `2^128` queries (birthday PRP) |
| **`EM2Encrypt256`** | **1,026 MB/s** (`31.2 ns/op`) | **449.8 MB/s** (`71.1 ns/op`) | `2^170.7` queries (BBB PRP) |
| **`TEMEncrypt256`** | **1,828 MB/s** (`17.5 ns/op`) | **623.1 MB/s** (`51.4 ns/op`) | `2^128` queries (tweakable PRP) |
| **`TEM2Encrypt256`** | **1,007 MB/s** (`31.8 ns/op`) | **318.7 MB/s** (`100.4 ns/op`) | `2^170.7` queries (BBB TPRP) |
| **`EMEncrypt256x4`** | **3,870 MB/s** (`8.28 ns/block`) | **2,416.9 MB/s** (`13.25 ns/block`) | `2^128` queries (birthday PRP) |
| **`EM2Encrypt256x4`** | **2,265 MB/s** (`14.13 ns/block`) | **1,368.5 MB/s** (`23.38 ns/block`) | `2^170.7` queries (BBB PRP) |
| **`TEMEncrypt256x4`** | **2,025 MB/s** (`15.80 ns/block`) | **1,264.3 MB/s** (`25.30 ns/block`) | `2^128` queries (tweakable PRP) |
| **`TEM2Encrypt256x4`** | **1,246 MB/s** (`25.68 ns/block`) | **688.6 MB/s** (`46.48 ns/block`) | `2^170.7` queries (BBB TPRP) |
| **`Rijndael-256`** | 130.1 MB/s (`245.9 ns/op`) | 87.2 MB/s (`366.8 ns/op`) | 256-bit block cipher (`SP 800-197`, 14r) |
| **`Rijndael-256x4`** | 117.3 MB/s (`272.8 ns/block`) | 94.2 MB/s (`339.8 ns/block`) | 256-bit block cipher (`SP 800-197`, 14r) |

> **Benchmark methodology note:** `BenchmarkPermute*`, `BenchmarkInversePermute*`, `BenchmarkEM*`, `BenchmarkTEM*`, `BenchmarkAES128Encrypt*`, and `BenchmarkRijndael256Encrypt*` feed their output back into the next iteration's input (`m = EMEncrypt*(...)`, `dst == src`), measuring serial dependency-chain latency across iterations (`AES128Encrypt*` and `Rijndael256Encrypt*` time the encryption core with pre-expanded round keys, excluding key expansion). `BenchmarkSoEM*` and `BenchmarkDM*` evaluate fixed input and key buffers across iterations, allowing out-of-order execution to overlap independent calls. See [`analysis/README.md` (Section L)](analysis/README.md#l-register-and-stack-clearing-cost) for interleaved single-core cycle-per-byte measurements including epilogue register and stack clearing.

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
Cross-architecture execution is also verified under `qemu-*-static` across 12 Go targets (`arm64` NEON+AES and `purego`, 64/32-bit Big-Endian `s390x`, `ppc64`, `mips64`, `mips`, and Little-Endian `riscv64`, `ppc64le`, `loong64`, `mips64le`, `386`, `arm`, `mipsle`).

### 3. Run Benchmarks
```bash
# Auto-selected tier:
go test -run=^none -bench=. -benchmem ./...

# Benchmark individual tiers:
AREION_FORCE_TIER=purego go test -run=^none -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=aesni go test -run=^none -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=vex go test -run=^none -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=vaesavx2 go test -run=^none -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=avx512 go test -run=^none -bench=. -benchmem -benchtime=500ms -count=1 ./...
AREION_FORCE_TIER=arm64 go test -run=^none -bench=. -benchmem -benchtime=500ms -count=1 ./...
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
	// 0. Optional FIPS 140-3 Cryptographic Algorithm Self-Test (CAST)
	if err := areion.SelfTest(); err != nil {
		panic(err)
	}

	// 1. Single-block permutation P1
	var state areion.State256
	areion.Permute256(&state)
	fmt.Printf("Permuted: %x\n", state)

	// 2. Davies-Meyer hashing
	var msg [32]byte
	digest := areion.DM256(&msg)
	fmt.Printf("DM256 Digest: %x\n", digest)

	// 3. SoEM22 PRF
	var key [64]byte // K1 || K2
	prf := areion.SoEM256(&key, &msg)
	fmt.Printf("SoEM22 PRF: %x\n", prf)

	// 4. 2-round BBB Tweakable Even-Mansour (2-TEM) wide-block cipher
	var tweak [32]byte
	ct := areion.TEM2Encrypt256(&key, &tweak, &msg)
	pt := areion.TEM2Decrypt256(&key, &tweak, &ct)
	fmt.Printf("TEM2-256 Ciphertext: %x (roundtrip ok: %v)\n", ct, pt == msg)

	// 5. Scrub sensitive key and plaintext buffers before returning
	areion.Zeroize(key[:])
	areion.Zeroize(pt[:])
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

3. **A Construction of a Cipher From a Single Pseudorandom Permutation**
   Shimon Even, Yishay Mansour.
   *ASIACRYPT 1991*, Lecture Notes in Computer Science, vol. 739, pp. 210–224; *Journal of Cryptology*, vol. 10, no. 3, pp. 151–162 (1997), [doi:10.1007/s001459900025](https://doi.org/10.1007/s001459900025).

4. **Key-Alternating Ciphers in a Provable Setting: Encryption Using a Small Number of Public Permutations**
   Andrey Bogdanov, Lars R. Knudsen, Gregor Leander, François-Xavier Standaert, John Steinberger, Elmar Tischhauser.
   *EUROCRYPT 2012*, Lecture Notes in Computer Science, vol. 7237, pp. 45–62, [doi:10.1007/978-3-642-29011-4_5](https://doi.org/10.1007/978-3-642-29011-4_5).

5. **Tight Security Bounds for Key-Alternating Ciphers**
   Shan Chen, John Steinberger.
   *EUROCRYPT 2014*, Lecture Notes in Computer Science, vol. 8441, pp. 327–350, [doi:10.1007/978-3-642-55220-5_33](https://doi.org/10.1007/978-3-642-55220-5_33).

6. **Tweakable Even-Mansour Ciphers**
   Rodolphe Lampe, Yannick Seurin.
   *FSE 2013*, Lecture Notes in Computer Science, vol. 8424, pp. 245–264, [doi:10.1007/978-3-662-43933-3_15](https://doi.org/10.1007/978-3-662-43933-3_15); and Bart Mennink, **Optimally Secure Tweakable Blockciphers**, *CRYPTO 2015*, Part I, LNCS vol. 9215, pp. 428–448, [doi:10.1007/978-3-662-47989-6_30](https://doi.org/10.1007/978-3-662-47989-6_30).

7. **Tweaking Even-Mansour Ciphers**
   Benoît Cogliati, Rodolphe Lampe, Yannick Seurin.
   *CRYPTO 2015*, Part I, Lecture Notes in Computer Science, vol. 9215, pp. 189–208, [doi:10.1007/978-3-662-47989-6_29](https://doi.org/10.1007/978-3-662-47989-6_29); and Avijit Dutta, **Minimizing the Two-Round Tweakable Even-Mansour Cipher**, *ASIACRYPT 2020*, Part I, LNCS vol. 12491, pp. 601–629, [doi:10.1007/978-3-030-64837-4_19](https://doi.org/10.1007/978-3-030-64837-4_19).

8. **Recommendation for Existing Application-Specific Key Derivation Functions / Wide-Block Rijndael-256**
   Joan Daemen, Vincent Rijmen, *The Design of Rijndael: AES — The Advanced Encryption Standard*, Springer (2002); NIST Special Publication 800-197 (Draft / Reference specification for 256-bit block Rijndael with ShiftRows offsets `(0, 1, 3, 4)`).

---

## License

Dual-licensed under either:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

Copyright (c) 2026 Andrey Kuvshinov.

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

> **Register and stack zeroization:** All hardware assembly kernels (both single-block and `×4` batch functions) execute directly in registers with zero local stack spills (zero-byte stack frame, no intermediate AoS↔SoA stack buffers) and clear all touched vector registers (`PXOR` / `VPXOR` / `VPXORD` on `X0..X30` plus `VZEROUPPER` on `x86-64`; `VEOR` on `V0..V31` on `arm64`) and scratch general-purpose registers (`XORQ` on `x86-64`; `MOVD ZR` on `arm64`) before returning. Hardware wrappers invoke `clobberScratchGPRs` before returning, while the `purego` fallback scrubs its local buffers and 1,024-byte software stack frame (`wipeSoftwareStack`). Verified by `areion_zeroize*_test.go`; see [`analysis/README.md` (Section L)](analysis/README.md#l-register-and-stack-clearing-cost) for instruction-count and cycle-per-byte overhead measurements.

---

## Benchmarks

### 1. Intel® Core™ i7-11700K @ 3.60GHz (Rocket Lake, x86-64)

3-run averaged throughput comparison across execution tiers on the same physical CPU (with reference cycles per byte `c = f · t / B` at `f = 3.60 GHz` reaching `0.336 c/B` on `Permute512x4`, `0.498` / `0.612 c/B` on `SoEM256x4` / `SoEM512x4`, and `0.491 c/B` on `EMEncrypt512x4`):

#### Core Permutations, Davies-Meyer, SoEM22 & AES-128 Primitives

| Operation | `purego` (Bitsliced) | `aesni` (128-bit SSE) | `vex` (128-bit VEX) | `vaesavx2` (256-bit YMM) | `avx512` (512-bit ZMM) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`Permute256`** | 36.6 MB/s (876.6 ns) | 2,070 MB/s (15.5 ns) | 2,121 MB/s (15.1 ns) | 2,109 MB/s (15.2 ns) | 2,086 MB/s (15.3 ns) |
| **`Permute512`** | 40.5 MB/s (1,579 ns) | 3,997 MB/s (16.0 ns) | 4,024 MB/s (15.9 ns) | 4,025 MB/s (15.9 ns) | 4,019 MB/s (15.9 ns) |
| **`InversePermute256`** | 35.3 MB/s (907.7 ns) | 1,468 MB/s (21.8 ns) | 1,469 MB/s (21.8 ns) | 1,460 MB/s (21.9 ns) | 1,457 MB/s (22.0 ns) |
| **`InversePermute512`** | 32.2 MB/s (1,992 ns) | 1,724 MB/s (37.1 ns) | 1,727 MB/s (37.1 ns) | 1,720 MB/s (37.2 ns) | 1,721 MB/s (37.2 ns) |
| **`DM256`** | 36.5 MB/s (878.4 ns) | 985 MB/s (32.5 ns) | 1,035 MB/s (30.9 ns) | 1,052 MB/s (30.4 ns) | 1,035 MB/s (30.9 ns) |
| **`DM512`** | 38.9 MB/s (1,648 ns) | 1,301 MB/s (49.2 ns) | 1,391 MB/s (46.1 ns) | 1,409 MB/s (45.5 ns) | 1,405 MB/s (45.6 ns) |
| **`SoEM256`** | 34.8 MB/s (920.7 ns) | 2,589 MB/s (12.4 ns) | 2,882 MB/s (11.1 ns) | 2,778 MB/s (11.5 ns) | 2,854 MB/s (11.2 ns) |
| **`SoEM512`** | 37.9 MB/s (1,696 ns) | 2,870 MB/s (22.3 ns) | 2,877 MB/s (22.3 ns) | 3,032 MB/s (21.1 ns) | 2,976 MB/s (21.6 ns) |
| **`Permute256x4`** | 140.3 MB/s (913.3 ns) | 6,208 MB/s (20.6 ns) | 6,727 MB/s (19.0 ns) | 6,816 MB/s (18.8 ns) | 6,432 MB/s (19.9 ns) |
| **`Permute512x4`** | 116.0 MB/s (2,211 ns) | 6,342 MB/s (40.4 ns) | 6,434 MB/s (39.8 ns) | 10,599 MB/s (24.2 ns) | 10,712 MB/s (23.9 ns) |
| **`InversePermute256x4`** | 127.4 MB/s (1,006 ns) | 5,354 MB/s (23.9 ns) | 5,567 MB/s (23.0 ns) | 5,278 MB/s (24.3 ns) | 4,899 MB/s (26.1 ns) |
| **`InversePermute512x4`** | 104.2 MB/s (2,461 ns) | 3,581 MB/s (71.5 ns) | 3,623 MB/s (70.7 ns) | 6,145 MB/s (41.7 ns) | 6,001 MB/s (42.7 ns) |
| **`SoEM256x4`** | 68.0 MB/s (1,882 ns) | 3,406 MB/s (37.6 ns) | 3,612 MB/s (35.4 ns) | 5,765 MB/s (22.2 ns) | 7,228 MB/s (17.7 ns) |
| **`SoEM512x4`** | 58.2 MB/s (4,412 ns) | 3,277 MB/s (78.2 ns) | 3,181 MB/s (80.6 ns) | 5,248 MB/s (48.8 ns) | 5,887 MB/s (43.5 ns) |
| **`AES128Round`** | 238 MB/s (67.2 ns) | 5,743 MB/s (2.79 ns) | 6,722 MB/s (2.38 ns) | 6,618 MB/s (2.42 ns) | 6,261 MB/s (2.58 ns) |
| **`AES128Round4`** | 629 MB/s (101.8 ns) | 14,563 MB/s (4.40 ns) | 16,464 MB/s (3.89 ns) | 18,141 MB/s (3.55 ns) | 21,592 MB/s (2.96 ns) |
| **`ExpandKey128`** | 490 MB/s (359.5 ns) | 1,026 MB/s (171.5 ns) | 1,017 MB/s (173.1 ns) | 1,056 MB/s (166.6 ns) | 1,058 MB/s (166.5 ns) |
| **`AES128EncryptBlock`** | 31.9 MB/s (502.9 ns) | 1,891 MB/s (8.46 ns) | 1,898 MB/s (8.43 ns) | 1,890 MB/s (8.47 ns) | 1,900 MB/s (8.42 ns) |
| **`AES128Encrypt4Blocks`** | 117.7 MB/s (544.1 ns) | 7,104 MB/s (9.01 ns) | 7,225 MB/s (8.86 ns) | 7,346 MB/s (8.71 ns) | 7,357 MB/s (8.70 ns) |

#### Wide-Block Ciphers (`EM`, `EM2`, `TEM`, `TEM2`) vs. `Rijndael-256` & `Vistrutah-256/512`

| Operation | `purego` (Bitsliced) | `aesni` (128-bit SSE) | `vex` (128-bit VEX) | `vaesavx2` (256-bit YMM) | `avx512` (512-bit ZMM) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`EMEncrypt256`** | 35.9 MB/s (892.3 ns) | 1,852 MB/s (17.3 ns) | 1,882 MB/s (17.0 ns) | 1,891 MB/s (16.9 ns) | 1,889 MB/s (16.9 ns) |
| **`EMDecrypt256`** | 36.2 MB/s (884.6 ns) | 1,355 MB/s (23.6 ns) | 1,353 MB/s (23.7 ns) | 1,347 MB/s (23.8 ns) | 1,351 MB/s (23.7 ns) |
| **`EMEncrypt512`** | 40.7 MB/s (1,581 ns) | 3,494 MB/s (18.3 ns) | 3,545 MB/s (18.1 ns) | 3,563 MB/s (18.0 ns) | 3,449 MB/s (18.6 ns) |
| **`EMDecrypt512`** | 32.4 MB/s (1,980 ns) | 1,638 MB/s (39.1 ns) | 1,631 MB/s (39.2 ns) | 1,639 MB/s (39.0 ns) | 1,637 MB/s (39.1 ns) |
| **`EM2Encrypt256`** | 19.0 MB/s (1,684 ns) | 1,002 MB/s (31.9 ns) | 1,021 MB/s (31.3 ns) | 1,018 MB/s (31.4 ns) | 1,022 MB/s (31.3 ns) |
| **`EM2Decrypt256`** | 18.2 MB/s (1,760 ns) | 710 MB/s (45.0 ns) | 710 MB/s (45.1 ns) | 709 MB/s (45.1 ns) | 712 MB/s (45.0 ns) |
| **`EM2Encrypt512`** | 20.7 MB/s (3,100 ns) | 1,920 MB/s (33.4 ns) | 1,907 MB/s (33.6 ns) | 1,910 MB/s (33.5 ns) | 1,916 MB/s (33.4 ns) |
| **`EM2Decrypt512`** | 16.0 MB/s (3,996 ns) | 843 MB/s (76.0 ns) | 839 MB/s (76.3 ns) | 841 MB/s (76.1 ns) | 842 MB/s (76.0 ns) |
| **`TEMEncrypt256`** | 18.9 MB/s (1,696 ns) | 1,744 MB/s (18.4 ns) | 1,742 MB/s (18.4 ns) | 1,810 MB/s (17.7 ns) | 1,744 MB/s (18.4 ns) |
| **`TEMDecrypt256`** | 18.7 MB/s (1,711 ns) | 1,306 MB/s (24.5 ns) | 1,321 MB/s (24.2 ns) | 1,303 MB/s (24.6 ns) | 1,314 MB/s (24.4 ns) |
| **`TEMEncrypt512`** | 20.7 MB/s (3,087 ns) | 2,117 MB/s (30.2 ns) | 2,122 MB/s (30.2 ns) | 2,157 MB/s (29.7 ns) | 2,123 MB/s (30.1 ns) |
| **`TEMDecrypt512`** | 17.1 MB/s (3,745 ns) | 1,436 MB/s (44.6 ns) | 1,450 MB/s (44.1 ns) | 1,466 MB/s (43.7 ns) | 1,440 MB/s (44.5 ns) |
| **`TEM2Encrypt256`** | 12.1 MB/s (2,658 ns) | 924 MB/s (34.7 ns) | 959 MB/s (33.4 ns) | 979 MB/s (32.7 ns) | 973 MB/s (32.9 ns) |
| **`TEM2Decrypt256`** | 11.6 MB/s (2,751 ns) | 683 MB/s (46.9 ns) | 684 MB/s (46.8 ns) | 681 MB/s (47.0 ns) | 681 MB/s (47.0 ns) |
| **`TEM2Encrypt512`** | 13.6 MB/s (4,695 ns) | 1,243 MB/s (51.5 ns) | 1,257 MB/s (50.9 ns) | 1,280 MB/s (50.0 ns) | 1,296 MB/s (49.4 ns) |
| **`TEM2Decrypt512`** | 11.2 MB/s (5,743 ns) | 707 MB/s (90.6 ns) | 728 MB/s (88.0 ns) | 739 MB/s (86.6 ns) | 733 MB/s (87.3 ns) |
| **`EMEncrypt256x4`** | 133.2 MB/s (960.9 ns) | 5,663 MB/s (22.6 ns) | 6,030 MB/s (21.2 ns) | 5,007 MB/s (25.6 ns) | 4,837 MB/s (26.5 ns) |
| **`EMDecrypt256x4`** | 128.0 MB/s (1,001 ns) | 4,573 MB/s (28.0 ns) | 4,649 MB/s (27.6 ns) | 3,994 MB/s (32.0 ns) | 3,901 MB/s (32.8 ns) |
| **`EMEncrypt512x4`** | 119.5 MB/s (2,144 ns) | 5,337 MB/s (48.0 ns) | 5,544 MB/s (46.2 ns) | 6,508 MB/s (39.3 ns) | 7,343 MB/s (34.9 ns) |
| **`EMDecrypt512x4`** | 100.8 MB/s (2,542 ns) | 3,212 MB/s (79.7 ns) | 3,234 MB/s (79.2 ns) | 3,627 MB/s (70.6 ns) | 4,847 MB/s (52.8 ns) |
| **`EM2Encrypt256x4`** | 67.3 MB/s (1,902 ns) | 3,160 MB/s (40.5 ns) | 3,247 MB/s (39.4 ns) | 3,135 MB/s (40.8 ns) | 3,114 MB/s (41.1 ns) |
| **`EM2Decrypt256x4`** | 64.4 MB/s (1,991 ns) | 2,497 MB/s (51.3 ns) | 2,591 MB/s (49.4 ns) | 2,380 MB/s (53.8 ns) | 2,359 MB/s (54.3 ns) |
| **`EM2Encrypt512x4`** | 60.6 MB/s (4,230 ns) | 2,875 MB/s (89.1 ns) | 2,967 MB/s (86.4 ns) | 3,590 MB/s (71.3 ns) | 4,842 MB/s (52.9 ns) |
| **`EM2Decrypt512x4`** | 51.7 MB/s (4,966 ns) | 1,600 MB/s (160.0 ns) | 1,616 MB/s (158.4 ns) | 1,765 MB/s (145.1 ns) | 2,820 MB/s (90.8 ns) |
| **`TEMEncrypt256x4`** | 65.3 MB/s (1,963 ns) | 2,496 MB/s (51.3 ns) | 2,682 MB/s (47.8 ns) | 4,065 MB/s (31.5 ns) | 4,783 MB/s (26.8 ns) |
| **`TEMDecrypt256x4`** | 62.8 MB/s (2,039 ns) | 2,391 MB/s (53.5 ns) | 2,625 MB/s (48.8 ns) | 3,692 MB/s (34.7 ns) | 3,714 MB/s (34.5 ns) |
| **`TEMEncrypt512x4`** | 58.4 MB/s (4,388 ns) | 2,645 MB/s (96.8 ns) | 2,716 MB/s (94.3 ns) | 3,785 MB/s (67.7 ns) | 4,816 MB/s (53.2 ns) |
| **`TEMDecrypt512x4`** | 52.0 MB/s (4,943 ns) | 2,035 MB/s (125.9 ns) | 2,045 MB/s (125.2 ns) | 2,720 MB/s (94.1 ns) | 3,953 MB/s (64.8 ns) |
| **`TEM2Encrypt256x4`** | 34.7 MB/s (3,690 ns) | 1,421 MB/s (90.2 ns) | 1,493 MB/s (85.7 ns) | 2,660 MB/s (48.1 ns) | 2,948 MB/s (43.5 ns) |
| **`TEM2Decrypt256x4`** | 33.8 MB/s (3,783 ns) | 1,207 MB/s (106.1 ns) | 1,205 MB/s (106.3 ns) | 2,029 MB/s (63.1 ns) | 2,256 MB/s (56.8 ns) |
| **`TEM2Encrypt512x4`** | 30.5 MB/s (8,407 ns) | 1,272 MB/s (201.3 ns) | 1,255 MB/s (204.1 ns) | 2,298 MB/s (111.4 ns) | 2,904 MB/s (88.2 ns) |
| **`TEM2Decrypt512x4`** | 27.5 MB/s (9,332 ns) | 750 MB/s (341.2 ns) | 743 MB/s (344.8 ns) | 1,349 MB/s (189.8 ns) | 2,098 MB/s (122.1 ns) |
| **`Rijndael-256`** | 30.3 MB/s (1,057 ns) | 1,154 MB/s (27.7 ns) | 1,034 MB/s (30.9 ns) | 1,033 MB/s (31.0 ns) | 1,031 MB/s (31.0 ns) |
| **`Rijndael-256x4`** | 87.6 MB/s (1,464 ns) | 3,314 MB/s (38.6 ns) | 2,719 MB/s (47.1 ns) | 3,413 MB/s (37.6 ns) | 3,795 MB/s (33.7 ns) |
| **`Vistrutah-256 (10r)`** | 43.5 MB/s (738.1 ns) | 1,994 MB/s (16.1 ns) | 1,832 MB/s (17.5 ns) | 1,452 MB/s (22.0 ns) | 1,474 MB/s (21.7 ns) |
| **`Vistrutah-256 (14r)`** | 30.7 MB/s (1,043 ns) | 1,449 MB/s (22.1 ns) | 1,343 MB/s (23.8 ns) | 1,142 MB/s (28.0 ns) | 1,137 MB/s (28.2 ns) |
| **`Vistrutah-256x4 (10r)`** | 77.8 MB/s (1,650 ns) | 5,022 MB/s (25.6 ns) | 5,256 MB/s (24.4 ns) | 5,238 MB/s (24.4 ns) | 6,033 MB/s (21.2 ns) |
| **`Vistrutah-256x4 (14r)`** | 59.5 MB/s (2,153 ns) | 3,835 MB/s (33.4 ns) | 3,901 MB/s (32.8 ns) | 4,089 MB/s (31.3 ns) | 4,504 MB/s (28.4 ns) |
| **`Vistrutah-512-256 (10r)`** | 62.7 MB/s (1,023 ns) | 3,245 MB/s (19.7 ns) | 3,036 MB/s (21.1 ns) | 2,345 MB/s (27.3 ns) | 1,881 MB/s (34.0 ns) |
| **`Vistrutah-512-256 (14r)`** | 47.6 MB/s (1,346 ns) | 2,334 MB/s (27.4 ns) | 2,282 MB/s (28.1 ns) | 1,752 MB/s (36.5 ns) | 1,377 MB/s (46.5 ns) |
| **`Vistrutah-512-256 (18r)`** | 39.2 MB/s (1,634 ns) | 1,843 MB/s (34.7 ns) | 1,816 MB/s (35.3 ns) | 1,412 MB/s (45.3 ns) | 1,085 MB/s (59.0 ns) |
| **`Vistrutah-512-512 (12r)`** | 58.2 MB/s (1,101 ns) | 2,677 MB/s (23.9 ns) | 2,603 MB/s (24.6 ns) | 2,019 MB/s (31.7 ns) | 1,589 MB/s (40.3 ns) |
| **`Vistrutah-512-512 (18r)`** | 38.1 MB/s (1,682 ns) | 1,791 MB/s (35.7 ns) | 1,761 MB/s (36.4 ns) | 1,409 MB/s (45.4 ns) | 1,088 MB/s (58.8 ns) |
| **`Vistrutah-512-256x4 (10r)`** | 70.7 MB/s (3,624 ns) | 4,488 MB/s (57.1 ns) | 4,589 MB/s (55.8 ns) | 7,020 MB/s (36.5 ns) | 6,844 MB/s (37.4 ns) |
| **`Vistrutah-512-256x4 (14r)`** | 50.6 MB/s (5,058 ns) | 2,988 MB/s (85.8 ns) | 3,110 MB/s (82.4 ns) | 5,015 MB/s (51.1 ns) | 5,484 MB/s (46.7 ns) |
| **`Vistrutah-512-256x4 (18r)`** | 39.1 MB/s (6,557 ns) | 2,247 MB/s (113.9 ns) | 2,240 MB/s (114.3 ns) | 4,423 MB/s (57.9 ns) | 4,544 MB/s (56.3 ns) |
| **`Vistrutah-512-512x4 (12r)`** | 58.9 MB/s (4,347 ns) | 3,531 MB/s (72.5 ns) | 3,598 MB/s (71.2 ns) | 6,394 MB/s (40.0 ns) | 6,341 MB/s (40.4 ns) |
| **`Vistrutah-512-512x4 (18r)`** | 38.9 MB/s (6,589 ns) | 2,219 MB/s (115.4 ns) | 2,311 MB/s (110.8 ns) | 4,600 MB/s (55.7 ns) | 4,629 MB/s (55.3 ns) |

All operations: 0 B/op, 0 allocs/op. On Intel® Core™ i7-11700K, `EMEncrypt256` (`1,891 MB/s`, `16.9 ns`) and `EMEncrypt256x4` (`6,030 MB/s`, `21.2 ns`) outperform 14-round `Rijndael-256` (`1,154 MB/s` single-block, `3,795 MB/s` 4-block) and 14-round `Vistrutah-256` (`1,449 MB/s` single-block, `4,504 MB/s` 4-block), while `EMEncrypt512` (`3,563 MB/s`) and `EMEncrypt512x4` (`7,343 MB/s`, `0.491 c/B`) outperform all `Vistrutah-512` variants (`10r`, `12r`, `14r`, `18r`).

### 2. AWS Graviton 4 (`c8g.4xlarge`, Neoverse-V2, 16 vCPUs, ARM64)

3-run averaged throughput measured on AWS Graviton 4 (`purego` bitsliced fallback vs `arm64` ARMv8 Cryptographic Extension; reference cycles per byte `c = f · t / B` at `f = 2.80 GHz` reach `0.652 c/B` on `Permute512x4`, `1.170 c/B` on `SoEM256x4`, and `0.989 c/B` on `EMEncrypt256x4`):

#### Core Permutations, Davies-Meyer, SoEM22 & AES-128 Primitives

| Operation | `purego` (Bitsliced) | `arm64` (128-bit NEON) |
| :--- | :---: | :---: |
| **`Permute256`** | 35.4 MB/s (904.1 ns) | 929.8 MB/s (34.4 ns) |
| **`Permute512`** | 39.8 MB/s (1,610 ns) | 1,572.5 MB/s (40.7 ns) |
| **`InversePermute256`** | 34.3 MB/s (933.0 ns) | 759.6 MB/s (42.1 ns) |
| **`InversePermute512`** | 30.5 MB/s (2,098 ns) | 1,027.1 MB/s (62.3 ns) |
| **`DM256`** | 34.7 MB/s (922.8 ns) | 645.1 MB/s (49.6 ns) |
| **`DM512`** | 38.8 MB/s (1,650 ns) | 932.3 MB/s (68.6 ns) |
| **`SoEM256`** | 33.6 MB/s (951.9 ns) | 684.3 MB/s (46.8 ns) |
| **`SoEM512`** | 37.2 MB/s (1,719 ns) | 1,054.6 MB/s (60.7 ns) |
| **`Permute256x4`** | 132.5 MB/s (965.9 ns) | 3,337.4 MB/s (38.4 ns) |
| **`Permute512x4`** | 117.2 MB/s (2,185 ns) | 4,294.9 MB/s (59.6 ns) |
| **`InversePermute256x4`** | 128.7 MB/s (995.0 ns) | 2,745.6 MB/s (46.6 ns) |
| **`InversePermute512x4`** | 100.3 MB/s (2,552 ns) | 3,143.2 MB/s (81.5 ns) |
| **`SoEM256x4`** | 64.0 MB/s (1,999 ns) | 2,391.9 MB/s (53.5 ns) |
| **`SoEM512x4`** | 56.6 MB/s (4,519 ns) | 1,159.6 MB/s (220.8 ns) |
| **`AES128Round`** | 207.7 MB/s (77.0 ns) | 4,459.3 MB/s (3.59 ns) |
| **`AES128Round4`** | 582.7 MB/s (109.8 ns) | 16,798.0 MB/s (3.81 ns) |
| **`ExpandKey128`** | 459.1 MB/s (383.4 ns) | 752.0 MB/s (234.0 ns) |
| **`AES128EncryptBlock`** | 31.5 MB/s (507.7 ns) | 1,589.9 MB/s (10.1 ns) |
| **`AES128Encrypt4Blocks`** | 114.3 MB/s (560.0 ns) | 6,023.9 MB/s (10.6 ns) |

#### Wide-Block Ciphers (`EM`, `EM2`, `TEM`, `TEM2`) vs. `Rijndael-256` & `Vistrutah-256/512`

| Operation | `purego` (Bitsliced) | `arm64` (128-bit NEON) |
| :--- | :---: | :---: |
| **`EMEncrypt256`** | 35.2 MB/s (907.7 ns) | 841.3 MB/s (38.0 ns) |
| **`EMDecrypt256`** | 34.1 MB/s (938.9 ns) | 706.6 MB/s (45.3 ns) |
| **`EMEncrypt512`** | 39.2 MB/s (1,633 ns) | 1,442.8 MB/s (44.4 ns) |
| **`EMDecrypt512`** | 30.1 MB/s (2,125 ns) | 966.1 MB/s (66.2 ns) |
| **`EM2Encrypt256`** | 17.9 MB/s (1,791 ns) | 449.8 MB/s (71.1 ns) |
| **`EM2Decrypt256`** | 17.4 MB/s (1,844 ns) | 371.3 MB/s (86.2 ns) |
| **`EM2Encrypt512`** | 19.8 MB/s (3,233 ns) | 771.9 MB/s (82.9 ns) |
| **`EM2Decrypt512`** | 15.2 MB/s (4,218 ns) | 501.3 MB/s (127.7 ns) |
| **`TEMEncrypt256`** | 17.9 MB/s (1,792 ns) | 623.0 MB/s (51.4 ns) |
| **`TEMDecrypt256`** | 17.6 MB/s (1,823 ns) | 598.4 MB/s (53.5 ns) |
| **`TEMEncrypt512`** | 19.8 MB/s (3,238 ns) | 787.9 MB/s (81.2 ns) |
| **`TEMDecrypt512`** | 16.9 MB/s (3,793 ns) | 634.7 MB/s (100.8 ns) |
| **`TEM2Encrypt256`** | 11.8 MB/s (2,718 ns) | 318.6 MB/s (100.4 ns) |
| **`TEM2Decrypt256`** | 11.5 MB/s (2,778 ns) | 292.8 MB/s (109.3 ns) |
| **`TEM2Encrypt512`** | 13.0 MB/s (4,931 ns) | 474.2 MB/s (134.9 ns) |
| **`TEM2Decrypt512`** | 10.7 MB/s (6,008 ns) | 363.4 MB/s (176.1 ns) |
| **`EMEncrypt256x4`** | 125.8 MB/s (1,018 ns) | 2,830.0 MB/s (45.2 ns) |
| **`EMDecrypt256x4`** | 122.3 MB/s (1,046 ns) | 2,408.8 MB/s (53.1 ns) |
| **`EMEncrypt512x4`** | 111.7 MB/s (2,292 ns) | 2,110.7 MB/s (121.3 ns) |
| **`EMDecrypt512x4`** | 96.8 MB/s (2,646 ns) | 1,587.7 MB/s (161.2 ns) |
| **`EM2Encrypt256x4`** | 64.1 MB/s (1,996 ns) | 1,565.5 MB/s (81.8 ns) |
| **`EM2Decrypt256x4`** | 62.5 MB/s (2,049 ns) | 1,346.6 MB/s (95.0 ns) |
| **`EM2Encrypt512x4`** | 56.8 MB/s (4,508 ns) | 1,112.0 MB/s (230.2 ns) |
| **`EM2Decrypt512x4`** | 48.9 MB/s (5,230 ns) | 828.0 MB/s (309.2 ns) |
| **`TEMEncrypt256x4`** | 64.2 MB/s (1,995 ns) | 1,581.5 MB/s (80.9 ns) |
| **`TEMDecrypt256x4`** | 62.8 MB/s (2,039 ns) | 1,471.7 MB/s (87.0 ns) |
| **`TEMEncrypt512x4`** | 57.1 MB/s (4,486 ns) | 1,128.8 MB/s (226.8 ns) |
| **`TEMDecrypt512x4`** | 51.6 MB/s (4,965 ns) | 959.1 MB/s (266.9 ns) |
| **`TEM2Encrypt256x4`** | 32.4 MB/s (3,950 ns) | 880.8 MB/s (145.3 ns) |
| **`TEM2Decrypt256x4`** | 31.7 MB/s (4,034 ns) | 798.1 MB/s (160.4 ns) |
| **`TEM2Encrypt512x4`** | 28.8 MB/s (8,892 ns) | 598.5 MB/s (427.7 ns) |
| **`TEM2Decrypt512x4`** | 26.0 MB/s (9,843 ns) | 499.1 MB/s (513.0 ns) |
| **`Rijndael-256`** | 33.5 MB/s (955.1 ns) | 738.0 MB/s (43.4 ns) |
| **`Rijndael-256x4`** | 93.6 MB/s (1,368 ns) | 2,357.8 MB/s (54.3 ns) |
| **`Vistrutah-256 (10r)`** | 42.3 MB/s (756.6 ns) | 1,611.2 MB/s (19.9 ns) |
| **`Vistrutah-256 (14r)`** | 30.5 MB/s (1,051 ns) | 1,221.0 MB/s (26.2 ns) |
| **`Vistrutah-256x4 (10r)`** | 80.7 MB/s (1,586 ns) | 4,485.7 MB/s (28.5 ns) |
| **`Vistrutah-256x4 (14r)`** | 57.5 MB/s (2,224 ns) | 3,552.6 MB/s (36.0 ns) |
| **`Vistrutah-512-256 (10r)`** | 66.4 MB/s (963.6 ns) | 2,783.5 MB/s (23.0 ns) |
| **`Vistrutah-512-256 (14r)`** | 47.9 MB/s (1,337 ns) | 2,069.1 MB/s (30.9 ns) |
| **`Vistrutah-512-256 (18r)`** | 37.4 MB/s (1,710 ns) | 1,648.4 MB/s (38.8 ns) |
| **`Vistrutah-512-512 (12r)`** | 55.9 MB/s (1,145 ns) | 2,369.6 MB/s (27.0 ns) |
| **`Vistrutah-512-512 (18r)`** | 37.5 MB/s (1,708 ns) | 1,645.3 MB/s (38.9 ns) |
| **`Vistrutah-512-256x4 (10r)`** | 68.0 MB/s (3,767 ns) | 4,442.6 MB/s (57.6 ns) |
| **`Vistrutah-512-256x4 (14r)`** | 48.6 MB/s (5,270 ns) | 3,447.4 MB/s (74.3 ns) |
| **`Vistrutah-512-256x4 (18r)`** | 37.8 MB/s (6,768 ns) | 2,809.7 MB/s (91.1 ns) |
| **`Vistrutah-512-512x4 (12r)`** | 56.0 MB/s (4,570 ns) | 3,802.1 MB/s (67.3 ns) |
| **`Vistrutah-512-512x4 (18r)`** | 37.4 MB/s (6,844 ns) | 2,835.1 MB/s (90.3 ns) |

All operations: 0 B/op, 0 allocs/op.

### 3. Comparison with `Rijndael-256` (`NIST SP 800-197`) and `Vistrutah-256/512` ([ePrint 2025/976](https://eprint.iacr.org/2025/976))

- **`Rijndael-256`** (14 rounds, 256-bit block, 256-bit key, `ShiftRows` offsets `(0, 1, 3, 4)` across an `8 × 4` byte matrix) requires a cross-128-bit-half byte permutation `InvShiftRows_AES128` ∘ `ShiftRows_R256(0,1,3,4)` (`PSHUFB`/`VPSHUFB` + `PBLENDVB`/`VPBLENDVB` on x86-64, `VTBL2` on ARM64) before every round and 480 bytes (`15 × 32 B`) of pre-expanded round keys in RAM.
- **`Vistrutah-256`** (`10` or `14` rounds, 256-bit block, 256-bit key) and **`Vistrutah-512`** (`10`, `14`, or `18` rounds with 256-bit key; `12` or `18` rounds with 512-bit key) alternate pairs of parallel 128-bit AES rounds with a cross-slice `mixSlice` byte shuffle (`PUNPCK*` + `PALIGNR`/`PSHUFB` on x86-64, `VZIP1`/`VZIP2` + `VTBL` on ARM64) every two rounds and an on-the-fly key permutation `ρ`.
- **`Areion-256` / `Areion-512`** use a 2-branch / 4-branch Feistel/SPN structure built natively from 128-bit AES rounds with **zero byte shuffles (`PSHUFB`/`VTBL`)** on the data path and **zero persistent round-key state in RAM** (`EM`, `EM2`, `TEM`, `TEM2` hold keys strictly in volatile registers and wipe them before returning):

| Wide-Block Cipher Primitive | Intel Core i7-11700K (Best HW Tier) | AWS Graviton 4 (`arm64`) | Block / Key / RAM Key State & Security |
| :--- | :---: | :---: | :--- |
| **`EMEncrypt256`** | **1,891 MB/s** (`16.9 ns/op`) | **841.3 MB/s** (`38.0 ns/op`) | 256b / 512b key, `0 B` RAM RK (`2^128` PRP) |
| **`EM2Encrypt256`** | **1,022 MB/s** (`31.3 ns/op`) | **449.8 MB/s** (`71.1 ns/op`) | 256b / 512b key, `0 B` RAM RK (`2^170.7` BBB PRP) |
| **`TEMEncrypt256`** | **1,810 MB/s** (`17.7 ns/op`) | **623.0 MB/s** (`51.4 ns/op`) | 256b / 512b + 256b tweak, `0 B` RAM RK (`2^128` TPRP) |
| **`TEM2Encrypt256`** | **979 MB/s** (`32.7 ns/op`) | **318.6 MB/s** (`100.4 ns/op`) | 256b / 512b + 256b tweak, `0 B` RAM RK (`2^170.7` BBB TPRP) |
| **`EMEncrypt256x4`** | **6,030 MB/s** (`5.30 ns/block`) | **2,830.0 MB/s** (`11.30 ns/block`) | 4×256b, `0 B` RAM RK (`2^128` PRP) |
| **`EM2Encrypt256x4`** | **3,247 MB/s** (`9.85 ns/block`) | **1,565.5 MB/s** (`20.45 ns/block`) | 4×256b, `0 B` RAM RK (`2^170.7` BBB PRP) |
| **`TEMEncrypt256x4`** | **4,783 MB/s** (`6.70 ns/block`) | **1,581.5 MB/s** (`20.23 ns/block`) | 4×256b + tweaks, `0 B` RAM RK (`2^128` TPRP) |
| **`TEM2Encrypt256x4`** | **2,948 MB/s** (`10.88 ns/block`) | **880.8 MB/s** (`36.33 ns/block`) | 4×256b + tweaks, `0 B` RAM RK (`2^170.7` BBB TPRP) |
| **`Rijndael-256 (14r)`** | 1,154 MB/s (`27.7 ns/op`) | 738.0 MB/s (`43.4 ns/op`) | 256b / 256b key, **`480 B` RAM RK** (`SP 800-197`) |
| **`Rijndael-256x4 (14r)`** | 3,795 MB/s (`8.43 ns/block`) | 2,357.8 MB/s (`13.58 ns/block`) | 4×256b, **`480 B` RAM RK** (`SP 800-197`) |
| **`Vistrutah-256 (10r / 14r)`** | 1,994 / 1,449 MB/s (`16.1` / `22.1 ns`) | 1,611.2 / 1,221.0 MB/s (`19.9` / `26.2 ns`) | 256b / 256b key, `0 B` RAM RK (`ePrint 2025/976`) |
| **`Vistrutah-256x4 (10r / 14r)`** | 6,033 / 4,504 MB/s (`5.30` / `7.10 ns/blk`) | 4,485.7 / 3,552.6 MB/s (`7.13` / `9.00 ns/blk`) | 4×256b, `0 B` RAM RK (`ePrint 2025/976`) |
| **`EMEncrypt512`** | **3,563 MB/s** (`18.0 ns/op`) | **1,442.8 MB/s** (`44.4 ns/op`) | 512b / 1024b key, `0 B` RAM RK (`2^256` PRP) |
| **`EMEncrypt512x4`** | **7,343 MB/s** (`8.73 ns/block`) | **2,110.7 MB/s** (`30.33 ns/block`) | 4×512b, `0 B` RAM RK (`2^256` PRP) |
| **`Vistrutah-512-256 (10r / 14r / 18r)`** | 3,245 / 2,334 / 1,843 MB/s | 2,783.5 / 2,069.1 / 1,648.4 MB/s | 512b / 256b key, `0 B` RAM RK (`ePrint 2025/976`) |
| **`Vistrutah-512-512 (12r / 18r)`** | 2,677 / 1,791 MB/s | 2,369.6 / 1,645.3 MB/s | 512b / 512b key, `0 B` RAM RK (`ePrint 2025/976`) |
| **`Vistrutah-512-256x4 (10r / 14r / 18r)`** | 7,020 / 5,484 / 4,544 MB/s | 4,442.6 / 3,447.4 / 2,809.7 MB/s | 4×512b / 256b key, `0 B` RAM RK (`ePrint 2025/976`) |
| **`Vistrutah-512-512x4 (12r / 18r)`** | 6,394 / 4,629 MB/s | 3,802.1 / 2,835.1 MB/s | 4×512b / 512b key, `0 B` RAM RK (`ePrint 2025/976`) |

> **Benchmark methodology note:** `BenchmarkPermute*`, `BenchmarkInversePermute*`, `BenchmarkEM*`, `BenchmarkTEM*`, `BenchmarkAES128Encrypt*`, `BenchmarkRijndael256*`, and `BenchmarkVistrutah*` feed their returned output back into the next iteration's input (`m = EMEncrypt*(...)`, `state = ...`), measuring serial dependency-chain latency across iterations (`AES128Encrypt*` and `Rijndael256Encrypt*` time the encryption core with pre-expanded round keys in RAM, whereas `Areion-EM*` and `Vistrutah*` take raw keys and expand/apply round keys on-the-fly in registers). `BenchmarkSoEM*` and `BenchmarkDM*` evaluate fixed input and key buffers across iterations, allowing out-of-order execution to overlap independent calls. See [`analysis/README.md` (Section L)](analysis/README.md#l-register-and-stack-clearing-cost) for interleaved single-core cycle-per-byte measurements including epilogue register and stack clearing.

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

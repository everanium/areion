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
| **[Types & Constants](API.md#1-types-and-constants)** | `Version`, `Version{Major,Minor,Patch}`, `State256`, `State512`, `Block`, `Block4`, `Key4`, `TierPureGo`..`TierARMCrypto` | 16–64 B | — | — | Version constants, fixed-size byte-array state/block type aliases, and hardware dispatch tier constants |
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

### Round Constants (`P1` and `P2`)
Table 2 (`P2`) is proposed by Andrey Kuvshinov and derived by [`scripts/verify_p2_table.py`](scripts/README.md). Following the Nothing-Up-My-Sleeve (NUMS) methodology of the original Areion paper, it continues the same stream of π words:
- **Table 1 (`P1`)**: Words 0..14 of the fractional part of π (Table 1 and Appendix A.1 of ePrint 2023/794); RC7 is kept as published, `0x801f2e2858efc16636920d871574e690`, a one-nibble shift from π word 7.
- **Table 2 (`P2`)**: Words 15..29 of the fractional part of π (15 consecutive 128-bit words); RC7, π word 22, takes the same one-nibble shift, `0xf6d6ff383f442392e0b4482a48420040`, in agreement with the Areion authors. Words 7 and 22 are the only words among 0..29 that begin with a zero nibble, so the shift falls on RC7 in both tables. The shift is a matter of consistency with Table 1: every claim of [`analysis/`](analysis/README.md) holds for both forms of this word.

The 15 hexadecimal entries of Table 1 (`P1`) and Table 2 (`P2`) (each stored in memory as 16 little-endian bytes; e.g., round 0 of `P1` begins with bytes `44 73 70 03` and round 0 of `P2` begins with bytes `93 e9 72 7c`; Areion-256 uses rounds 0..9 and Areion-512 uses rounds 0..14):

| Round | Hexadecimal constant (`P1`) | Hexadecimal constant (`P2`) |
| ---: | :--- | :--- |
| 0 | `243f6a8885a308d313198a2e03707344` | `b4cc5c341141e8cea15486af7c72e993` |
| 1 | `a4093822299f31d0082efa98ec4e6c89` | `b3ee1411636fbc2a2ba9c55d741831f6` |
| 2 | `452821e638d01377be5466cf34e90c6c` | `ce5c3e169b87931eafd6ba336c24cf5c` |
| 3 | `c0ac29b7c97c50dd3f84d5b5b5470917` | `7a325381289586773b8f48986b4bb9af` |
| 4 | `9216d5d98979fb1bd1310ba698dfb5ac` | `c4bfe81b6628219361d809ccfb21a991` |
| 5 | `2ffd72dbd01adfb7b8e1afed6a267e96` | `487cac605dec8032ef845d5de98575b1` |
| 6 | `ba7c9045f12c7f9924a19947b3916cf7` | `dc262302eb651b8823893e81d396acc5` |
| 7 | `801f2e2858efc16636920d871574e690` | `f6d6ff383f442392e0b4482a48420040` |
| 8 | `a458fea3f4933d7e0d95748f728eb658` | `69c8f04a9e1f9b5e21c66842f6e96c9a` |
| 9 | `718bcd5882154aee7b54a41dc25a59b5` | `670c9c61abd388f06a51a0d2d8542f68` |
| 10 | `9c30d5392af26013c5d1b023286085f0` | `960fa728ab5133a36eef0b6c137a3be4` |
| 11 | `ca417918b8db38ef8e79dcb0603a180e` | `ba3bf0507efb2a98a1f1651d39af0176` |
| 12 | `6c9e0e8bb01e8a3ed71577c1bd314b27` | `66ca593e82430e888cee8619456f9fb4` |
| 13 | `78af2fda55605c60e65525f3aa55ab94` | `7d84a5c33b8b5ebee06f75d885c12073` |
| 14 | `5748986263e8144055ca396a2aab10b6` | `401a449f56c16aa64ed3aa62363f7706` |

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
| **`avx512`** | Intel Ice Lake, Tiger Lake, Rocket Lake, Xeon Ice Lake-SP+; AMD Zen 4+ (`AVX-512F + AVX-512DQ + AVX-512BW + AVX-512VL + VAES`) | `VAESENC`, `VAESENCLAST`, `VAESDEC`, `VAESDECLAST`, `VPXOR`, `VPXORQ`, `VSHUFI64X2`, `VINSERTI64X4` (2-instruction `VAESENCLAST` + `VAESDEC` 512-bit `InvMixColumns`) | 512-bit ZMM (4 AES blocks) |
| **`vaesavx2`** | Intel Alder Lake+ (no AVX-512); AMD Zen 3 (`AVX2 + VAES`) | `VAESENC`, `VAESENCLAST`, `VAESDEC`, `VAESDECLAST`, `VPXOR`, `VPERM2I128` (2-instruction `VAESENCLAST` + `VAESDEC` 256-bit `InvMixColumns`) | 256-bit YMM (2 AES blocks / reg, up to 4 lanes in `Y0..Y7`) |
| **`vex`** | Intel Sandy Bridge+, AMD Bulldozer+ (`AVX + AES-NI`) | 3-operand VEX XMM `VAESENC`, `VAESENCLAST`, `VAESDECLAST`, `VAESIMC`, `VAESKEYGENASSIST`, `VPXOR`, `VPUNPCKLQDQ`, `VPUNPCKHQDQ`, `VPSRLDQ` | 128-bit XMM (3-operand VEX) |
| **`aesni`** | Intel Westmere+ (`AES-NI` without `AVX`) | Legacy SSE `AESENC`, `AESENCLAST`, `AESDECLAST`, `AESIMC`, `AESKEYGENASSIST`, `PXOR`, `PUNPCKLQDQ`, `PUNPCKHQDQ`, `PSRLDQ` | 128-bit XMM (2-operand SSE) |
| **`arm64`** | ARMv8 with Cryptographic Extension, Apple Silicon, Graviton (`NEON + AES`) | `AESE`, `AESMC`, `AESD`, `AESIMC`, `VEOR`, `VTRN1`, `VTRN2` | 128-bit NEON (up to 4 lanes in `V0..V31`) |
| **`purego`** | All architectures | Constant-time 64-bit bitsliced Boyar–Peralta forward/inverse S-boxes & maskless linear layer | 64-bit bitsliced software (up to 4 blocks/word) |

> **Note on single-block execution:** Single-block functions (`Permute256/512`, `InversePermute256/512` and their `P2` forms, `DM256/512`, `SoEM256/512`, `EM*`, `EM2*`, `TEM*`, `TEM2*`, `AES128Round`, `AES128FinalRound`, `ExpandKey128`, `AES128EncryptBlock`) use 3-operand VEX XMM instructions on `vex`, `vaesavx2`, and `avx512` tiers (eliminating destructive `MOVOA` register copies and legacy SSE transition penalties), and legacy 2-operand XMM instructions on `aesni`. `SoEM256`, `SoEM512`, `TEMEncrypt*`, and `TEM2*` interleave independent `P1` and `P2` evaluations in a single assembly call (and in lanes 0 and 1 of a single bitsliced pass on `purego`).

> **Note on VAES detection:** `golang.org/x/sys/cpu` reports VAES only together with AVX-512; the package reads CPUID leaf 7 directly so that VAES+AVX2 hosts (AMD Zen 3, Intel Alder Lake) activate the `vaesavx2` tier.

> **Register and stack zeroization:** All hardware assembly kernels (both single-block and `×4` batch functions) execute directly in registers with zero local stack spills (zero-byte stack frame, no intermediate AoS↔SoA stack buffers) and clear all touched vector registers (`PXOR` / `VPXOR` / `VPXORD` on `X0..X30` plus `VZEROUPPER` on `x86-64`; `VEOR` on `V0..V31` on `arm64`) and scratch general-purpose registers (`XORQ` on `x86-64`; `MOVD ZR` on `arm64`) before returning. On `purego` fallback paths, Go routines scrub their local buffers, scrub their 1,024-byte software stack frame (`wipeSoftwareStack`), and clobber volatile scratch GPRs (`clobberScratchGPRs`). Verified by `areion_zeroize*_test.go`; see [`analysis/README.md` (Section L)](analysis/README.md#l-register-and-stack-clearing-cost) for instruction-count and cycle-per-byte overhead measurements.

---

## Benchmarks

### 1. Intel® Core™ i7-11700K @ 3.60GHz (Rocket Lake, x86-64)

3-run averaged throughput comparison across execution tiers on the same physical CPU (with reference cycles per byte `c = f · t / B` at `f = 3.60 GHz` reaching `0.32` / `0.33 c/B` on `Permute512x4` / `Permute512P2x4`, `0.58 c/B` on `InversePermute512x4` / `InversePermute512P2x4`, `0.43` / `0.58 c/B` on `SoEM256x4` / `SoEM512x4`, and `0.28` / `0.29 c/B` on `EMEncrypt256x4` / `EMEncrypt512x4`):

#### Core Permutations, Davies-Meyer, SoEM22 & AES-128 Primitives (MB/s, ns/op)

| Operation | `purego` | `aesni` | `vex` | `vaesavx2` | `avx512` | `c/B` (best) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`Permute256`** | 37.3 (862.30 ns) | 2,062.3 (15.52 ns) | 2,125.3 (15.06 ns) | 2,116.8 (15.12 ns) | 2,125.5 (15.06 ns) | 1.69 c/B |
| **`Permute512`** | 39.2 (1,635.33 ns) | 4,029.9 (15.90 ns) | 4,043.4 (15.83 ns) | 4,039.1 (15.85 ns) | 4,039.2 (15.85 ns) | 0.89 c/B |
| **`InversePermute256`** | 35.4 (907.33 ns) | 1,460.3 (21.92 ns) | 1,462.8 (21.88 ns) | 1,465.6 (21.83 ns) | 1,462.8 (21.88 ns) | 2.46 c/B |
| **`InversePermute512`** | 32.7 (1,962.67 ns) | 1,714.4 (37.33 ns) | 1,713.0 (37.36 ns) | 1,719.3 (37.23 ns) | 1,715.6 (37.30 ns) | 2.09 c/B |
| **`Permute256P2`** | 38.5 (830.57 ns) | 2,065.7 (15.49 ns) | 2,117.8 (15.11 ns) | 2,115.3 (15.13 ns) | 2,124.6 (15.06 ns) | 1.69 c/B |
| **`Permute512P2`** | 42.4 (1,510.67 ns) | 4,089.1 (15.65 ns) | 4,046.6 (15.82 ns) | 4,004.0 (15.99 ns) | 4,013.0 (15.95 ns) | 0.88 c/B |
| **`InversePermute256P2`** | 36.3 (884.03 ns) | 1,470.5 (21.76 ns) | 1,467.9 (21.80 ns) | 1,466.6 (21.82 ns) | 1,460.8 (21.91 ns) | 2.45 c/B |
| **`InversePermute512P2`** | 32.7 (1,958.33 ns) | 1,710.0 (37.43 ns) | 1,711.9 (37.39 ns) | 1,717.1 (37.27 ns) | 1,718.1 (37.25 ns) | 2.10 c/B |
| **`DM256`** | 38.4 (834.33 ns) | 4,866.5 (6.58 ns) | 5,446.6 (5.91 ns) | 6,109.0 (5.24 ns) | 5,816.5 (5.51 ns) | 0.59 c/B |
| **`DM512`** | 42.1 (1,521.67 ns) | 5,503.4 (11.63 ns) | 5,521.3 (11.59 ns) | 5,406.2 (11.88 ns) | 5,361.2 (11.94 ns) | 0.65 c/B |
| **`SoEM256`** | 35.1 (910.60 ns) | 2,871.6 (11.18 ns) | 3,248.5 (9.86 ns) | 3,175.9 (10.09 ns) | 3,080.4 (10.47 ns) | 1.11 c/B |
| **`SoEM512`** | 39.7 (1,613.67 ns) | 3,076.2 (20.81 ns) | 3,337.8 (19.18 ns) | 3,311.1 (19.35 ns) | 3,155.6 (20.30 ns) | 1.08 c/B |
| **`Permute256x4`** | 139.1 (920.97 ns) | 6,878.6 (18.61 ns) | 6,910.9 (18.53 ns) | 7,224.2 (17.72 ns) | 6,497.1 (19.70 ns) | 0.50 c/B |
| **`Permute512x4`** | 126.3 (2,033.67 ns) | 6,836.9 (37.44 ns) | 7,039.8 (36.41 ns) | 11,337.0 (22.59 ns) | 10,875.5 (23.54 ns) | 0.32 c/B |
| **`InversePermute256x4`** | 123.1 (1,050.70 ns) | 5,400.9 (23.70 ns) | 5,366.2 (23.88 ns) | 5,323.5 (24.04 ns) | 4,884.9 (26.20 ns) | 0.67 c/B |
| **`InversePermute512x4`** | 97.1 (2,660.33 ns) | 3,679.5 (69.59 ns) | 3,793.5 (67.50 ns) | 6,228.8 (41.10 ns) | 6,025.3 (42.49 ns) | 0.58 c/B |
| **`Permute256P2x4`** | 144.0 (889.60 ns) | 6,744.3 (18.98 ns) | 7,075.9 (18.09 ns) | 7,332.7 (17.46 ns) | 6,463.6 (19.80 ns) | 0.49 c/B |
| **`Permute512P2x4`** | 124.9 (2,055.67 ns) | 7,066.7 (36.23 ns) | 6,886.6 (37.21 ns) | 10,975.3 (23.35 ns) | 10,656.6 (24.03 ns) | 0.33 c/B |
| **`InversePermute256P2x4`** | 139.6 (917.30 ns) | 5,302.6 (24.17 ns) | 5,460.7 (23.44 ns) | 5,324.9 (24.04 ns) | 4,898.2 (26.13 ns) | 0.66 c/B |
| **`InversePermute512P2x4`** | 105.7 (2,429.33 ns) | 3,634.1 (70.46 ns) | 3,792.7 (67.51 ns) | 6,219.0 (41.17 ns) | 5,997.5 (42.68 ns) | 0.58 c/B |
| **`SoEM256x4`** | 65.1 (1,965.33 ns) | 3,700.6 (34.61 ns) | 3,906.6 (32.77 ns) | 6,030.7 (21.23 ns) | 8,400.8 (15.24 ns) | 0.43 c/B |
| **`SoEM512x4`** | 60.4 (4,260.33 ns) | 3,370.5 (76.02 ns) | 3,372.6 (75.93 ns) | 5,582.8 (45.86 ns) | 6,177.8 (41.45 ns) | 0.58 c/B |
| **`AES128Round`** | 243.6 (66.38 ns) | 5,992.4 (2.67 ns) | 6,563.4 (2.45 ns) | 6,760.8 (2.37 ns) | 6,713.3 (2.39 ns) | 0.53 c/B |
| **`AES128Round4`** | 603.2 (106.13 ns) | 14,438.0 (4.46 ns) | 16,977.1 (3.78 ns) | 19,402.6 (3.30 ns) | 21,714.9 (2.98 ns) | 0.17 c/B |
| **`ExpandKey128`** | 527.9 (333.50 ns) | 4,694.4 (37.52 ns) | 4,813.8 (36.56 ns) | 4,723.4 (37.27 ns) | 4,657.4 (37.81 ns) | 0.75 c/B |
| **`AES128EncryptBlock`** | 30.9 (519.67 ns) | 1,889.3 (8.47 ns) | 1,899.6 (8.42 ns) | 1,902.4 (8.41 ns) | 1,903.3 (8.41 ns) | 1.89 c/B |
| **`AES128Encrypt4Blocks`** | 115.8 (553.07 ns) | 7,272.8 (8.80 ns) | 7,390.9 (8.66 ns) | 7,381.9 (8.67 ns) | 7,386.2 (8.67 ns) | 0.49 c/B |

#### Wide-Block Ciphers (`EM`, `EM2`, `TEM`, `TEM2`) vs. `Rijndael-256`, `Vistrutah-256/512` & `ASURA` (MB/s, ns/op)

| Operation | `purego` | `aesni` | `vex` | `vaesavx2` | `avx512` | `c/B` (best) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`EMEncrypt256`** | 36.7 (871.83 ns) | 4,561.2 (7.03 ns) | 5,810.6 (5.51 ns) | 5,378.3 (5.95 ns) | 5,667.7 (5.65 ns) | 0.62 c/B |
| **`EMDecrypt256`** | 36.4 (879.60 ns) | 3,554.7 (9.03 ns) | 4,101.7 (7.80 ns) | 4,400.4 (7.28 ns) | 4,306.1 (7.43 ns) | 0.82 c/B |
| **`EMEncrypt512`** | 41.6 (1,540.33 ns) | 5,362.0 (11.96 ns) | 5,450.9 (11.74 ns) | 5,615.2 (11.40 ns) | 5,256.1 (12.21 ns) | 0.64 c/B |
| **`EMDecrypt512`** | 33.2 (1,927.67 ns) | 2,719.5 (23.55 ns) | 2,883.7 (22.20 ns) | 2,842.5 (22.53 ns) | 2,832.9 (22.59 ns) | 1.25 c/B |
| **`EM2Encrypt256`** | 19.7 (1,623.00 ns) | 2,160.9 (14.83 ns) | 2,268.8 (14.15 ns) | 2,348.6 (13.64 ns) | 2,328.2 (13.76 ns) | 1.53 c/B |
| **`EM2Decrypt256`** | 18.4 (1,742.00 ns) | 1,668.9 (19.21 ns) | 1,717.5 (18.69 ns) | 1,764.2 (18.15 ns) | 1,713.9 (18.71 ns) | 2.04 c/B |
| **`EM2Encrypt512`** | 21.0 (3,051.00 ns) | 2,419.0 (26.46 ns) | 2,356.2 (27.17 ns) | 2,347.5 (27.27 ns) | 2,392.5 (26.75 ns) | 1.49 c/B |
| **`EM2Decrypt512`** | 17.1 (3,747.67 ns) | 1,070.8 (59.77 ns) | 1,082.1 (59.15 ns) | 1,080.5 (59.24 ns) | 1,064.7 (60.14 ns) | 3.33 c/B |
| **`TEMEncrypt256`** | 19.0 (1,688.33 ns) | 2,166.6 (14.78 ns) | 2,245.3 (14.26 ns) | 2,341.2 (13.68 ns) | 2,307.4 (13.89 ns) | 1.54 c/B |
| **`TEMDecrypt256`** | 19.3 (1,658.00 ns) | 1,904.6 (16.81 ns) | 2,082.2 (15.41 ns) | 2,213.9 (14.46 ns) | 1,989.2 (16.12 ns) | 1.63 c/B |
| **`TEMEncrypt512`** | 20.9 (3,068.00 ns) | 2,241.2 (28.57 ns) | 2,293.8 (27.92 ns) | 2,317.4 (27.63 ns) | 2,273.8 (28.15 ns) | 1.55 c/B |
| **`TEMDecrypt512`** | 18.3 (3,505.67 ns) | 1,569.7 (40.78 ns) | 1,603.1 (39.93 ns) | 1,569.6 (40.84 ns) | 1,627.0 (39.34 ns) | 2.21 c/B |
| **`TEM2Encrypt256`** | 12.6 (2,535.67 ns) | 1,087.5 (29.44 ns) | 1,187.8 (26.95 ns) | 1,138.3 (28.13 ns) | 1,147.4 (27.89 ns) | 3.03 c/B |
| **`TEM2Decrypt256`** | 11.3 (2,832.00 ns) | 901.6 (35.55 ns) | 901.7 (35.50 ns) | 966.1 (33.12 ns) | 916.1 (34.96 ns) | 3.73 c/B |
| **`TEM2Encrypt512`** | 13.3 (4,830.00 ns) | 1,271.0 (50.39 ns) | 1,341.3 (47.72 ns) | 1,315.9 (48.65 ns) | 1,334.2 (47.98 ns) | 2.68 c/B |
| **`TEM2Decrypt512`** | 11.1 (5,791.00 ns) | 752.5 (85.07 ns) | 758.9 (84.34 ns) | 775.8 (82.49 ns) | 766.1 (83.55 ns) | 4.64 c/B |
| **`EMEncrypt256x4`** | 134.4 (957.40 ns) | 6,998.3 (18.30 ns) | 7,446.8 (17.21 ns) | 9,081.6 (14.11 ns) | 12,789.7 (10.04 ns) | 0.28 c/B |
| **`EMDecrypt256x4`** | 123.0 (1,047.73 ns) | 5,853.5 (21.88 ns) | 6,208.6 (20.62 ns) | 7,882.1 (16.25 ns) | 10,932.6 (11.71 ns) | 0.33 c/B |
| **`EMEncrypt512x4`** | 120.7 (2,124.67 ns) | 6,127.2 (41.83 ns) | 6,150.4 (41.68 ns) | 10,282.9 (24.93 ns) | 12,409.3 (20.64 ns) | 0.29 c/B |
| **`EMDecrypt512x4`** | 101.9 (2,521.67 ns) | 3,493.8 (73.27 ns) | 3,475.5 (73.71 ns) | 6,057.0 (42.27 ns) | 7,438.8 (34.44 ns) | 0.48 c/B |
| **`EM2Encrypt256x4`** | 71.1 (1,801.33 ns) | 3,200.1 (40.01 ns) | 3,752.7 (34.14 ns) | 4,707.8 (27.21 ns) | 6,513.2 (19.66 ns) | 0.55 c/B |
| **`EM2Decrypt256x4`** | 66.4 (1,926.67 ns) | 2,691.9 (47.57 ns) | 2,768.8 (46.26 ns) | 3,730.1 (34.32 ns) | 5,327.8 (24.03 ns) | 0.68 c/B |
| **`EM2Encrypt512x4`** | 61.6 (4,158.67 ns) | 3,256.9 (78.60 ns) | 3,103.4 (82.63 ns) | 4,153.8 (61.66 ns) | 5,838.2 (43.88 ns) | 0.62 c/B |
| **`EM2Decrypt512x4`** | 50.0 (5,120.67 ns) | 1,680.7 (152.30 ns) | 1,695.7 (150.93 ns) | 2,032.6 (125.97 ns) | 3,606.7 (70.99 ns) | 1.00 c/B |
| **`TEMEncrypt256x4`** | 68.5 (1,876.67 ns) | 2,714.8 (47.15 ns) | 2,933.0 (43.65 ns) | 4,581.3 (27.95 ns) | 6,282.9 (20.39 ns) | 0.57 c/B |
| **`TEMDecrypt256x4`** | 65.2 (1,965.67 ns) | 2,715.7 (47.14 ns) | 2,842.7 (45.05 ns) | 4,433.2 (28.89 ns) | 5,944.5 (21.56 ns) | 0.61 c/B |
| **`TEMEncrypt512x4`** | 59.3 (4,329.33 ns) | 2,905.3 (88.16 ns) | 3,060.6 (83.65 ns) | 4,106.4 (62.36 ns) | 5,788.9 (44.24 ns) | 0.62 c/B |
| **`TEMDecrypt512x4`** | 50.4 (5,091.67 ns) | 2,077.0 (123.33 ns) | 2,136.1 (119.90 ns) | 2,861.4 (89.52 ns) | 4,553.0 (56.28 ns) | 0.79 c/B |
| **`TEM2Encrypt256x4`** | 36.3 (3,529.67 ns) | 1,480.5 (86.48 ns) | 1,517.6 (84.38 ns) | 2,779.8 (46.06 ns) | 3,250.3 (39.42 ns) | 1.11 c/B |
| **`TEM2Decrypt256x4`** | 34.3 (3,740.33 ns) | 1,276.5 (100.30 ns) | 1,279.9 (100.03 ns) | 2,324.0 (55.09 ns) | 2,714.4 (47.16 ns) | 1.33 c/B |
| **`TEM2Encrypt512x4`** | 32.0 (8,009.33 ns) | 1,342.2 (190.77 ns) | 1,358.9 (188.37 ns) | 2,536.5 (100.93 ns) | 3,219.3 (79.53 ns) | 1.12 c/B |
| **`TEM2Decrypt512x4`** | 27.1 (9,451.67 ns) | 752.3 (340.30 ns) | 747.6 (343.40 ns) | 1,440.6 (177.67 ns) | 2,321.2 (110.33 ns) | 1.55 c/B |
| **`Rijndael-256`** | 30.5 (1,063.10 ns) | 2,182.3 (14.68 ns) | 1,936.8 (16.52 ns) | 1,909.1 (16.77 ns) | 1,827.5 (17.53 ns) | 1.65 c/B |
| **`Rijndael-256x4`** | 88.6 (1,446.33 ns) | 3,649.8 (35.10 ns) | 3,168.7 (40.42 ns) | 4,257.9 (30.13 ns) | 6,929.4 (18.50 ns) | 0.52 c/B |
| **`Vistrutah-256 (10r)`** | 43.5 (735.97 ns) | 3,746.5 (8.55 ns) | 3,819.1 (8.40 ns) | 4,704.6 (6.84 ns) | 4,831.2 (6.66 ns) | 0.75 c/B |
| **`Vistrutah-256 (14r)`** | 29.5 (1,098.30 ns) | 2,574.6 (12.43 ns) | 2,660.7 (12.04 ns) | 3,390.7 (9.45 ns) | 3,489.6 (9.17 ns) | 1.03 c/B |
| **`Vistrutah-256x4 (10r)`** | 74.9 (1,711.33 ns) | 6,284.6 (20.37 ns) | 6,253.2 (20.48 ns) | 9,024.8 (14.20 ns) | 11,948.8 (10.72 ns) | 0.30 c/B |
| **`Vistrutah-256x4 (14r)`** | 58.5 (2,187.67 ns) | 4,596.4 (27.86 ns) | 4,367.4 (29.34 ns) | 6,066.8 (21.12 ns) | 8,263.1 (15.50 ns) | 0.44 c/B |
| **`Vistrutah-512-256 (10r)`** | 67.9 (943.43 ns) | 4,166.5 (15.38 ns) | 4,280.1 (14.96 ns) | 4,892.2 (13.09 ns) | 3,973.1 (16.13 ns) | 0.74 c/B |
| **`Vistrutah-512-256 (14r)`** | 48.5 (1,321.33 ns) | 2,819.3 (22.70 ns) | 2,811.0 (22.79 ns) | 3,185.5 (20.10 ns) | 2,648.3 (24.20 ns) | 1.13 c/B |
| **`Vistrutah-512-256 (18r)`** | 36.6 (1,760.00 ns) | 2,058.6 (31.13 ns) | 2,035.9 (31.57 ns) | 2,444.7 (26.18 ns) | 1,927.2 (33.24 ns) | 1.47 c/B |
| **`Vistrutah-512-512 (12r)`** | 58.4 (1,096.33 ns) | 3,432.1 (18.65 ns) | 3,596.6 (17.81 ns) | 4,038.6 (15.85 ns) | 3,447.0 (18.59 ns) | 0.89 c/B |
| **`Vistrutah-512-512 (18r)`** | 36.1 (1,773.67 ns) | 2,152.3 (29.75 ns) | 2,205.8 (29.02 ns) | 2,364.7 (27.10 ns) | 2,061.4 (31.05 ns) | 1.52 c/B |
| **`Vistrutah-512-256x4 (10r)`** | 67.7 (3,794.33 ns) | 5,004.8 (51.15 ns) | 5,094.1 (50.29 ns) | 8,644.8 (29.62 ns) | 10,641.0 (24.06 ns) | 0.34 c/B |
| **`Vistrutah-512-256x4 (14r)`** | 50.9 (5,031.67 ns) | 3,221.1 (79.51 ns) | 3,302.8 (77.51 ns) | 6,251.4 (40.99 ns) | 7,111.6 (36.01 ns) | 0.51 c/B |
| **`Vistrutah-512-256x4 (18r)`** | 38.9 (6,632.00 ns) | 2,377.0 (107.70 ns) | 2,399.0 (106.83 ns) | 5,115.6 (50.06 ns) | 5,564.7 (46.02 ns) | 0.65 c/B |
| **`Vistrutah-512-512x4 (12r)`** | 59.2 (4,326.67 ns) | 4,074.7 (62.83 ns) | 4,091.8 (62.58 ns) | 7,663.2 (33.43 ns) | 8,820.2 (29.05 ns) | 0.41 c/B |
| **`Vistrutah-512-512x4 (18r)`** | 38.8 (6,609.33 ns) | 2,391.3 (107.07 ns) | 2,433.8 (105.20 ns) | 5,169.4 (49.53 ns) | 5,729.1 (44.71 ns) | 0.63 c/B |
| **`Asura-ExpandTweakey`** | 34.1 (946.13 ns) | 1,451.6 (22.05 ns) | 1,433.9 (22.33 ns) | 1,462.8 (21.88 ns) | 1,412.6 (22.67 ns) | 2.46 c/B |
| **`Asura-Encrypt (12r, rtk)`** | 24.3 (1,319.67 ns) | 3,685.4 (8.69 ns) | 3,771.8 (8.50 ns) | 3,864.1 (8.28 ns) | 3,601.1 (8.89 ns) | 0.93 c/B |
| **`Asura-Decrypt (12r, rtk)`** | 25.3 (1,266.67 ns) | 2,148.8 (14.90 ns) | 2,265.0 (14.13 ns) | 2,257.0 (14.18 ns) | 2,023.2 (15.92 ns) | 1.59 c/B |
| **`Asura-Encryptx4 (12r, rtk)`** | 50.5 (2,535.00 ns) | 4,984.4 (25.77 ns) | 5,319.0 (24.06 ns) | 7,334.4 (17.45 ns) | 11,091.8 (11.54 ns) | 0.32 c/B |
| **`Asura-Decryptx4 (12r, rtk)`** | 55.2 (2,319.33 ns) | 3,654.2 (35.03 ns) | 3,675.0 (34.83 ns) | 4,842.4 (26.43 ns) | 7,203.7 (17.77 ns) | 0.50 c/B |
| **`Asura-Encrypt-OTF (12r)`** | 14.6 (2,195.33 ns) | 1,086.3 (29.49 ns) | 1,110.9 (28.83 ns) | 1,121.2 (28.55 ns) | 1,113.4 (28.74 ns) | 3.21 c/B |
| **`Asura-Decrypt-OTF (12r)`** | 9.8 (3,260.00 ns) | 544.4 (58.85 ns) | 574.8 (55.68 ns) | 568.2 (56.34 ns) | 574.3 (55.72 ns) | 6.26 c/B |
| **`Asura-Encryptx4-OTF (12r)`** | 37.9 (3,374.00 ns) | 2,701.6 (47.38 ns) | 2,758.0 (46.41 ns) | 3,338.3 (38.38 ns) | 2,929.5 (43.69 ns) | 1.08 c/B |
| **`Asura-Decryptx4-OTF (12r)`** | 28.5 (4,512.33 ns) | 1,562.8 (81.93 ns) | 1,580.8 (81.00 ns) | 1,823.5 (70.20 ns) | 1,501.0 (85.28 ns) | 1.97 c/B |

All operations: 0 B/op, 0 allocs/op. On Intel® Core™ i7-11700K, `EMEncrypt256` (`5,810.6 MB/s`, `5.51 ns`, `0.62 c/B`) and `EMEncrypt256x4` (`12,789.7 MB/s`, `10.04 ns`, `0.28 c/B`) outperform 14-round `Rijndael-256` (`2,182.3 MB/s` single-block, `6,929.4 MB/s` 4-block), 10r/14r `Vistrutah-256` (`4,831.2` / `3,489.6 MB/s` single-block, `11,948.8` / `8,263.1 MB/s` 4-block), and 12-round `ASURA` (`3,864.1 MB/s` pre-expanded `rtk` / `1,121.2 MB/s` `OTF` single-block, `11,091.8 MB/s` `rtk` / `3,338.3 MB/s` `OTF` 4-block), while `TEMEncrypt256` (`2,341.2 MB/s`) and `TEMDecrypt256` (`2,213.9 MB/s`) outperform `Asura-Encrypt-OTF` (`1,121.2 MB/s`, `2.1×`) and `Asura-Decrypt-OTF` (`574.8 MB/s`, `3.9×`), and `EMEncrypt512` (`5,615.2 MB/s`, `11.40 ns`, `0.64 c/B`) and `EMEncrypt512x4` (`12,409.3 MB/s`, `20.64 ns`, `0.29 c/B`) outperform all `Vistrutah-512` variants (`10r`, `12r`, `14r`, `18r`).

### 2. AWS Graviton 4 (`c8g.4xlarge`, Neoverse-V2, 16 vCPUs, ARM64)

3-run averaged throughput measured on AWS Graviton 4 (`purego` bitsliced fallback vs `arm64` ARMv8 Cryptographic Extension; reference cycles per byte `c = f · t / B` at `f = 2.80 GHz` reach `0.55 c/B` on `Permute512x4` / `Permute512P2x4`, `0.57` / `0.63 c/B` on `InversePermute256x4` / `InversePermute512x4`, `1.05` / `1.63 c/B` on `SoEM256x4` / `SoEM512x4`, and `0.75` / `0.64 c/B` on `EMEncrypt256x4` / `EMEncrypt512x4`):

#### Core Permutations, Davies-Meyer, SoEM22 & AES-128 Primitives (MB/s, ns/op)

| Operation | `purego` | `arm64` | `c/B` (`arm64`) |
| :--- | :---: | :---: | :---: |
| **`Permute256`** | 35.3 (905.70 ns) | 1,034.3 (30.94 ns) | 2.71 c/B |
| **`Permute512`** | 39.6 (1,615.00 ns) | 1,853.8 (34.52 ns) | 1.51 c/B |
| **`InversePermute256`** | 34.3 (932.93 ns) | 1,350.0 (23.70 ns) | 2.07 c/B |
| **`InversePermute512`** | 30.5 (2,101.67 ns) | 1,592.9 (40.18 ns) | 1.76 c/B |
| **`Permute256P2`** | 35.4 (905.00 ns) | 1,031.1 (31.04 ns) | 2.72 c/B |
| **`Permute512P2`** | 39.7 (1,612.33 ns) | 1,853.4 (34.53 ns) | 1.51 c/B |
| **`InversePermute256P2`** | 34.4 (930.90 ns) | 1,350.3 (23.70 ns) | 2.07 c/B |
| **`InversePermute512P2`** | 30.4 (2,101.67 ns) | 1,593.5 (40.16 ns) | 1.76 c/B |
| **`DM256`** | 35.4 (903.97 ns) | 2,419.2 (13.23 ns) | 1.16 c/B |
| **`DM512`** | 39.4 (1,625.00 ns) | 2,351.2 (27.22 ns) | 1.19 c/B |
| **`SoEM256`** | 33.5 (955.27 ns) | 1,167.5 (27.41 ns) | 2.40 c/B |
| **`SoEM512`** | 36.9 (1,735.00 ns) | 1,669.4 (38.34 ns) | 1.68 c/B |
| **`Permute256x4`** | 132.7 (964.83 ns) | 4,070.9 (31.44 ns) | 0.69 c/B |
| **`Permute512x4`** | 117.7 (2,175.67 ns) | 5,050.5 (50.69 ns) | 0.55 c/B |
| **`InversePermute256x4`** | 128.8 (993.67 ns) | 4,879.4 (26.23 ns) | 0.57 c/B |
| **`InversePermute512x4`** | 99.9 (2,562.67 ns) | 4,452.0 (57.50 ns) | 0.63 c/B |
| **`Permute256P2x4`** | 132.8 (964.13 ns) | 4,074.3 (31.42 ns) | 0.69 c/B |
| **`Permute512P2x4`** | 117.5 (2,178.67 ns) | 5,049.8 (50.70 ns) | 0.55 c/B |
| **`InversePermute256P2x4`** | 128.8 (993.80 ns) | 4,869.5 (26.29 ns) | 0.58 c/B |
| **`InversePermute512P2x4`** | 100.0 (2,560.67 ns) | 4,443.6 (57.61 ns) | 0.63 c/B |
| **`SoEM256x4`** | 65.7 (1,949.67 ns) | 2,655.9 (48.20 ns) | 1.05 c/B |
| **`SoEM512x4`** | 57.1 (4,480.00 ns) | 1,716.6 (149.13 ns) | 1.63 c/B |
| **`AES128Round`** | 212.9 (75.14 ns) | 4,459.5 (3.59 ns) | 0.63 c/B |
| **`AES128Round4`** | 577.7 (110.80 ns) | 16,739.7 (3.82 ns) | 0.17 c/B |
| **`ExpandKey128`** | 451.1 (390.20 ns) | 6,511.9 (27.03 ns) | 0.43 c/B |
| **`AES128EncryptBlock`** | 31.5 (507.70 ns) | 1,594.2 (10.04 ns) | 1.76 c/B |
| **`AES128Encrypt4Blocks`** | 115.0 (556.47 ns) | 6,053.8 (10.57 ns) | 0.46 c/B |

#### Wide-Block Ciphers (`EM`, `EM2`, `TEM`, `TEM2`) vs. `Rijndael-256`, `Vistrutah-256/512` & `ASURA` (MB/s, ns/op)

| Operation | `purego` | `arm64` | `c/B` (`arm64`) |
| :--- | :---: | :---: | :---: |
| **`EMEncrypt256`** | 35.2 (909.23 ns) | 2,335.2 (13.70 ns) | 1.20 c/B |
| **`EMDecrypt256`** | 34.1 (939.77 ns) | 2,566.0 (12.47 ns) | 1.09 c/B |
| **`EMEncrypt512`** | 39.2 (1,630.67 ns) | 2,291.8 (27.93 ns) | 1.22 c/B |
| **`EMDecrypt512`** | 29.9 (2,140.67 ns) | 1,746.0 (36.66 ns) | 1.60 c/B |
| **`EM2Encrypt256`** | 17.9 (1,791.00 ns) | 994.4 (32.18 ns) | 2.82 c/B |
| **`EM2Decrypt256`** | 17.3 (1,849.33 ns) | 1,136.5 (28.16 ns) | 2.46 c/B |
| **`EM2Encrypt512`** | 19.8 (3,231.67 ns) | 1,049.9 (60.96 ns) | 2.67 c/B |
| **`EM2Decrypt512`** | 15.0 (4,254.33 ns) | 841.3 (76.07 ns) | 3.33 c/B |
| **`TEMEncrypt256`** | 17.8 (1,793.00 ns) | 975.5 (32.81 ns) | 2.87 c/B |
| **`TEMDecrypt256`** | 17.5 (1,824.33 ns) | 936.2 (34.18 ns) | 2.99 c/B |
| **`TEMEncrypt512`** | 19.8 (3,239.33 ns) | 1,033.5 (61.93 ns) | 2.71 c/B |
| **`TEMDecrypt512`** | 17.0 (3,755.33 ns) | 912.2 (70.16 ns) | 3.07 c/B |
| **`TEM2Encrypt256`** | 11.7 (2,730.33 ns) | 451.1 (70.93 ns) | 6.21 c/B |
| **`TEM2Decrypt256`** | 11.5 (2,777.00 ns) | 494.4 (64.73 ns) | 5.66 c/B |
| **`TEM2Encrypt512`** | 13.0 (4,925.33 ns) | 644.1 (99.36 ns) | 4.35 c/B |
| **`TEM2Decrypt512`** | 10.8 (5,945.33 ns) | 567.8 (112.70 ns) | 4.93 c/B |
| **`EMEncrypt256x4`** | 128.7 (994.93 ns) | 3,743.4 (34.19 ns) | 0.75 c/B |
| **`EMDecrypt256x4`** | 124.8 (1,025.33 ns) | 4,397.9 (29.11 ns) | 0.64 c/B |
| **`EMEncrypt512x4`** | 113.8 (2,249.67 ns) | 4,384.3 (58.39 ns) | 0.64 c/B |
| **`EMDecrypt512x4`** | 97.6 (2,623.67 ns) | 3,951.8 (64.78 ns) | 0.71 c/B |
| **`EM2Encrypt256x4`** | 65.6 (1,951.67 ns) | 1,990.0 (64.32 ns) | 1.41 c/B |
| **`EM2Decrypt256x4`** | 63.4 (2,018.33 ns) | 2,392.1 (53.51 ns) | 1.17 c/B |
| **`EM2Encrypt512x4`** | 57.7 (4,438.33 ns) | 2,381.6 (107.50 ns) | 1.18 c/B |
| **`EM2Decrypt512x4`** | 49.3 (5,197.00 ns) | 2,151.7 (118.97 ns) | 1.30 c/B |
| **`TEMEncrypt256x4`** | 65.9 (1,943.67 ns) | 2,027.9 (63.12 ns) | 1.38 c/B |
| **`TEMDecrypt256x4`** | 64.4 (1,988.33 ns) | 2,189.1 (58.47 ns) | 1.28 c/B |
| **`TEMEncrypt512x4`** | 57.0 (4,488.00 ns) | 1,709.3 (149.80 ns) | 1.64 c/B |
| **`TEMDecrypt512x4`** | 51.6 (4,958.67 ns) | 1,578.5 (162.20 ns) | 1.77 c/B |
| **`TEM2Encrypt256x4`** | 33.3 (3,844.00 ns) | 1,078.6 (118.70 ns) | 2.60 c/B |
| **`TEM2Decrypt256x4`** | 32.6 (3,925.33 ns) | 1,169.4 (109.43 ns) | 2.39 c/B |
| **`TEM2Encrypt512x4`** | 28.8 (8,905.00 ns) | 885.2 (289.20 ns) | 3.16 c/B |
| **`TEM2Decrypt512x4`** | 26.1 (9,806.33 ns) | 822.0 (311.47 ns) | 3.41 c/B |
| **`Rijndael-256`** | 33.5 (955.07 ns) | 1,405.3 (22.77 ns) | 1.99 c/B |
| **`Rijndael-256x4`** | 93.5 (1,369.33 ns) | 2,717.9 (47.10 ns) | 1.03 c/B |
| **`Vistrutah-256 (10r)`** | 42.2 (758.10 ns) | 3,635.5 (8.80 ns) | 0.77 c/B |
| **`Vistrutah-256 (14r)`** | 30.4 (1,053.33 ns) | 2,482.3 (12.89 ns) | 1.13 c/B |
| **`Vistrutah-256x4 (10r)`** | 79.9 (1,602.00 ns) | 6,323.2 (20.24 ns) | 0.44 c/B |
| **`Vistrutah-256x4 (14r)`** | 57.3 (2,233.67 ns) | 4,575.8 (27.97 ns) | 0.61 c/B |
| **`Vistrutah-512-256 (10r)`** | 65.8 (973.13 ns) | 3,786.7 (16.90 ns) | 0.74 c/B |
| **`Vistrutah-512-256 (14r)`** | 47.4 (1,350.00 ns) | 2,594.4 (24.67 ns) | 1.08 c/B |
| **`Vistrutah-512-256 (18r)`** | 37.1 (1,727.00 ns) | 1,961.1 (32.64 ns) | 1.43 c/B |
| **`Vistrutah-512-512 (12r)`** | 55.9 (1,145.33 ns) | 3,094.8 (20.68 ns) | 0.90 c/B |
| **`Vistrutah-512-512 (18r)`** | 37.5 (1,708.00 ns) | 1,985.3 (32.24 ns) | 1.41 c/B |
| **`Vistrutah-512-256x4 (10r)`** | 67.7 (3,779.00 ns) | 5,449.5 (46.98 ns) | 0.51 c/B |
| **`Vistrutah-512-256x4 (14r)`** | 48.5 (5,280.67 ns) | 4,147.9 (61.72 ns) | 0.68 c/B |
| **`Vistrutah-512-256x4 (18r)`** | 37.7 (6,783.33 ns) | 3,235.4 (79.13 ns) | 0.87 c/B |
| **`Vistrutah-512-512x4 (12r)`** | 56.7 (4,514.33 ns) | 4,849.4 (52.79 ns) | 0.58 c/B |
| **`Vistrutah-512-512x4 (18r)`** | 37.8 (6,765.67 ns) | 3,262.1 (78.48 ns) | 0.86 c/B |
| **`Asura-ExpandTweakey`** | 32.2 (992.77 ns) | 844.6 (37.88 ns) | 3.31 c/B |
| **`Asura-Encrypt (12r, rtk)`** | 22.7 (1,410.67 ns) | 3,058.8 (10.46 ns) | 0.92 c/B |
| **`Asura-Decrypt (12r, rtk)`** | 25.0 (1,281.33 ns) | 1,668.2 (19.18 ns) | 1.68 c/B |
| **`Asura-Encryptx4 (12r, rtk)`** | 50.3 (2,543.00 ns) | 5,847.9 (21.89 ns) | 0.48 c/B |
| **`Asura-Decryptx4 (12r, rtk)`** | 55.3 (2,316.33 ns) | 3,508.4 (36.48 ns) | 0.80 c/B |
| **`Asura-Encrypt-OTF (12r)`** | 13.4 (2,382.00 ns) | 793.8 (40.31 ns) | 3.53 c/B |
| **`Asura-Decrypt-OTF (12r)`** | 9.7 (3,296.00 ns) | 337.9 (94.71 ns) | 8.29 c/B |
| **`Asura-Encryptx4-OTF (12r)`** | 35.9 (3,570.33 ns) | 2,420.0 (52.89 ns) | 1.16 c/B |
| **`Asura-Decryptx4-OTF (12r)`** | 28.9 (4,436.33 ns) | 1,136.2 (112.67 ns) | 2.46 c/B |

All operations: 0 B/op, 0 allocs/op.

### 3. Comparison with `Rijndael-256` (`NIST SP 800-197`), `Vistrutah-256/512` ([ePrint 2025/976](https://eprint.iacr.org/2025/976)) & `ASURA` (`INDOCRYPT 2024`) (MB/s, ns/op)

- **`Rijndael-256`** (14 rounds, 256-bit block, 256-bit key, `ShiftRows` offsets `(0, 1, 3, 4)` across an `8 × 4` byte matrix) requires a cross-128-bit-half byte permutation `InvShiftRows_AES128` ∘ `ShiftRows_R256(0,1,3,4)` (`PSHUFB`/`VPSHUFB` + `PBLENDVB`/`VPBLENDVB` on x86-64, `VTBL2` on ARM64) before every round and 480 bytes (`15 × 32 B`) of pre-expanded round keys in RAM.
- **`Vistrutah-256`** (`10` or `14` rounds, 256-bit block, 256-bit key) and **`Vistrutah-512`** (`10`, `14`, or `18` rounds with 256-bit key; `12` or `18` rounds with 512-bit key) alternate pairs of parallel 128-bit AES rounds with a cross-slice `mixSlice` byte shuffle (`PUNPCK*` + `PALIGNR`/`PSHUFB` on x86-64, `VZIP1`/`VZIP2` + `VTBL` on ARM64) every two rounds and an on-the-fly key permutation `ρ`.
- **`ASURA`** (`12` rounds = `6` double-rounds + final half-round, 256-bit block, 256-bit key, 128-bit tweak, INDOCRYPT 2024) couples two 128-bit AES lanes via a 32-byte permutation `perm256` mapped natively to `VUZP1` / `VUZP2` (encryption) and `VZIP1` / `VZIP2` (decryption) on ARM64 (or `VPSHUFB` + `VPUNPCKLQDQ`/`VPUNPCKHQDQ` on x86-64). Because `ASURA` applies `MixColumns` in its final half-round and uses forward `AESENC` inside `R_core` during decryption, decryption requires additional AES instructions per sub-round (`AESMC` + `AESE` on ARM64, `VAESDECLAST` + `VAESENC` on x86-64, even after collapsing the `F_delta` inverse branch via the Equivalent Inverse Cipher identity) — making `ASURA` decryption ~1.5–1.8× slower than encryption (`1,668.2` vs `3,058.8 MB/s` on Graviton 4; `2,265.0` vs `3,864.1 MB/s` on Intel i7-11700K). Furthermore, `ASURA` requires either **416 bytes (`13 × 32 B`) of pre-expanded round tweakeys in RAM** (invalidated whenever the 128-bit tweak changes) or an **on-the-fly (`OTF`) tweakey schedule** that executes 12 additional AES rounds on the tweak plus 12 `κ` byte-shuffle + `GF(2^8)` xtime updates per block (24 steps for `OTF` decryption: 12 forward to derive `rtk[12]` followed by 12 inverse steps), reducing single-block `OTF` throughput to `793.8` / `337.9 MB/s` (`Enc`/`Dec`) on Graviton 4 and `1,121.2` / `574.8 MB/s` on Intel i7-11700K.
- **`Areion-256` / `Areion-512`** use a 2-branch / 4-branch Feistel/SPN structure built natively from 128-bit AES rounds with **zero byte shuffles (`PSHUFB`/`VTBL`)** on the data path, symmetric encryption/decryption cost, and **zero persistent round-key state in RAM** (`EM`, `EM2`, `TEM`, `TEM2` hold keys and tweaks strictly in volatile registers and wipe them before returning):

| Wide-Block Cipher Primitive | Intel Core i7-11700K (Best HW Tier) | AWS Graviton 4 (`arm64`) | Block / Key / RAM Key State & Security |
| :--- | :---: | :---: | :--- |
| **`EMEncrypt256`** | **5,810.6** (5.51 ns) | **2,335.2** (13.70 ns) | 256b / 512b key, 0 B RAM RK (2^128 PRP) |
| **`EMDecrypt256`** | **4,400.4** (7.28 ns) | **2,566.0** (12.47 ns) | 256b / 512b key, 0 B RAM RK (2^128 PRP) |
| **`EMEncrypt512`** | **5,615.2** (11.40 ns) | **2,291.8** (27.93 ns) | 512b / 1024b key, 0 B RAM RK (2^256 PRP) |
| **`EM2Encrypt256`** | **2,348.6** (13.64 ns) | **994.4** (32.18 ns) | 256b / 512b key, 0 B RAM RK (2^170.7 BBB PRP) |
| **`EM2Encrypt512`** | **2,419.0** (26.46 ns) | **1,049.9** (60.96 ns) | 512b / 1024b key, 0 B RAM RK (2^341.3 BBB PRP) |
| **`TEMEncrypt256`** | **2,341.2** (13.68 ns) | **975.5** (32.81 ns) | 256b / 512b + 256b tweak, 0 B RAM RK (2^128 TPRP) |
| **`TEMDecrypt256`** | **2,213.9** (14.46 ns) | **936.2** (34.18 ns) | 256b / 512b + 256b tweak, 0 B RAM RK (2^128 TPRP) |
| **`TEMEncrypt512`** | **2,317.4** (27.63 ns) | **1,033.5** (61.93 ns) | 512b / 1024b + 512b tweak, 0 B RAM RK (2^256 TPRP) |
| **`TEM2Encrypt256`** | **1,187.8** (26.95 ns) | **451.1** (70.93 ns) | 256b / 512b + 256b tweak, 0 B RAM RK (2^170.7 BBB TPRP) |
| **`TEM2Encrypt512`** | **1,341.3** (47.72 ns) | **644.1** (99.36 ns) | 512b / 1024b + 512b tweak, 0 B RAM RK (2^341.3 BBB TPRP) |
| **`EMEncrypt256x4`** | **12,789.7** (2.51 ns/blk) | **3,743.4** (8.55 ns/blk) | 4×256b, 0 B RAM RK (2^128 PRP) |
| **`EMDecrypt256x4`** | **10,932.6** (2.93 ns/blk) | **4,397.9** (7.28 ns/blk) | 4×256b, 0 B RAM RK (2^128 PRP) |
| **`EMEncrypt512x4`** | **12,409.3** (5.16 ns/blk) | **4,384.3** (14.60 ns/blk) | 4×512b, 0 B RAM RK (2^256 PRP) |
| **`EM2Encrypt256x4`** | **6,513.2** (4.92 ns/blk) | **1,990.0** (16.08 ns/blk) | 4×256b, 0 B RAM RK (2^170.7 BBB PRP) |
| **`EM2Encrypt512x4`** | **5,838.2** (10.97 ns/blk) | **2,381.6** (26.88 ns/blk) | 4×512b, 0 B RAM RK (2^341.3 BBB PRP) |
| **`TEMEncrypt256x4`** | **6,282.9** (5.10 ns/blk) | **2,027.9** (15.78 ns/blk) | 4×256b + tweaks, 0 B RAM RK (2^128 TPRP) |
| **`TEMDecrypt256x4`** | **5,944.5** (5.39 ns/blk) | **2,189.1** (14.62 ns/blk) | 4×256b + tweaks, 0 B RAM RK (2^128 TPRP) |
| **`TEMEncrypt512x4`** | **5,788.9** (11.06 ns/blk) | **1,709.3** (37.45 ns/blk) | 4×512b + tweaks, 0 B RAM RK (2^256 TPRP) |
| **`TEM2Encrypt256x4`** | **3,250.3** (9.86 ns/blk) | **1,078.6** (29.68 ns/blk) | 4×256b + tweaks, 0 B RAM RK (2^170.7 BBB TPRP) |
| **`TEM2Encrypt512x4`** | **3,219.3** (19.88 ns/blk) | **885.2** (72.30 ns/blk) | 4×512b + tweaks, 0 B RAM RK (2^341.3 BBB TPRP) |
| **`Rijndael-256 (14r)`** | 2,182.3 (14.68 ns) | 1,405.3 (22.77 ns) | 256b / 256b key, **480 B RAM RK** (SP 800-197) |
| **`Rijndael-256x4 (14r)`** | 6,929.4 (4.62 ns/blk) | 2,717.9 (11.78 ns/blk) | 4×256b, **480 B RAM RK** (SP 800-197) |
| **`Vistrutah-256 (10r / 14r)`** | 4,831.2 / 3,489.6 (6.66 / 9.17 ns) | 3,635.5 / 2,482.3 (8.80 / 12.89 ns) | 256b / 256b key, 0 B RAM RK (ePrint 2025/976) |
| **`Vistrutah-256x4 (10r / 14r)`** | 11,948.8 / 8,263.1 (2.68 / 3.88 ns/blk) | 6,323.2 / 4,575.8 (5.06 / 6.99 ns/blk) | 4×256b, 0 B RAM RK (ePrint 2025/976) |
| **`Vistrutah-512-256 (10r / 14r / 18r)`** | 4,892.2 / 3,185.5 / 2,444.7 | 3,786.7 / 2,594.4 / 1,961.1 | 512b / 256b key, 0 B RAM RK (ePrint 2025/976) |
| **`Vistrutah-512-512 (12r / 18r)`** | 4,038.6 / 2,364.7 | 3,094.8 / 1,985.3 | 512b / 512b key, 0 B RAM RK (ePrint 2025/976) |
| **`Vistrutah-512-256x4 (10r / 14r / 18r)`** | 10,641.0 / 7,111.6 / 5,564.7 | 5,449.5 / 4,147.9 / 3,235.4 | 4×512b / 256b key, 0 B RAM RK (ePrint 2025/976) |
| **`Vistrutah-512-512x4 (12r / 18r)`** | 8,820.2 / 5,729.1 | 4,849.4 / 3,262.1 | 4×512b / 512b key, 0 B RAM RK (ePrint 2025/976) |
| **`Asura-Encrypt / Decrypt (12r, rtk)`** | 3,864.1 / 2,265.0 (8.28 / 14.13 ns) | 3,058.8 / 1,668.2 (10.46 / 19.18 ns) | 256b / 256b + 128b tweak, **416 B RAM RK** (INDOCRYPT 2024) |
| **`Asura-Encryptx4 / Decryptx4 (12r, rtk)`** | 11,091.8 / 7,203.7 (2.89 / 4.44 ns/blk) | 5,847.9 / 3,508.4 (5.47 / 9.12 ns/blk) | 4×256b + tweak, **416 B RAM RK** (INDOCRYPT 2024) |
| **`Asura-Encrypt / Decrypt-OTF (12r)`** | 1,121.2 / 574.8 (28.55 / 55.68 ns) | 793.8 / 337.9 (40.31 / 94.71 ns) | 256b / 256b + 128b tweak, 0 B RAM RK (INDOCRYPT 2024) |
| **`Asura-Encryptx4 / Decryptx4-OTF (12r)`** | 3,338.3 / 1,823.5 (9.60 / 17.55 ns/blk) | 2,420.0 / 1,136.2 (13.22 / 28.17 ns/blk) | 4×256b + shared tweak, 0 B RAM RK (INDOCRYPT 2024) |

On Intel Core i7-11700K, `EMEncrypt256` (`5,810.6 MB/s`, `5.51 ns/op`, `0.62 c/B`) and `EMEncrypt256x4` (`12,789.7 MB/s`, `10.04 ns/op`, `0.28 c/B`) outperform 14-round `Rijndael-256` (`2,182.3 MB/s` single-block, `6,929.4 MB/s` 4-block — `2.7×` and `1.8×` faster), 10r/14r `Vistrutah-256` (`4,831.2` / `3,489.6 MB/s` single-block, `11,948.8` / `8,263.1 MB/s` 4-block — `1.2×`/`1.7×` and `1.1×`/`1.5×` faster), and 12-round `ASURA` with pre-expanded tweakeys (`3,864.1 MB/s` single-block, `11,091.8 MB/s` 4-block — `1.5×` and `1.2×` faster), while `EMDecrypt256` (`4,400.4 MB/s`) and `EMDecrypt256x4` (`10,932.6 MB/s`) are `1.9×` and `1.5×` faster than `Asura-Decrypt` (`2,265.0 MB/s`) and `Asura-Decryptx4` (`7,203.7 MB/s`). In zero-RAM-state tweakable operation (where the tweak changes per block), `TEMEncrypt256` (`2,341.2 MB/s`) and `TEMDecrypt256` (`2,213.9 MB/s`) outperform `Asura-Encrypt-OTF` (`1,121.2 MB/s`, `2.1×`) and `Asura-Decrypt-OTF` (`574.8 MB/s`, `3.9×`) on Intel Core i7-11700K, and `TEMEncrypt256` (`975.5 MB/s`) and `TEMDecrypt256` (`936.2 MB/s`) outperform `Asura-Encrypt-OTF` (`793.8 MB/s`, `1.2×`) and `Asura-Decrypt-OTF` (`337.9 MB/s`, `2.8×`) on AWS Graviton 4 (`arm64`), where `EMDecrypt256` (`2,566.0 MB/s`) and `EMDecrypt256x4` (`4,397.9 MB/s`) also outperform pre-expanded `Asura-Decrypt` (`1,668.2 MB/s`, `1.5×`) and `Asura-Decryptx4` (`3,508.4 MB/s`, `1.3×`).

> **Benchmark methodology note:** `BenchmarkPermute*`, `BenchmarkInversePermute*`, `BenchmarkAES128Round*`, and `BenchmarkAES128Encrypt*` modify their state buffer in-place (`dst == src`), measuring serial dependency-chain latency across iterations (`AES128Encrypt*`, `Rijndael256Encrypt*`, and `Asura{Encrypt,Decrypt}*` time the cipher core with pre-expanded round keys/tweakeys in RAM, whereas `Areion-{EM,EM2,TEM,TEM2}*`, `Vistrutah*`, and `Asura*OTF*` take raw keys/tweaks and expand/apply round keys on-the-fly in registers). `BenchmarkSoEM*`, `BenchmarkDM*`, `BenchmarkEM*`, `BenchmarkEM2*`, `BenchmarkTEM*`, `BenchmarkTEM2*`, `BenchmarkRijndael256*`, `BenchmarkVistrutah*`, and `BenchmarkAsura*` evaluate fixed input, tweak, and key buffers across iterations (`out != in`), allowing out-of-order execution to overlap independent calls and measuring pipelined throughput. See [`analysis/README.md` (Section L)](analysis/README.md#l-register-and-stack-clearing-cost) for interleaved single-core cycle-per-byte measurements including epilogue register and stack clearing.

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

### 4. Verify Round Constant Derivation & ASURA KATs
```bash
python3 scripts/verify_p2_table.py
python3 scripts/verify_asura_kat.py
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

9. **Vistrutah: Extremely Fast 256 and 512-bit Block Ciphers Strategy for Modern CPUs**
   Roberto Avanzi, Subhadeep Banik, Orr Dunkelman, Shibam Ghosh, Marcel Nageler.
   *IACR Cryptology ePrint Archive*, Paper 2025/976 (2025), [IACR ePrint 2025/976](https://eprint.iacr.org/2025/976).

10. **ASURA: An Efficient Large-State Tweakable Block Cipher for ARM Environment**
    Atsushi Tanaka, Rentaro Shiba, Kosei Sakamoto, Mostafizar Rahman, Takuro Shiraya, Takanori Isobe.
    *Progress in Cryptology — INDOCRYPT 2024*, Lecture Notes in Computer Science, vol. 15495, pp. 143–164, Springer (2025), [doi:10.1007/978-3-031-80308-6_7](https://doi.org/10.1007/978-3-031-80308-6_7).

---

## License

Dual-licensed under either:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

Copyright (c) 2026 Andrey Kuvshinov.

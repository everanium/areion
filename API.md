## Public API Reference (`github.com/everanium/areion`)

Complete reference for all exported types, constants, and functions in package `areion` ([`areion.go`](areion.go), [`cpu.go`](cpu.go)).
For architectural details, security proofs, and benchmarks, see [`README.md`](README.md).
Companion C99 / C11 reference library: **[`everanium/areion-c`](https://github.com/everanium/areion-c)** ([`API.md`](https://github.com/everanium/areion-c/blob/main/API.md)).

---

## Table of Contents

1. [Types and Constants](#1-types-and-constants)
2. [Cryptographic Permutations (P1 and P2, Single-Block & 4-Way)](#2-cryptographic-permutations-p1-and-p2-single-block--4-way)
3. [Davies-Meyer Compression Functions](#3-davies-meyer-compression-functions)
4. [Sum of Even-Mansour (SoEM22) Pseudorandom Functions (PRFs)](#4-sum-of-even-mansour-soem22-pseudorandom-functions-prfs)
5. [Invertible Wide-Block Ciphers (EM, EM2, TEM, TEM2)](#5-invertible-wide-block-ciphers-em-em2-tem-tem2)
6. [Low-Level AES-128 & Round Primitives](#6-low-level-aes-128--round-primitives)
7. [Runtime Dispatch, Self-Test, and Memory Zeroization](#7-runtime-dispatch-self-test-and-memory-zeroization)

---

### 1. Types and Constants

Fixed-size byte-array type aliases for permutation states and AES blocks, together with integer tier codes returned by `TierCode()`.

#### State and Block Type Aliases

| Type Definition | Size | Description |
| :--- | :---: | :--- |
| `type State256 = [32]byte` | 32 B (256 bits) | 256-bit state for the Areion-256 permutations `P1_256` and `P2_256` |
| `type State512 = [64]byte` | 64 B (512 bits) | 512-bit state for the Areion-512 permutations `P1_512` and `P2_512` |
| `type Block = [16]byte` | 16 B (128 bits) | Single 128-bit AES block |
| `type Block4 = [64]byte` | 64 B (`4 × 128` bits) | Four 128-bit AES blocks packed contiguously (512-bit vector width) |
| `type Key4 = [64]byte` | 64 B (`4 × 128` bits) | Four 128-bit AES round keys for 4-way parallel round operations |

#### Hardware Acceleration Tier Constants

| Constant | Value | Tier Name (`Tier()`) | Required ISA Extensions |
| :--- | :---: | :---: | :--- |
| `TierPureGo` | `0` | `"purego"` | Portable constant-time 64-bit bitsliced software fallback (all architectures) |
| `TierAESNI` | `1` | `"aesni"` | `x86-64` legacy 2-operand SSE `AES-NI` (128-bit XMM) |
| `TierVEX` | `2` | `"vex"` | `x86-64` `AVX + AES-NI` 3-operand VEX-encoded XMM |
| `TierVAESAVX2` | `3` | `"vaesavx2"` | `x86-64` `AVX2 + VAES` (256-bit YMM Vector AES) |
| `TierAVX512` | `4` | `"avx512"` | `x86-64` `AVX-512F + AVX-512DQ + AVX-512BW + AVX-512VL + VAES` (512-bit ZMM Vector AES) |
| `TierARMCrypto` | `5` | `"arm64"` | `ARM64` `NEON + ARMv8 Cryptographic Extension` (`AESE` / `AESMC` / `AESD` / `AESIMC`) |

---

### 2. Cryptographic Permutations (P1 and P2, Single-Block & 4-Way)

In-place forward and inverse permutations over 256-bit (`State256`, 10 rounds) and 512-bit (`State512`, 15 rounds) states, plus 4-way parallel batch entry points (`*[4][32]byte` and `*[4][64]byte`).

#### Core Permutations (P1, Table 1 — Isobe et al., TCHES 2023)

| Function Signature | State Size | Rounds | Description |
| :--- | :---: | :---: | :--- |
| `Permute256(state *State256)` | 32 B | 10 | Forward permutation `P1_256` in place |
| `InversePermute256(state *State256)` | 32 B | 10 | Inverse permutation `P1_256⁻¹` in place |
| `Permute512(state *State512)` | 64 B | 15 | Forward permutation `P1_512` in place |
| `InversePermute512(state *State512)` | 64 B | 15 | Inverse permutation `P1_512⁻¹` in place |
| `Permute256x4(states *[4][32]byte)` | 4 × 32 B | 10 | 4-way parallel forward permutation `P1_256` in place |
| `InversePermute256x4(states *[4][32]byte)` | 4 × 32 B | 10 | 4-way parallel inverse permutation `P1_256⁻¹` in place |
| `Permute512x4(states *[4][64]byte)` | 4 × 64 B | 15 | 4-way parallel forward permutation `P1_512` in place |
| `InversePermute512x4(states *[4][64]byte)` | 4 × 64 B | 15 | 4-way parallel inverse permutation `P1_512⁻¹` in place |

#### Domain-Separated Second Permutations (P2, Table 2 — π words 15..29)

| Function Signature | State Size | Rounds | Description |
| :--- | :---: | :---: | :--- |
| `Permute256P2(state *State256)` | 32 B | 10 | Forward permutation `P2_256` in place (Table 2 round constants) |
| `InversePermute256P2(state *State256)` | 32 B | 10 | Inverse permutation `P2_256⁻¹` in place (Table 2 round constants) |
| `Permute512P2(state *State512)` | 64 B | 15 | Forward permutation `P2_512` in place (Table 2 round constants) |
| `InversePermute512P2(state *State512)` | 64 B | 15 | Inverse permutation `P2_512⁻¹` in place (Table 2 round constants) |
| `Permute256P2x4(states *[4][32]byte)` | 4 × 32 B | 10 | 4-way parallel forward permutation `P2_256` in place |
| `InversePermute256P2x4(states *[4][32]byte)` | 4 × 32 B | 10 | 4-way parallel inverse permutation `P2_256⁻¹` in place |
| `Permute512P2x4(states *[4][64]byte)` | 4 × 64 B | 15 | 4-way parallel forward permutation `P2_512` in place |
| `InversePermute512P2x4(states *[4][64]byte)` | 4 × 64 B | 15 | 4-way parallel inverse permutation `P2_512⁻¹` in place |

---

### 3. Davies-Meyer Compression Functions

Fixed-input short-message compression functions (`Areion256-DM` and `Areion512-DM`) as specified in Section 4.1.1, Eqs. (1)–(3) of Isobe et al. ([ePrint 2023/794](https://eprint.iacr.org/2023/794)).

| Function Signature | Input | Digest | Construction |
| :--- | :---: | :---: | :--- |
| `DM256(m *[32]byte) [32]byte` | 32 B | 32 B | `h = P1_256(m) ⊕ m` |
| `DM512(m *[64]byte) [32]byte` | 64 B | 32 B | 256-bit truncation of `P1_512(m) ⊕ m` keeping 32-bit words `x2 \|\| x3 \|\| x6 \|\| x7 \|\| x8 \|\| x9 \|\| x12 \|\| x13` |

---

### 4. Sum of Even-Mansour (SoEM22) Pseudorandom Functions (PRFs)

Beyond-birthday-bound pseudorandom functions (secure up to `2^(2n/3)` queries) over `(P1, P2)` with a `2n`-bit key `K = K1 || K2` ([Chen, Lambooij, and Mennink, CRYPTO 2019](https://eprint.iacr.org/2019/554)). Single-block calls interleave `P1` and `P2` in a single fused assembly invocation.

| Function Signature | Input | Key (`K1 \|\| K2`) | Output | Construction |
| :--- | :---: | :---: | :---: | :--- |
| `SoEM256(key *[64]byte, m *[32]byte) [32]byte` | 32 B | 64 B | 32 B | `P1_256(m ⊕ K1) ⊕ P2_256(m ⊕ K2) ⊕ K1 ⊕ K2` |
| `SoEM512(key *[128]byte, m *[64]byte) [64]byte` | 64 B | 128 B | 64 B | `P1_512(m ⊕ K1) ⊕ P2_512(m ⊕ K2) ⊕ K1 ⊕ K2` |
| `SoEM256x4(keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte` | 4 × 32 B | 4 × 64 B | 4 × 32 B | 4-way parallel `SoEM256` over 4 independent `(key, input)` pairs |
| `SoEM512x4(keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte` | 4 × 64 B | 4 × 128 B | 4 × 64 B | 4-way parallel `SoEM512` over 4 independent `(key, input)` pairs |

---

### 5. Invertible Wide-Block Ciphers (EM, EM2, TEM, TEM2)

Four families of invertible 256-bit (32-byte block, 64-byte key `K = K1 || K2`) and 512-bit (64-byte block, 128-byte key `K = K1 || K2`) wide-block ciphers and tweakable wide-block ciphers.

#### 5.1 1-Round Even-Mansour (1-EM, Birthday-Bound Strong PRP)

| Function Signature | Block | Key (`K1 \|\| K2`) | Construction |
| :--- | :---: | :---: | :--- |
| `EMEncrypt256(key *[64]byte, m *[32]byte) (out [32]byte)` | 32 B | 64 B | `C = P1_256(M ⊕ K1) ⊕ K2` |
| `EMDecrypt256(key *[64]byte, c *[32]byte) (out [32]byte)` | 32 B | 64 B | `M = P1_256⁻¹(C ⊕ K2) ⊕ K1` |
| `EMEncrypt512(key *[128]byte, m *[64]byte) (out [64]byte)` | 64 B | 128 B | `C = P1_512(M ⊕ K1) ⊕ K2` |
| `EMDecrypt512(key *[128]byte, c *[64]byte) (out [64]byte)` | 64 B | 128 B | `M = P1_512⁻¹(C ⊕ K2) ⊕ K1` |
| `EMEncrypt256x4(keys *[4][64]byte, msgs *[4][32]byte) (out [4][32]byte)` | 4 × 32 B | 4 × 64 B | 4-way parallel `EMEncrypt256` |
| `EMDecrypt256x4(keys *[4][64]byte, ct *[4][32]byte) (out [4][32]byte)` | 4 × 32 B | 4 × 64 B | 4-way parallel `EMDecrypt256` |
| `EMEncrypt512x4(keys *[4][128]byte, msgs *[4][64]byte) (out [4][64]byte)` | 4 × 64 B | 4 × 128 B | 4-way parallel `EMEncrypt512` |
| `EMDecrypt512x4(keys *[4][128]byte, ct *[4][64]byte) (out [4][64]byte)` | 4 × 64 B | 4 × 128 B | 4-way parallel `EMDecrypt512` |

#### 5.2 2-Round Independent-Permutation Even-Mansour (2-EM, Beyond-Birthday-Bound Strong PRP)

| Function Signature | Block | Key (`K1 \|\| K2`) | Construction |
| :--- | :---: | :---: | :--- |
| `EM2Encrypt256(key *[64]byte, m *[32]byte) (out [32]byte)` | 32 B | 64 B | `C = P2_256(P1_256(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2` |
| `EM2Decrypt256(key *[64]byte, c *[32]byte) (out [32]byte)` | 32 B | 64 B | `M = P1_256⁻¹(P2_256⁻¹(C ⊕ K1 ⊕ K2) ⊕ K2) ⊕ K1` |
| `EM2Encrypt512(key *[128]byte, m *[64]byte) (out [64]byte)` | 64 B | 128 B | `C = P2_512(P1_512(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2` |
| `EM2Decrypt512(key *[128]byte, c *[64]byte) (out [64]byte)` | 64 B | 128 B | `M = P1_512⁻¹(P2_512⁻¹(C ⊕ K1 ⊕ K2) ⊕ K2) ⊕ K1` |
| `EM2Encrypt256x4(keys *[4][64]byte, msgs *[4][32]byte) (out [4][32]byte)` | 4 × 32 B | 4 × 64 B | 4-way parallel `EM2Encrypt256` |
| `EM2Decrypt256x4(keys *[4][64]byte, ct *[4][32]byte) (out [4][32]byte)` | 4 × 32 B | 4 × 64 B | 4-way parallel `EM2Decrypt256` |
| `EM2Encrypt512x4(keys *[4][128]byte, msgs *[4][64]byte) (out [4][64]byte)` | 4 × 64 B | 4 × 128 B | 4-way parallel `EM2Encrypt512` |
| `EM2Decrypt512x4(keys *[4][128]byte, ct *[4][64]byte) (out [4][64]byte)` | 4 × 64 B | 4 × 128 B | 4-way parallel `EM2Decrypt512` |

#### 5.3 1-Round Tweakable Even-Mansour (1-TEM, Birthday-Bound Strong TPRP)

| Function Signature | Block | Key (`K1 \|\| K2`) | Tweak (`T`) | Construction |
| :--- | :---: | :---: | :---: | :--- |
| `TEMEncrypt256(key *[64]byte, tweak *[32]byte, m *[32]byte) (out [32]byte)` | 32 B | 64 B | 32 B | `W = P2_256(T ⊕ K2) ⊕ K1`, `C = P1_256(M ⊕ W) ⊕ W` |
| `TEMDecrypt256(key *[64]byte, tweak *[32]byte, c *[32]byte) (out [32]byte)` | 32 B | 64 B | 32 B | `W = P2_256(T ⊕ K2) ⊕ K1`, `M = P1_256⁻¹(C ⊕ W) ⊕ W` |
| `TEMEncrypt512(key *[128]byte, tweak *[64]byte, m *[64]byte) (out [64]byte)` | 64 B | 128 B | 64 B | `W = P2_512(T ⊕ K2) ⊕ K1`, `C = P1_512(M ⊕ W) ⊕ W` |
| `TEMDecrypt512(key *[128]byte, tweak *[64]byte, c *[64]byte) (out [64]byte)` | 64 B | 128 B | 64 B | `W = P2_512(T ⊕ K2) ⊕ K1`, `M = P1_512⁻¹(C ⊕ W) ⊕ W` |
| `TEMEncrypt256x4(keys *[4][64]byte, tweaks *[4][32]byte, msgs *[4][32]byte) (out [4][32]byte)` | 4 × 32 B | 4 × 64 B | 4 × 32 B | 4-way parallel `TEMEncrypt256` |
| `TEMDecrypt256x4(keys *[4][64]byte, tweaks *[4][32]byte, ct *[4][32]byte) (out [4][32]byte)` | 4 × 32 B | 4 × 64 B | 4 × 32 B | 4-way parallel `TEMDecrypt256` |
| `TEMEncrypt512x4(keys *[4][128]byte, tweaks *[4][64]byte, msgs *[4][64]byte) (out [4][64]byte)` | 4 × 64 B | 4 × 128 B | 4 × 64 B | 4-way parallel `TEMEncrypt512` |
| `TEMDecrypt512x4(keys *[4][128]byte, tweaks *[4][64]byte, ct *[4][64]byte) (out [4][64]byte)` | 4 × 64 B | 4 × 128 B | 4 × 64 B | 4-way parallel `TEMDecrypt512` |

#### 5.4 2-Round BBB Tweakable Even-Mansour (2-TEM, Beyond-Birthday-Bound Strong TPRP)

With per-tweak masks `W1 = P1(T ⊕ K1) ⊕ K1` and `W2 = P2(T ⊕ K2) ⊕ K2`:

| Function Signature | Block | Key (`K1 \|\| K2`) | Tweak (`T`) | Construction |
| :--- | :---: | :---: | :---: | :--- |
| `TEM2Encrypt256(key *[64]byte, tweak *[32]byte, m *[32]byte) (out [32]byte)` | 32 B | 64 B | 32 B | `C = P2_256(P1_256(M ⊕ W1) ⊕ W2) ⊕ W1 ⊕ W2` |
| `TEM2Decrypt256(key *[64]byte, tweak *[32]byte, c *[32]byte) (out [32]byte)` | 32 B | 64 B | 32 B | `M = P1_256⁻¹(P2_256⁻¹(C ⊕ W1 ⊕ W2) ⊕ W2) ⊕ W1` |
| `TEM2Encrypt512(key *[128]byte, tweak *[64]byte, m *[64]byte) (out [64]byte)` | 64 B | 128 B | 64 B | `C = P2_512(P1_512(M ⊕ W1) ⊕ W2) ⊕ W1 ⊕ W2` |
| `TEM2Decrypt512(key *[128]byte, tweak *[64]byte, c *[64]byte) (out [64]byte)` | 64 B | 128 B | 64 B | `M = P1_512⁻¹(P2_512⁻¹(C ⊕ W1 ⊕ W2) ⊕ W2) ⊕ W1` |
| `TEM2Encrypt256x4(keys *[4][64]byte, tweaks *[4][32]byte, msgs *[4][32]byte) (out [4][32]byte)` | 4 × 32 B | 4 × 64 B | 4 × 32 B | 4-way parallel `TEM2Encrypt256` |
| `TEM2Decrypt256x4(keys *[4][64]byte, tweaks *[4][32]byte, ct *[4][32]byte) (out [4][32]byte)` | 4 × 32 B | 4 × 64 B | 4 × 32 B | 4-way parallel `TEM2Decrypt256` |
| `TEM2Encrypt512x4(keys *[4][128]byte, tweaks *[4][64]byte, msgs *[4][64]byte) (out [4][64]byte)` | 4 × 64 B | 4 × 128 B | 4 × 64 B | 4-way parallel `TEM2Encrypt512` |
| `TEM2Decrypt512x4(keys *[4][128]byte, tweaks *[4][64]byte, ct *[4][64]byte) (out [4][64]byte)` | 4 × 64 B | 4 × 128 B | 4 × 64 B | 4-way parallel `TEM2Decrypt512` |

---

### 6. Low-Level AES-128 & Round Primitives

Building blocks for custom AES-based constructions, exposed in both hardware-dispatched and pure-Go bitsliced forms.

| Function Signature | Block Width | Description |
| :--- | :---: | :--- |
| `AES128Round(block, roundKey *Block)` | 16 B | Hardware-dispatched single-block AES round (`SubBytes` → `ShiftRows` → `MixColumns` → `AddRoundKey`) |
| `RoundHW(block, roundKey *Block)` | 16 B | Alias for `AES128Round` |
| `Round(block, roundKey *Block)` | 16 B | Constant-time bitsliced pure-Go software single-block AES round |
| `AES128FinalRound(block, roundKey *Block)` | 16 B | Hardware-dispatched single-block AES final round (`SubBytes` → `ShiftRows` → `AddRoundKey`, no `MixColumns`) |
| `FinalRoundHW(block, roundKey *Block)` | 16 B | Alias for `AES128FinalRound` |
| `FinalRound(block, roundKey *Block)` | 16 B | Constant-time bitsliced pure-Go software single-block AES final round |
| `AES128Round4(blocks, roundKeys *Block4)` | 4 × 16 B | Hardware-dispatched 4-block parallel AES encryption round |
| `Round4HW(blocks, roundKeys *Block4)` | 4 × 16 B | Alias for `AES128Round4` |
| `AES128FinalRound4(blocks, roundKeys *Block4)` | 4 × 16 B | Hardware-dispatched 4-block parallel AES final round (no `MixColumns`) |
| `FinalRound4HW(blocks, roundKeys *Block4)` | 4 × 16 B | Alias for `AES128FinalRound4` |
| `XorBlock(dst, a, b *Block)` | 16 B | Sets `*dst = *a ^ *b` on 16-byte blocks |
| `XorBlock4(dst, a, b *Block4)` | 64 B | Sets `*dst = *a ^ *b` on 64-byte (4-block) vectors |
| `ExpandKey128(key *[16]byte, rk *[11][16]byte)` | 16 B → 11 × 16 B | Expands a 16-byte AES-128 key into 11 round keys (FIPS 197 §5.2) |
| `AES128EncryptBlock(rk *[11][16]byte, dst, src *[16]byte)` | 16 B | Full 10-round AES-128 single-block encryption (`dst` and `src` may alias) |
| `AES128Encrypt4Blocks(rk *[11][16]byte, dst, src *[64]byte)` | 4 × 16 B | Full 10-round AES-128 4-block parallel encryption under shared `rk` (`dst` and `src` may alias) |

---

### 7. Runtime Dispatch, Self-Test, and Memory Zeroization

Runtime CPU tier introspection/override, FIPS 140-3 Known-Answer Self-Test (CAST), and DSE-resistant buffer scrubbing.

| Function Signature | Return Type | Description |
| :--- | :---: | :--- |
| `Tier() string` | `string` | Active dispatch tier name: `"avx512"`, `"vaesavx2"`, `"vex"`, `"aesni"`, `"arm64"`, or `"purego"` |
| `TierCode() int32` | `int32` | Active dispatch tier constant (`TierPureGo`..`TierARMCrypto`) |
| `SetTier(tier string) error` | `error` | Overrides the active tier (`"auto"`, `"avx512"`, `"vaesavx2"`, `"vex"`, `"aesni"`, `"arm64"`, `"purego"`, plus aliases `"neon"`/`"sve"`/`"sve2"` and `"purec"`/`"scalar"`/`"gpr"`); also configurable at startup via `AREION_FORCE_TIER` |
| `UseHardwareAcceleration() bool` | `bool` | Reports whether hardware AES acceleration is available and currently enabled (`TierCode() != TierPureGo`) |
| `SelfTest() error` | `error` | FIPS 140-3 Power-On Known-Answer Self-Test (CAST) across all primitives on the active tier |
| `Zeroize(b []byte)` | — | Overwrites `b` with zeros and prevents dead-store elimination via `clear(b); runtime.KeepAlive(b)` |

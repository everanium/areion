## Areion Auxiliary Scripts

This directory contains standalone cryptanalytic and verification tooling for the Areion permutation family and the SoEM22 construction.

## Tools

### `verify_p2_table.py`

Python 3 verification script for the Areion-SoEM22 round constants. Standard library only.

#### Purpose
The Sum of Even-Mansour (SoEM22) construction (Chen, Lambooij, Mennink, CRYPTO 2019), as well as the `EM2`, `TEM`, and `TEM2` wide-block ciphers, requires two independent permutations `P1` and `P2`:

```text
F(k1, k2, m) = P1(m ⊕ k1) ⊕ P2(m ⊕ k2) ⊕ k1 ⊕ k2
```

`P1` uses the published Areion round constants (Isobe et al., TCHES 2023; Table 1 and Appendix A.1 of the extended version, ePrint 2023/794): the first 15 128-bit words of the fractional part of π (words 0..14), with RC7 kept as published (`0x801f2e2858efc16636920d871574e690`, a one-nibble shift from π word 7). `P2` is the Areion permutation under a second table, the subsequent 15 consecutive 128-bit words of π (words 15..29), with RC7 (`0x0f6d6ff383f442392e0b4482a4842004`, π word 22) taking the same one-nibble shift as RC7 of `P1`: `0xf6d6ff383f442392e0b4482a48420040`. Words 7 and 22 are the only words among 0..29 that begin with a zero nibble. Table 2 is proposed by Andrey Kuvshinov; this script derives and checks it.

The SoEM22 security bound is proven for two independent random permutations. The checks below are structural properties of the constants; treating the two Areion instances as independent permutations remains an assumption about the instantiation.

`verify_p2_table.py` computes and reports:
1. **Arbitrary-precision derivation**: Computes hexadecimal digits of π directly from Machin's formula `π/4 = 4·arctan(1/5) - arctan(1/239)` using pure integer arithmetic (zero external dependencies).
2. **Byte-level layout**: Confirms byte alignment matching Areion's C reference implementation (`_mm_setr_epi32`).
3. **RC7 shift**: Confirms that RC7 of both tables is the π word shifted by one nibble, and that words 7 and 22 are the only words among 0..29 that begin with a zero nibble.
4. **Distinctness**: Validates that all 15 constants in Table 2 are pairwise distinct and disjoint from Table 1.
5. **Weight distributions**: Reports Hamming-weight statistics against the binomial distribution `B(128, 0.5)`.
6. **Linear independence and difference space**: Verifies that the `15 × 128` matrices of Table 1, Table 2, and `Δ_r = RC1[r] ⊕ RC2[r]` have rank 15 and the combined `30 × 128` matrix has full rank 30 over `GF(2)`.
7. **Cross-table distinctness**: Evaluates all `15 × 15 = 225` cross-permutation differences `Δ(i,j) = RC1[i] ⊕ RC2[j]`, confirming no identical pairs (min Hamming distance 50).
8. **AES column symmetry**: Confirms zero 32-bit column duplicates in Table 2.
9. **Library constant verification**: Parses `constants.go` and verifies that its literal arrays match the derived Table 1 and Table 2 bit-for-bit.
10. **C table emission**: Emits ready-to-use C declarations.

#### Usage

```bash
python3 scripts/verify_p2_table.py
```

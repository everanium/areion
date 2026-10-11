# Areion Auxiliary Scripts

This directory contains standalone cryptanalytic and verification tooling for the Areion permutation family and the SoEM22 construction.

## Tools

### `verify_p2_table.py`

Python 3 verification script for the Areion-SoEM22 round constants. Standard library only.

#### Purpose
The Sum of Even-Mansour (SoEM22) construction (Chen, Lambooij, Mennink, CRYPTO 2019) requires two independent permutations $P_1$ and $P_2$:
$$F(k_1, k_2, m) = P_1(m \oplus k_1) \oplus P_2(m \oplus k_2) \oplus k_1 \oplus k_2$$

$P_1$ uses the published Areion round constants (Isobe et al., TCHES 2023; Table 1 and Appendix A.1 of the extended version, ePrint 2023/794): the first 15 128-bit words of the fractional part of $\pi$ (words 0..14), with RC7 kept as published (`0x801f2e2858efc16636920d871574e690`, a one-nibble shift from $\pi$ word 7). $P_2$ is the Areion permutation under a second table, the subsequent 15 consecutive 128-bit words of $\pi$ (words 15..29). Table 2 is proposed by Andrey Kuvshinov; this script derives and checks it.

The SoEM22 security bound is proven for two independent random permutations. The checks below are structural properties of the constants; treating the two Areion instances as independent permutations remains an assumption about the instantiation.

`verify_p2_table.py` computes and reports:
1. **Arbitrary-precision derivation**: Computes hexadecimal digits of $\pi$ directly from Machin's formula ($\pi/4 = 4 \arctan(1/5) - \arctan(1/239)$) using pure integer arithmetic (zero external dependencies).
2. **Byte-level layout**: Confirms byte alignment matching Areion's C reference implementation (`_mm_setr_epi32`).
3. **Distinctness**: Validates that all 15 constants in Table 2 are pairwise distinct and disjoint from Table 1.
4. **Weight distributions**: Reports Hamming-weight statistics (vs $B(128, 0.5)$).
5. **Linear independence**: Verifies that the combined $30 \times 128$ matrix of Table 1 and Table 2 has full rank 30 over $\mathrm{GF}(2)$.
6. **Cross-table distinctness**: Evaluates all $15 \times 15 = 225$ cross-permutation differences $\Delta_{i,j} = \mathrm{RC}_1[i] \oplus \mathrm{RC}_2[j]$, confirming no identical pairs (min Hamming distance 51).
7. **AES column symmetry**: Confirms zero 32-bit column duplicates in Table 2.
8. **C table emission**: Emits ready-to-use C declarations.

#### Usage

```bash
python3 scripts/verify_p2_table.py
```

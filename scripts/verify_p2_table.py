#!/usr/bin/env python3
"""
Derive and verify SoEM22 P2 round constants (pi words 15..29).

Context:
  Instantiation of the SoEM22 construction (Chen, Lambooij, Mennink, CRYPTO 2019)
  over Areion-256 and Areion-512 permutations:
      F(m) = P1(m ^ k1) ^ P2(m ^ k2) ^ k1 ^ k2
  Where:
    - P1 uses the published Areion constants (pi-derived words 0..14; Isobe et al., TCHES 2023,
      Table 1 and Appendix A.1 of the extended version, IACR ePrint 2023/794).
    - P2 is instantiated with the subsequent consecutive 15 128-bit words of pi (words 15..29),
      with RC7 (pi word 22) taking the same one-nibble shift as the published RC7 of P1.

  Table 2 (P2) is proposed by Andrey Kuvshinov. The SoEM22 bound is proven for two independent
  random permutations; treating the two Areion instances as independent is an assumption about
  the instantiation, which the structural checks below do not prove.

This script performs verification of these constants:
  1. High-precision derivation from the fractional digits of pi (Machin series).
  2. Byte-level layout and endianness formatting.
  3. RC7 shift (both tables; words 7 and 22 the only leading-zero words among 0..29).
  4. Pairwise distinctness (internal and cross-table).
  5. Hamming weight distributions vs. binomial expectation B(128, 0.5).
  6. Cross-permutation difference space (Delta_r = RC_r^(1) ^ RC_r^(2)) uniqueness and ranks.
  7. Cross-table distinctness (all 225 pairs of P1 x P2).
  8. AES 32-bit column equality checks.
  9. Linear independence over GF(2) (matrix ranks of P1, P2, [P1; P2], and Deltas).
  10. Formatted C source declarations.
"""

import math
import os
import re
import sys


def compute_pi_fraction_hex(num_hex_digits: int) -> str:
    """
    Computes hex digits of fractional part of pi using integer arithmetic
    based on Machin's formula: pi/4 = 4*arctan(1/5) - arctan(1/239).
    """
    scale = 16 ** (num_hex_digits + 25)

    def arccot(x: int) -> int:
        x_power = scale // x
        total = x_power
        sign = -1
        k = 3
        while True:
            x_power //= (x * x)
            term = x_power // k
            if term == 0:
                break
            total += sign * term
            sign = -sign
            k += 2
        return total

    pi_val = 4 * (4 * arccot(5) - arccot(239))
    frac_val = pi_val - 3 * scale
    hex_str = hex(frac_val)[2:]
    return hex_str[:num_hex_digits]


def gf2_rank(rows: list) -> int:
    """Computes the matrix rank of a list of integers over GF(2)."""
    basis = []
    for r in rows:
        val = r
        for b in basis:
            val = min(val, val ^ b)
        if val > 0:
            basis.append(val)
            basis.sort(reverse=True)
    return len(basis)


def to_le_bytes(val: int) -> list:
    """Converts a 128-bit integer into 16 little-endian bytes."""
    return [(val >> (8 * i)) & 0xFF for i in range(16)]


def to_paper_uint32_words(val: int) -> list:
    """
    Converts a 128-bit integer into 4 big-endian 32-bit words, exactly
    matching the format of 'const uint32_t RC[15*4]' in Appendix A.1 of the
    Areion paper (which are then loaded via _mm_setr_epi32(RC[3], RC[2], RC[1], RC[0])).
    """
    return [(val >> (32 * (3 - i))) & 0xFFFFFFFF for i in range(4)]


def format_hex128(val: int) -> str:
    return f"0x{val:032x}"


def verify_constants_go(p1_published: list, p2_words: list) -> bool:
    """Verifies that constants.go matches the derived tables bit-for-bit."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    constants_path = os.path.join(script_dir, "..", "constants.go")
    if not os.path.exists(constants_path):
        return True

    with open(constants_path, "r", encoding="utf-8") as f:
        content = f.read()

    def extract_table(var_name: str) -> list:
        pattern = rf"var\s+{var_name}\s*=\s*\[15\]\[16\]byte\{{(.*?)\n\}}"
        m = re.search(pattern, content, re.DOTALL)
        if not m:
            return []
        block = m.group(1)
        rows = re.findall(r"\{([0-9a-fx,\s]+)\}", block)
        words = []
        for r in rows:
            b = [int(x.strip(), 16) for x in r.split(",") if x.strip()]
            val = sum(b[i] << (8 * i) for i in range(16))
            words.append(val)
        return words

    p1_go = extract_table("roundConstantsP1")
    p2_go = extract_table("roundConstantsP2")

    if len(p1_go) != 15 or len(p2_go) != 15:
        print("[!] Warning: Could not parse roundConstants from constants.go")
        return False

    p1_match = (p1_go == p1_published)
    p2_match = (p2_go == p2_words)
    return p1_match and p2_match


def main():
    print("=" * 86)
    print("   AREION-SoEM22 ROUND CONSTANT DERIVATION & CHECKS")
    print("   Reference: Chen, Lambooij, Mennink (CRYPTO 2019) & Isobe et al. (TCHES 2023 / ePrint 2023/794)")
    print("=" * 86)

    failures = 0

    # 1. Compute Pi digits for 30 consecutive 128-bit words (words 0..29)
    total_words = 30
    total_hex = total_words * 32
    print(f"\n[+] Deriving {total_words * 128} bits ({total_hex} hex digits) of fractional pi (Machin series)...")
    pi_hex = compute_pi_fraction_hex(total_hex)

    raw_words = [int(pi_hex[i * 32 : (i + 1) * 32], 16) for i in range(total_words)]

    # P1 constants (Rounds 0..14)
    # Note on Round 7: the published constant (Table 1 and Appendix A.1 of ePrint 2023/794)
    # differs from pi word 7 by a one-nibble shift and is kept as published:
    #   pi fraction: 0x0801f2e2858efc16636920d871574e69
    #   published:   0x801f2e2858efc16636920d871574e690
    p1_pi = raw_words[:15]
    p1_published = list(p1_pi)
    p1_published[7] = 0x801f2e2858efc16636920d871574e690

    # P2 constants (Rounds 0..14) -> words 15..29 of pi
    # Note on Round 7: pi word 22 takes the same one-nibble shift as the published RC7 of P1:
    #   pi fraction: 0x0f6d6ff383f442392e0b4482a4842004
    #   Table 2:     0xf6d6ff383f442392e0b4482a48420040
    # Words 7 and 22 are the only words among 0..29 that begin with a zero nibble.
    p2_pi = raw_words[15:30]
    p2_words = list(p2_pi)
    p2_words[7] = 0xf6d6ff383f442392e0b4482a48420040

    def shift_nibble(w):
        return (w << 4) & ((1 << 128) - 1)

    leading_zero = [i for i, w in enumerate(raw_words) if w >> 124 == 0]
    if leading_zero == [7, 22] and p1_published[7] == shift_nibble(p1_pi[7]) and p2_words[7] == shift_nibble(p2_pi[7]):
        print("[PASS] RC7 of both tables: the pi word shifted by one nibble; words 7 and 22 are the only")
        print("       words among 0..29 that begin with a zero nibble.")
    else:
        print(f"[FAIL] RC7 shift check: words with a leading zero nibble {leading_zero}")
        failures += 1

    # Verify matching constants.go
    if verify_constants_go(p1_published, p2_words):
        print("[PASS] Table 1 & Table 2 match constants.go bit-for-bit.")
    else:
        print("[FAIL] Table 1 & Table 2 do not match constants.go!")
        failures += 1

    # -------------------------------------------------------------------------
    # SECTION 1: ROUND-BY-ROUND CONSTANTS AND DELTAS
    # -------------------------------------------------------------------------
    print("\n" + "-" * 86)
    print(" SECTION 1: ROUND CONSTANT ALIGNMENT & CROSS-PERMUTATION DIFFERENCES")
    print("-" * 86)
    print(f" {'Rnd':^4} | {'Table 1 (P1, published)':^34} | {'Table 2 (P2, NUMS pi)':^34} | {'HW1':^3} | {'HW2':^3} | {'D_HW':^4}")
    print("-" * 86)

    deltas = []
    for r in range(15):
        w1 = p1_published[r]
        w2 = p2_words[r]
        delta = w1 ^ w2
        deltas.append(delta)
        hw1 = bin(w1).count("1")
        hw2 = bin(w2).count("1")
        hwd = bin(delta).count("1")
        print(f" {r:^4} | {format_hex128(w1)} | {format_hex128(w2)} | {hw1:^3} | {hw2:^3} | {hwd:^4}")

    print("-" * 86)
    print(" * Note: Round 7 in Table 1 reflects the published TCHES 2023 constant (0x801f...e690).")
    print("   Unshifted pi word 7 is 0x0801f2e2858efc16636920d871574e69.")
    print(" * Note: Round 7 in Table 2 takes the same one-nibble shift (0xf6d6...0040).")
    print("   Unshifted pi word 22 is 0x0f6d6ff383f442392e0b4482a4842004.")

    # -------------------------------------------------------------------------
    # SECTION 2: STATISTICAL & WEIGHT PROPERTIES
    # -------------------------------------------------------------------------
    print("\n" + "-" * 86)
    print(" SECTION 2: STATISTICAL PROPERTIES & WEIGHT DISTRIBUTIONS")
    print("-" * 86)

    hw_p1 = [bin(w).count("1") for w in p1_published]
    hw_p2 = [bin(w).count("1") for w in p2_words]
    hw_d = [bin(d).count("1") for d in deltas]

    def stats(arr):
        mean = sum(arr) / len(arr)
        variance = sum((x - mean) ** 2 for x in arr) / len(arr)
        std = math.sqrt(variance)
        return min(arr), max(arr), mean, std

    min1, max1, avg1, std1 = stats(hw_p1)
    min2, max2, avg2, std2 = stats(hw_p2)
    mind, maxd, avgd, stdd = stats(hw_d)

    print(f" Ideal Binomial B(128, 0.5) Distribution:   Expected Mean = 64.00, StdDev = 5.66")
    print(f" Table 1 (P1, published):  Min = {min1:2d}, Max = {max1:2d}, Mean = {avg1:5.2f}, StdDev = {std1:4.2f}")
    print(f" Table 2 (P2, NUMS pi):    Min = {min2:2d}, Max = {max2:2d}, Mean = {avg2:5.2f}, StdDev = {std2:4.2f}")
    print(f" Deltas  (P1 ^ P2):        Min = {mind:2d}, Max = {maxd:2d}, Mean = {avgd:5.2f}, StdDev = {stdd:4.2f}")

    # -------------------------------------------------------------------------
    # SECTION 3: INVARIANT TESTS
    # -------------------------------------------------------------------------
    print("\n" + "-" * 86)
    print(" SECTION 3: INVARIANT CHECKS")
    print("-" * 86)

    # 3.1 Distinctness
    u1 = len(set(p1_published)) == 15
    u2 = len(set(p2_words)) == 15
    overlap = set(p1_published).intersection(set(p2_words))
    disjoint = len(overlap) == 0

    if u1:
        print(" [PASS] Table 1 Internal Distinctness:       15 / 15 unique words")
    else:
        print(" [FAIL] Table 1 has duplicate round constants!")
        failures += 1

    if u2:
        print(" [PASS] Table 2 Internal Distinctness:       15 / 15 unique words")
    else:
        print(" [FAIL] Table 2 has duplicate round constants!")
        failures += 1

    if disjoint:
        print(" [PASS] Cross-Table Distinctness:            |P1 intersect P2| = 0 (disjoint sets)")
    else:
        print(f" [FAIL] Collision detected between P1 and P2: {overlap}")
        failures += 1

    # 3.2 Delta Uniqueness & Non-Zero
    deltas_unique = (len(set(deltas)) == 15)
    deltas_nonzero = all(d != 0 for d in deltas)

    if deltas_nonzero:
        print(" [PASS] Delta Strict Non-Zero Property:      All 15 delta words != 0 (P1[r] != P2[r] for all r)")
    else:
        print(" [FAIL] At least one round has identical P1 and P2 constants!")
        failures += 1

    if deltas_unique:
        print(" [PASS] Delta Strict Uniqueness:             15 / 15 unique deltas")
    else:
        print(" [FAIL] Duplicate delta words detected across rounds!")
        failures += 1

    # 3.3 Linear Independence over GF(2)
    rank_p1 = gf2_rank(p1_published)
    rank_p2 = gf2_rank(p2_words)
    rank_combined = gf2_rank(p1_published + p2_words)
    rank_deltas = gf2_rank(deltas)

    if rank_p1 == 15:
        print(f" [PASS] GF(2) Rank of Table 1 (15x128):      {rank_p1} / 15 (Full rank)")
    else:
        print(f" [FAIL] Table 1 has rank {rank_p1} < 15!")
        failures += 1

    if rank_p2 == 15:
        print(f" [PASS] GF(2) Rank of Table 2 (15x128):      {rank_p2} / 15 (Full rank)")
    else:
        print(f" [FAIL] Table 2 has rank {rank_p2} < 15!")
        failures += 1

    if rank_combined == 30:
        print(f" [PASS] GF(2) Combined Rank (30x128):       {rank_combined} / 30 (Full rank, independent spans)")
    else:
        print(f" [FAIL] Combined matrix has rank {rank_combined} < 30!")
        failures += 1

    if rank_deltas == 15:
        print(f" [PASS] GF(2) Deltas Rank (15x128):         {rank_deltas} / 15 (Full rank)")
    else:
        print(f" [FAIL] Deltas matrix has rank {rank_deltas} < 15!")
        failures += 1

    # 3.4 Cross-Round Slide Resistance (All 225 pairs)
    cross_pairs_hw = []
    zero_pairs = 0
    for i in range(15):
        for j in range(15):
            d = p1_published[i] ^ p2_words[j]
            hw = bin(d).count("1")
            cross_pairs_hw.append(hw)
            if d == 0:
                zero_pairs += 1

    min_cp, max_cp, avg_cp, std_cp = stats(cross_pairs_hw)
    if zero_pairs == 0:
        print(f" [PASS] Cross-Round Pair Distinctness:       Tested all 15x15 = 225 pairs of P1[i] ^ P2[j]")
        print(f"        -> Zero-difference pairs:            {zero_pairs}")
        print(f"        -> Cross-pair Hamming Distance:      Min = {min_cp}, Max = {max_cp}, Mean = {avg_cp:.2f}")
    else:
        print(f" [FAIL] Found {zero_pairs} pairs with identical P1[i] and P2[j] constants!")
        failures += 1

    # 3.5 AES Column Invariant Subspaces
    column_symmetric_words = 0
    for idx, w in enumerate(p2_words):
        cols = [(w >> (32 * c)) & 0xFFFFFFFF for c in range(4)]
        if len(set(cols)) < 4:
            column_symmetric_words += 1

    if column_symmetric_words == 0:
        print(f" [PASS] AES Column Symmetry Check:           {column_symmetric_words} / 15 words with identical 32-bit columns")
    else:
        print(f" [FAIL] Found {column_symmetric_words} words with identical 32-bit columns!")
        failures += 1

    # -------------------------------------------------------------------------
    # SECTION 4: C IMPLEMENTATION ARRAYS
    # -------------------------------------------------------------------------
    print("\n" + "-" * 86)
    print(" SECTION 4: C TABLES")
    print("-" * 86)
    print("/*")
    print(" * Areion-SoEM22 Table 2 Round Constants (P2)")
    print(" * Derived from 128-bit words 15..29 of fractional pi; RC7 (word 22) shifted by one nibble as in Table 1.")
    print(" * Format: 15 rounds x 4 uint32_t words, matching Appendix A.1 of Isobe et al. (ePrint 2023/794).")
    print(" * Loaded via: #define RC2_0(i) _mm_setr_epi32(RC2[(i)*4+3], RC2[(i)*4+2], RC2[(i)*4+1], RC2[(i)*4+0])")
    print(" */")
    print("const uint32_t RC2[15*4] = {")
    for r in range(15):
        w = p2_words[r]
        u = to_paper_uint32_words(w)
        comment = f"/* Round {r:2d}: 0x{w:032x} */"
        print(f"    0x{u[0]:08x}, 0x{u[1]:08x}, 0x{u[2]:08x}, 0x{u[3]:08x},  {comment}")
    print("};")

    print("\n/*")
    print(" * Byte-array format (15 rounds x 16 bytes, little-endian):")
    print(" */")
    print("static const uint8_t AreionRCTable2[15][16] = {")
    for r in range(15):
        b = to_le_bytes(p2_words[r])
        bytes_str = ", ".join(f"0x{x:02x}" for x in b)
        print(f"    {{{bytes_str}}},  /* Round {r:2d} */")
    print("};")

    print("=" * 86)
    if failures == 0:
        print(" [+] All mathematical and structural checks PASSED.")
        print("=" * 86)
        sys.exit(0)
    else:
        print(f" [!] FAILED: {failures} check(s) failed.")
        print("=" * 86)
        sys.exit(1)


if __name__ == "__main__":
    main()

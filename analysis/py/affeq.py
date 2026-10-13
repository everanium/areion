#!/usr/bin/env python3
"""Section F: byte-structured affine equivalences P2 = B o P1 o A.

A map that acts byte-wise and carries the S-box layer to an S-box layer
pairs an input map M_in with an output map M_out = S o M_in o S^-1, and
for linear M_in this forces M_in(x) = a * x^(2^i) (the linear
self-equivalences of inversion). To pass MixColumns, a byte-wise linear
map D1 with MC o D1 = D2 o MC must be the same field scalar on every
byte of the column (MC rows mix with coefficients 1, 2, 3, and 0x02
generates F_256 over F_2). So a chain through S, then MC, needs M_out's linear
part to be a field scalar. This checks all 2040 (a, i): which have
M_out linear part equal to multiplication by some lambda, and which
have M_in commuting with multiplication by 2."""
from sbox_selfeq import S, gmul, gpow

IS = [0] * 256
for x, y in enumerate(S):
    IS[y] = x

hits = []
mc_ok = []
for a in range(1, 256):
    for i in range(8):
        Min = lambda x: gmul(a, gpow(x, 1 << i)) if x else 0
        Mout = [S[Min(IS[y])] for y in range(256)]
        off = Mout[0]
        lin = [v ^ off for v in Mout]
        # linear?
        assert all(lin[x ^ y] == lin[x] ^ lin[y] for x in (1, 2, 4, 8, 16, 32, 64, 128) for y in range(256))
        lam = lin[1]
        if all(lin[y] == gmul(lam, y) for y in range(256)):
            hits.append((a, i, lam, off))
        if all(Min(gmul(2, x)) == gmul(2, Min(x)) for x in range(256)):
            mc_ok.append((a, i))
print("(a, i) with M_out linear part a field scalar:", hits)
print("(a, i) with M_in commuting with multiplication by 2:", len(mc_ok), "(all with i = 0)" if all(i == 0 for _, i in mc_ok) else mc_ok)

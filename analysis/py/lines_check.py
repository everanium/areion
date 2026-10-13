#!/usr/bin/env python3
"""Section B4: S(lambda*F) = 0x63 ^ A(lambda^-1 * F) for the
subfield F = F_4 or F_16, with A the linear part of the AES affine map.
MixColumns multiplies a byte by a field element, which maps F-lines to
F-lines. So a dimension-preserving coset trail with a single varying
byte can pass the next S-box only if A maps some F-line onto an F-line
(B1: those lines are the only sets of dimension 2 / 4 that S maps
affinely). Checks all 85 F_4-lines and 17 F_16-lines."""
from sbox_selfeq import S, gmul, gpow

def Alin(x):  # S(x) = Alin(inv(x)) ^ 0x63
    r = 0
    for i in range(8):
        b = 0
        for k in (0, 4, 5, 6, 7):
            b ^= (x >> ((i + k) % 8)) & 1
        r ^= b << i
    return r

def subfield(d):
    return sorted(x for x in range(256) if gpow(x, 2 ** d) == x)

for d, name in ((2, 'F_4'), (4, 'F_16')):
    F = subfield(d)
    assert len(F) == 2 ** d
    lines = {frozenset(gmul(l, f) for f in F) for l in range(1, 256)}
    hits = []
    for L in lines:
        img = frozenset(Alin(x) for x in L)
        if img in lines:
            hits.append((sorted(L)[:4], sorted(img)[:4]))
    # also: does S itself map an F-line onto an F-line as a set (offset 0x63 included)?
    s_hits = [L for L in lines if frozenset(S[x] for x in L) in lines]
    # and onto a coset of an F-line: S(L) = line ^ t for some t
    coset_hits = []
    for L in lines:
        img = sorted(S[x] for x in L)
        lin = frozenset(v ^ img[0] for v in img)
        if lin in lines:
            coset_hits.append(sorted(L)[:3])
    print(f'{name}: {len(lines)} lines; A maps a line onto a line: {len(hits)}; '
          f'S maps a line onto a line: {len(s_hits)}; S maps a line onto a coset of a line: {len(coset_hits)}')

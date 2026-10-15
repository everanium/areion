#!/usr/bin/env python3
"""Areion-256 / Areion-512 written as alternating S-box layers (partial,
possibly inverse) and affine maps on the full state, checked against the
library permutations (build/kat.txt). With y = SB(x0), Areion-256 uses
  x0' = SR(y) with y = (MC SR)^-1 (SB^-1(w) ^ c),  w = SB(MC SR y ^ c),
so one round is S, A1, S, A2, S^-1, A3 on the 256-bit state, the affine
steps A1, A2, A3 having linear parts L1, L2, L3."""
from sbox_selfeq import S

IS = [0] * 256
for x, y in enumerate(S):
    IS[y] = x

def xt(b): return ((b << 1) ^ 0x1b) & 0xff if b & 0x80 else b << 1
def mul(a, k):
    r = 0
    while k:
        if k & 1: r ^= a
        a = xt(a); k >>= 1
    return r

def SR(b): return [b[(i + 4 * (i % 4)) % 16] for i in range(16)]
def ISR(b):
    o = [0] * 16
    for i in range(16):
        o[(i + 4 * (i % 4)) % 16] = b[i]
    return o
def MCm(b, m):
    o = [0] * 16
    for c in range(4):
        a = b[4 * c:4 * c + 4]
        for r in range(4):
            o[4 * c + r] = mul(a[0], m[(0 - r) % 4]) ^ mul(a[1], m[(1 - r) % 4]) ^ mul(a[2], m[(2 - r) % 4]) ^ mul(a[3], m[(3 - r) % 4])
    return o
def MC(b): return MCm(b, [2, 3, 1, 1])
def IMC(b): return MCm(b, [14, 11, 13, 9])
def SBb(b): return [S[v] for v in b]
def ISBb(b): return [IS[v] for v in b]
def X(a, b): return [u ^ v for u, v in zip(a, b)]

from paths import BUILD, constants
P1, P2pi, P2sh = constants()

# --- direct round functions (mirror the library) ---
def perm256(st, rc):
    x = [st[0:16], st[16:32]]
    for r in range(10):
        A, B = (0, 1) if r % 2 == 0 else (1, 0)
        t = MC(SR(SBb(X(MC(SR(SBb(x[A]))), rc[r]))))
        x[B] = X(t, x[B])
        x[A] = SR(SBb(x[A]))
    return x[0] + x[1]

def round512(x, ia, rc):
    ib, ic, id_ = (ia + 1) % 4, (ia + 2) % 4, (ia + 3) % 4
    a, b, c, d = x[ia], x[ib], x[ic], x[id_]
    b = X(b, MC(SR(SBb(a))))
    d = X(d, MC(SR(SBb(c))))
    a = SR(SBb(a))
    c = MC(SR(SBb(X(SR(SBb(c)), rc))))
    x[ia], x[ib], x[ic], x[id_] = a, b, c, d

def perm512(st, rc):
    x = [st[16 * i:16 * i + 16] for i in range(4)]
    for r in range(15):
        round512(x, r % 4, rc[r])
    x = [x[3], x[0], x[1], x[2]]
    return sum(x, [])

# --- layer decomposition: list of ('S', blocks, inverse) / ('A', lin, blockconst) ---
def steps256(rc):
    out = []
    for r in range(10):
        A, B = (0, 1) if r % 2 == 0 else (1, 0)
        c = rc[r]
        out.append(('S', (A,), False))
        out.append(('A', ('L1', A), {A: c}))             # A <- MC SR A ^ c
        out.append(('S', (A,), False))
        out.append(('A', ('L2', A), {}))                 # B <- B ^ MC SR A
        out.append(('S', (A,), True))
        out.append(('A', ('L3', A), {A: L3blk(c)}))      # A <- SR (MC SR)^-1 (A ^ c)
    return out

def L1blk(b): return MC(SR(b))
def L3blk(b): return SR(ISR(IMC(b)))           # SR o (MC o SR)^-1

def lin256(kind, A, x):
    B = 1 - A
    x = [x[0][:], x[1][:]]
    if kind == 'L1': x[A] = L1blk(x[A])
    elif kind == 'L2': x[B] = X(x[B], MC(SR(x[A])))
    elif kind == 'L3': x[A] = L3blk(x[A])
    return x

def steps512(rc):
    out = []
    for r in range(15):
        o = r % 4
        out.append(('S', (o, (o + 2) % 4), False))
        out.append(('A', ('M1', o), {(o + 2) % 4: rc[r]}))
        out.append(('S', ((o + 2) % 4,), False))
        out.append(('A', ('M2', o), {}))
    out.append(('A', ('ROT', 0), {}))
    return out

def lin512(kind, o, x):
    x = [b[:] for b in x]
    ia, ib, ic, id_ = o, (o + 1) % 4, (o + 2) % 4, (o + 3) % 4
    if kind == 'M1':
        a, b, c, d = x[ia], x[ib], x[ic], x[id_]
        x[ia], x[ib], x[ic], x[id_] = SR(a), X(b, MC(SR(a))), SR(c), X(d, MC(SR(c)))
    elif kind == 'M2':
        x[ic] = MC(SR(x[ic]))
    elif kind == 'ROT':
        x = [x[3], x[0], x[1], x[2]]
    return x

def run_steps(st, steps, nb, lin):
    x = [st[16 * i:16 * i + 16] for i in range(nb)]
    for s in steps:
        if s[0] == 'S':
            for blk in s[1]:
                x[blk] = ISBb(x[blk]) if s[2] else SBb(x[blk])
        else:
            kind, arg = s[1]
            x = lin(kind, arg, x)
            for blk, c in s[2].items():
                x[blk] = X(x[blk], c)
    return sum(x, [])

if __name__ == '__main__':
    # the library uses the published P1, whatever AREION_RC7P1 selects
    P1, _, P2lib = constants(library=True)    # the library's P2 is the shift form
    ok = True
    for line in open(BUILD / 'kat.txt'):
        w, i, o1, o2 = line.split()
        i, o1, o2 = (list(bytes.fromhex(v)) for v in (i, o1, o2))
        if w == '256':
            for rc, o in ((P1, o1), (P2lib, o2)):
                ok &= perm256(i, rc) == o
                ok &= run_steps(i, steps256(rc), 2, lin256) == o
        else:
            for rc, o in ((P1, o1), (P2lib, o2)):
                ok &= perm512(i, rc) == o
                ok &= run_steps(i, steps512(rc), 4, lin512) == o
    print('direct and layered permutations match the library on kat.txt:', ok)

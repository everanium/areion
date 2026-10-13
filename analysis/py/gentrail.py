#!/usr/bin/env python3
"""Section B2: generic subspace trails (valid for every coset, i.e. every
key) of Areion-256 / Areion-512, by propagation of difference spaces. The
affine hull of every derivative image of the AES S-box and of its inverse
is F_2^8 (checked below), so an S-box layer maps a difference space U
onto its projection outside the layer plus the full bytes on which U is
nonzero; linear steps map U exactly. The shared S-box layer of a round
is applied once, as in the library. Real differences of random pairs
must lie in the propagated spaces, and on sampled starts their rank is
compared with the propagated dimension. Starting from one full byte and
from one bit, at every position and every start round, the script
reports how many whole rounds keep the difference space below the full
state, forward through P and backward through P^-1."""
import random

from layers import SR, ISR, MC, IMC, SBb, ISBb, P1
from sbox_selfeq import S

# the affine hull of every derivative image of S and of S^-1 is F_2^8, so an
# S-box layer can move a difference on an active byte anywhere in that byte
IS = [0] * 256
for x, y in enumerate(S):
    IS[y] = x
for name, T in (("S", S), ("S^-1", IS)):
    for a in range(1, 256):
        imgs = [T[x] ^ T[x ^ a] for x in range(256)]
        basis = []
        for y in imgs:
            v = y ^ imgs[0]
            for b in basis:
                v = min(v, v ^ b)
            if v:
                basis.append(v)
        assert len(basis) == 8, (name, a)
print("affine hull of every derivative image of S and S^-1 is F_2^8: yes")

FULLBLOCK = (1 << 128) - 1


def blk(v, k):
    return [(v >> (128 * k + 8 * i)) & 0xff for i in range(16)]


def put(v, k, b):
    v &= ~(FULLBLOCK << (128 * k))
    return v | (sum(x << (8 * i) for i, x in enumerate(b)) << (128 * k))


def echelon(vs):
    basis = {}
    for v in vs:
        while v:
            hb = v.bit_length() - 1
            if hb not in basis:
                basis[hb] = v
                break
            v ^= basis[hb]
    return list(basis.values())


def support(vs, k):
    """Bytes of block k on which some vector of vs is nonzero."""
    return {i for v in vs for i, x in enumerate(blk(v, k)) if x}


def full_bytes(k, idx):
    return [1 << (128 * k + 8 * i + j) for i in idx for j in range(8)]


def s_layer(U, blocks):
    """Generic S-box (or inverse S-box) layer on the given blocks."""
    out = list(U)
    extra = []
    for k in blocks:
        extra += full_bytes(k, support(U, k))
        out = [v & ~(FULLBLOCK << (128 * k)) for v in out]
    return echelon(out + extra)


def lin(U, f):
    return echelon(f(v) for v in U)


def X(a, b):
    return [p ^ q for p, q in zip(a, b)]


# ---- Areion-256: x_B ^= MC SR SB(MC SR SB(x_A) ^ c), x_A = SR SB(x_A) ----

def fwd256(U, r):
    A, B = (0, 1) if r % 2 == 0 else (1, 0)
    U = s_layer(U, [A])                                   # y = SB(x_A), shared
    t = echelon(put(0, A, MC(SR(blk(v, A)))) for v in U)  # F's second S-box input
    w = full_bytes(B, support(t, A))                      # generic S on it, placed in x_B
    w = [put(0, B, MC(SR(blk(v, B)))) for v in w]         # ... then MC SR
    U = lin(U, lambda v: put(v, A, SR(blk(v, A))))        # x_A = SR(y)
    return echelon(U + w)


def bwd256(U, r):
    A, B = (0, 1) if r % 2 == 0 else (1, 0)
    t = echelon(put(0, A, MC(blk(v, A))) for v in U)      # MC SR y = MC x_A'
    w = full_bytes(B, support(t, A))
    w = [put(0, B, MC(SR(blk(v, B)))) for v in w]
    U = lin(U, lambda v: put(v, A, ISR(blk(v, A))))       # y = SR^-1 x_A'
    U = echelon(U + w)                                    # x_B = x_B' ^ F
    return s_layer(U, [A])                                # x_A = SB^-1(y)


# ---- Areion-512: one round on (a, b, c, d) = blocks o, o+1, o+2, o+3 ----

def fwd512(U, r):
    o = r % 4
    a, b, c, d = o, (o + 1) % 4, (o + 2) % 4, (o + 3) % 4
    U = s_layer(U, [a, c])                                # shared SB on a and c

    def m1(v):
        ya, yc = blk(v, a), blk(v, c)
        v = put(v, b, X(blk(v, b), MC(SR(ya))))
        v = put(v, d, X(blk(v, d), MC(SR(yc))))
        v = put(v, a, SR(ya))
        return put(v, c, SR(yc))
    U = lin(U, m1)
    U = s_layer(U, [c])
    return lin(U, lambda v: put(v, c, MC(SR(blk(v, c)))))


def bwd512(U, r):
    o = r % 4
    a, b, c, d = o, (o + 1) % 4, (o + 2) % 4, (o + 3) % 4
    U = lin(U, lambda v: put(v, c, ISR(IMC(blk(v, c)))))
    U = s_layer(U, [c])

    def m1inv(v):
        ap, c1 = blk(v, a), blk(v, c)
        v = put(v, b, X(blk(v, b), MC(ap)))               # b = b' ^ MC SR(SR^-1 a')
        v = put(v, d, X(blk(v, d), MC(c1)))
        v = put(v, a, ISR(ap))
        return put(v, c, ISR(c1))
    U = lin(U, m1inv)
    return s_layer(U, [a, c])


# ---- soundness: real differences stay inside the propagated spaces ----

def real256(x, r, backward):
    A, B = (0, 1) if r % 2 == 0 else (1, 0)
    x = [b[:] for b in x]
    if not backward:
        y = SBb(x[A])
        x[B] = X(x[B], MC(SR(SBb(X(MC(SR(y)), P1[r])))))
        x[A] = SR(y)
    else:
        y = ISR(x[A])
        x[B] = X(x[B], MC(SR(SBb(X(MC(SR(y)), P1[r])))))
        x[A] = ISBb(y)
    return x


def real512(x, r, backward):
    o = r % 4
    a, b, c, d = o, (o + 1) % 4, (o + 2) % 4, (o + 3) % 4
    x = [q[:] for q in x]
    if not backward:
        ya, yc = SBb(x[a]), SBb(x[c])
        x[b] = X(x[b], MC(SR(ya)))
        x[d] = X(x[d], MC(SR(yc)))
        x[a] = SR(ya)
        x[c] = MC(SR(SBb(X(SR(yc), P1[r]))))
    else:
        c1 = X(ISBb(ISR(IMC(x[c]))), P1[r])
        x[b] = X(x[b], MC(x[a]))
        x[d] = X(x[d], MC(c1))
        x[a] = ISBb(ISR(x[a]))
        x[c] = ISBb(ISR(c1))
    return x


def member(U, v):
    piv = {u.bit_length() - 1: u for u in echelon(U)}
    while v:
        hb = v.bit_length() - 1
        if hb not in piv:
            return False
        v ^= piv[hb]
    return True


def soundness(width, fwd, bwd, R, real, rng):
    nb = width // 128
    bad = 0
    for backward in (False, True):
        for r0 in range(R):
            for byte in (0, 16 * nb - 1, 16):
                U = echelon([1 << (8 * byte + i) for i in range(8)])
                order = list(range(r0, -1, -1) if backward else range(r0, R))
                spaces = []
                for r in order:
                    U = (bwd if backward else fwd)(U, r)
                    spaces.append(U)
                for _ in range(20):
                    x = [[rng.randrange(256) for _ in range(16)] for _ in range(nb)]
                    y = [q[:] for q in x]
                    y[byte // 16][byte % 16] ^= rng.randrange(1, 256)
                    for r, Ur in zip(order, spaces):
                        x, y = real(x, r, backward), real(y, r, backward)
                        if not member(Ur, to_int(x) ^ to_int(y)):
                            bad += 1
    return bad


def to_int(x):
    return sum(b << (8 * i) for i, b in enumerate(sum(x, [])))


def tightness(width, fwd, bwd, R, real, rng, pairs=600, depth=4):
    """Rank of real differences against the propagated dimension, first rounds."""
    nb = width // 128
    worst = 0
    checked = 0
    for backward in (False, True):
        r0 = R - 1 if backward else 0
        order = list(range(r0, r0 - depth, -1) if backward else range(r0, r0 + depth))
        for byte in (0, 5, 16, 16 * nb - 1):
            U = echelon([1 << (8 * byte + i) for i in range(8)])
            spaces = []
            for r in order:
                U = (bwd if backward else fwd)(U, r)
                spaces.append(U)
            diffs = [[] for _ in order]
            for _ in range(pairs):
                x = [[rng.randrange(256) for _ in range(16)] for _ in range(nb)]
                y = [q[:] for q in x]
                y[byte // 16][byte % 16] ^= rng.randrange(1, 256)
                for i, r in enumerate(order):
                    x, y = real(x, r, backward), real(y, r, backward)
                    diffs[i].append(to_int(x) ^ to_int(y))
            for Ur, D in zip(spaces, diffs):
                worst = max(worst, len(Ur) - len(echelon(D)))
                checked += 1
    return checked, worst


rng = random.Random(1)
for width, fwd, bwd, R, real in ((256, fwd256, bwd256, 10, real256), (512, fwd512, bwd512, 15, real512)):
    print(f"Areion-{width}: real differences outside the propagated spaces: "
          f"{soundness(width, fwd, bwd, R, real, rng)}")
    checked, worst = tightness(width, fwd, bwd, R, real, rng)
    print(f"Areion-{width}: propagated dimension minus rank of real differences, "
          f"{checked} sampled spaces: at most {worst}")

for width, fwd, bwd, R in ((256, fwd256, bwd256, 10), (512, fwd512, bwd512, 15)):
    nb = width // 128
    n = 128 * nb
    for backward, start in ((False, "byte"), (True, "byte"), (False, "bit"), (True, "bit")):
        step = bwd if backward else fwd
        best, arg, cut = 0, None, 0
        for r0 in range(R):
            for byte in range(16 * nb):
                U = echelon([1 << (8 * byte + i) for i in (range(8) if start == "byte" else (0,))])
                length = 0
                for r in (range(r0, -1, -1) if backward else range(r0, R)):
                    U = step(U, r)
                    if len(U) == n:
                        break
                    length += 1
                else:
                    cut = max(cut, length)  # still below full at the end of the permutation
                    continue
                if length > best:
                    best, arg = length, (r0, byte)
        dname = "backward" if backward else "forward"
        print(f"Areion-{width} {dname}, start in one {start}: longest generic subspace trail {best} rounds "
              f"(start round {arg[0]}, byte {arg[1]}); runs reaching the end of the permutation "
              f"while still below full: up to {cut} rounds")

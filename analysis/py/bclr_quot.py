#!/usr/bin/env python3
"""Section B3: quotient step. When dim W < n, any g of the BCLR setting
factors through the quotient F^n / W (W lies in its 0-linear
structures), which has 2^(n - dim W) points. g must also be
invariant under every partial S-box layer, so it is constant on the
classes of the relation proj(x) ~ proj(S_layer(x)). Random states give
edges of that relation (every edge found is real); if the classes merge
into one, only constant g remain."""
import random
from layers import P1, P2pi, P2sh, steps256, steps512, lin256, lin512, SBb
from bclr_full import diffs, to_int, to_state, maps256, maps512

def basis_of(D, maps, nb):
    basis = {}
    def red(v):
        while v:
            hb = v.bit_length() - 1
            if hb not in basis:
                return v
            v ^= basis[hb]
        return 0
    todo = list(D)
    while todo:
        v = todo.pop()
        r = red(v)
        if r:
            basis[r.bit_length() - 1] = r
            for m in maps:
                todo.append(to_int(m(to_state(v, nb))))
    return basis

def proj(basis, v):
    for hb in sorted(basis, reverse=True):
        if v >> hb & 1:
            v ^= basis[hb]
    return v

def classes(width, tables):
    nb = width // 128
    sf, maps = (steps256, maps256) if width == 256 else (steps512, maps512)
    D, _ = diffs(tables, sf, nb)
    basis = basis_of(D, maps, nb)
    k = 128 * nb - len(basis)
    if k == 0:
        return 0, 1, 1, 1
    if width == 256:
        layers = [(0,), (1,)]
    else:
        layers = [(o, (o + 2) % 4) for o in range(4)] + [((o + 2) % 4,) for o in range(4)]
    parent = {}
    def find(a):
        parent.setdefault(a, a)
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a
    rng = random.Random(5)
    for _ in range(4000):
        x = rng.getrandbits(128 * nb)
        st = to_state(x, nb)
        for L in layers:
            y = [b[:] for b in st]
            for blk in L:
                y[blk] = SBb(y[blk])
            a, b = find(proj(basis, x)), find(proj(basis, to_int(y)))
            parent[a] = b
    reps = {find(a) for a in list(parent)}
    return k, 2 ** k, len(reps), len(parent)

# every case of bclr_full.py; only those with dim W below the state size need the quotient step
CASES = [('P1 alone', [P1]), ('P2 pi alone', [P2pi]), ('P2 shift alone', [P2sh]),
         ('P1 and P2 pi', [P1, P2pi]), ('P1 and P2 shift', [P1, P2sh])]
for width in (256, 512):
    for name, tables in CASES:
        k, total, ncls, seen = classes(width, tables)
        if k:
            print(f'Areion-{width}, {name}: codim W = {k}; quotient points seen {seen} of {total}; classes after S-layer edges: {ncls}')

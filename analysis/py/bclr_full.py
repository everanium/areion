#!/usr/bin/env python3
"""Section B3: the BCLR criterion on the full-state layered form of
layers.py. Setting: g is invariant for every S-box layer (partial layers
and their inverses) and for every affine step; then for two affine steps
with the same linear part the XOR of their constants is a linear
structure of g, and the linear structures form a subspace invariant
under every linear part. W = smallest such subspace containing those
differences; dim W = full state rules out a non-constant g of this
kind."""
import itertools
from layers import (P1, P2pi, P2sh, steps256, steps512, lin256, lin512)

def to_int(x): return sum(b << (8 * i) for i, b in enumerate(sum(x, [])))
def to_state(v, nb): 
    bs = [(v >> (8 * i)) & 0xff for i in range(16 * nb)]
    return [bs[16 * k:16 * k + 16] for k in range(nb)]

def diffs(tables, steps_fn, nb):
    groups = {}
    for T in tables:
        for s in steps_fn(T):
            if s[0] == 'A' and s[2]:
                st = [[0] * 16 for _ in range(nb)]
                for blk, c in s[2].items():
                    st[blk] = c
                groups.setdefault(s[1], set()).add(to_int(st))
    D = []
    for key, cs in groups.items():
        cs = sorted(cs)
        D += [a ^ b for a, b in itertools.combinations(cs, 2)]
    return D, {k: len(v) for k, v in groups.items()}

def closure(D, maps, nb):
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
    return len(basis)

maps256 = [lambda x, k=k, a=a: lin256(k, a, x) for k in ('L1', 'L2', 'L3') for a in (0, 1)]
maps512 = [lambda x, k=k, o=o: lin512(k, o, x) for k in ('M1', 'M2') for o in range(4)]
if __name__ == '__main__':
    # control: one constant repeated in every round gives no differences
    same = [P1[0]] * 15
    D, _ = diffs([same], steps256, 2)
    print(f'control, Areion-256 with one repeated constant: {len(D)} differences; dim W = {closure(D, maps256, 2)}')
    for width, nb, sf, maps in ((256, 2, steps256, maps256), (512, 4, steps512, maps512)):
        for name, tables in (('P1 alone', [P1]), ('P2 pi alone', [P2pi]), ('P2 shift alone', [P2sh]),
                             ('P1 and P2 pi', [P1, P2pi]), ('P1 and P2 shift', [P1, P2sh])):
            D, g = diffs(tables, sf, nb)
            print(f'Areion-{width}, {name}: {len(D)} differences in {len(g)} groups; dim W = {closure(D, maps, nb)} of {128 * nb}')

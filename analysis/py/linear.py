#!/usr/bin/env python3
"""Truncated (byte-activity) linear-trail model of Areion-256 /
Areion-512, the dual of the difference model in model.py: an XOR node
forces equal masks on its two inputs and its output, a fork (one value
consumed twice) takes the XOR of the two branch masks, and the S-box
layer applied to the forked value is active where that XOR is nonzero.
MixColumns is modelled by its branch number 5, which also holds for the
transposed inverse that propagates masks.

Masks do not depend on the round constants (adding a constant only
changes the sign of a correlation), so one set of bounds covers P1, P2
and both RC7 forms.

The shared S-box layer of a round is counted once (single count, the
library's structure); --double counts it once per branch, for comparison
with the ASL column of Table 7 of the Areion paper.

    python3 analysis/py/linear.py WIDTH ROUNDS [--double]    (WIDTH: aes | 256 | 512)
"""
import argparse
import json
import sys
import time

from model import Model, build_aes, minimise


def xor3(m, a, b, c):
    for x, y, z in zip(a, b, c):
        m.cl += [[-x, y, z], [x, -y, z], [x, y, -z]]


def eq(m, a, b):
    for x, y in zip(a, b):
        m.cl += [[-x, y], [x, -y]]


def fork(m, u, double):
    """u is the mask on an S-box output consumed twice; returns the branch masks."""
    p1, p2 = m.new(), m.new()
    xor3(m, u, p1, p2)
    if double:
        m.count(p1)
        m.count(p2)
    else:
        m.count(u)
    return p1, p2


def build_256(rounds, double=False):
    m = Model()
    x = [m.new(), m.new()]
    m.cl.append(x[0] + x[1])                  # nonzero input mask
    rec = []
    for r in range(rounds):
        ai, bi = (0, 1) if r % 2 == 0 else (1, 0)
        A, B = x[ai], x[bi]
        p1, p2 = fork(m, A, double)           # SB(A) feeds the new A and F
        S = m.sr(p1)
        V = m.mc(m.sr(p2))                    # first half of F, then the constant
        m.count(V)                            # second S-box layer of F
        W = m.mc(m.sr(V))
        eq(m, B, W)                           # new B = W ^ B
        rec.append({"A": A, "B": B, "V": V, "W": W})
        x[ai], x[bi] = S, W
        m.mark()
    return m, rec


def build_512(rounds, double=False):
    m = Model()
    x = [m.new() for _ in range(4)]
    m.cl.append(sum(x, []))                   # nonzero input mask
    rec = []
    for r in range(rounds):
        o = r % 4
        ia, ib, ic, id_ = o, (o + 1) % 4, (o + 2) % 4, (o + 3) % 4
        a, b, c, d = x[ia], x[ib], x[ic], x[id_]
        p1a, p2a = fork(m, a, double)         # SB(a): new a and the update of b
        na = m.sr(p1a)
        t1 = m.mc(m.sr(p2a))
        eq(m, b, t1)
        p1c, p2c = fork(m, c, double)         # SB(c): the new c and the update of d
        t2 = m.mc(m.sr(p2c))
        eq(m, d, t2)
        c1 = m.sr(p1c)
        m.count(c1)                           # second S-box layer on SR(SB(c)) ^ constant
        cf = m.mc(m.sr(c1))
        rec.append({"a": a, "b": b, "c": c, "d": d, "c1": c1})
        x[ia], x[ib], x[ic], x[id_] = na, t1, cf, t2
        m.mark()
    return m, rec


def build(width, rounds, double=False):
    if width == "aes":
        m, rec = build_aes(rounds)            # truncated masks propagate like differences
        return m, rec
    return (build_256 if width == 256 else build_512)(rounds, double)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("width")
    ap.add_argument("rounds", type=int)
    ap.add_argument("--kmax", type=int, default=400)
    ap.add_argument("--double", action="store_true")
    a = ap.parse_args()
    width = a.width if a.width == "aes" else int(a.width)
    m, _ = build(width, a.rounds, a.double)
    t0 = time.time()
    k, _ = minimise(m, a.kmax, log=lambda s: print(s, file=sys.stderr, flush=True))
    print(json.dumps({"width": a.width, "mode": "linear" + ("-double" if a.double else ""),
                      "rounds": a.rounds, "min_active_sboxes": k, "secs": round(time.time() - t0, 1)}), flush=True)

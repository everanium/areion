#!/usr/bin/env python3
"""Truncated (byte-activity) related-constant differential model of
Areion-256 / Areion-512, P1(u) versus P2(u ^ delta), solved with pysat.
Every round adds Delta_r = RC1_r ^ RC2_r (a byte mask per round; all 16
bytes are nonzero for both RC7 forms of P2, with either form of P1),
and delta is free, including 0.
Plain AES rounds (SB, SR, MC) are included as a validation of the
counting: 4 rounds give the known 25.

Byte conventions follow the library: column-major state, shiftRows maps
new[i] = old[(i + 4*(i%4)) % 16], mixColumns on bytes 4c..4c+3.
"""
import itertools
import json
import sys
import time

from pysat.card import ITotalizer
from pysat.solvers import Solver


class Model:
    def __init__(self):
        self.nv = 0
        self.cl = []
        self.sboxes = []
        self.rounds = [[]]   # S-box literals per round (closed by mark()), for bounds.py

    def mark(self):
        """Close the current round's S-box list."""
        self.rounds.append([])

    def new(self, n=16):
        v = list(range(self.nv + 1, self.nv + 1 + n))
        self.nv += n
        return v

    @staticmethod
    def sr(w):
        return [w[(i + 4 * (i % 4)) % 16] for i in range(16)]

    def mc(self, a):
        b = self.new()
        for c in range(4):
            col = a[4 * c:4 * c + 4] + b[4 * c:4 * c + 4]
            # branch number 5: forbid total activity 1..4 over the 8 bytes
            for k in range(1, 5):
                for act in itertools.combinations(range(8), k):
                    s = set(act)
                    self.cl.append([(-col[i] if i in s else col[i]) for i in range(8)])
        return b

    def xor(self, a, b):
        c = self.new()
        for x, y, z in zip(a, b, c):
            self.cl += [[-x, y, z], [x, -y, z], [x, y, -z]]
        return c

    def addc(self, a, mask):
        if mask == 0:
            return a
        c = self.new()
        for j in range(16):
            if mask >> j & 1:
                self.cl.append([a[j], c[j]])
            else:
                self.cl += [[-a[j], c[j]], [a[j], -c[j]]]
        return c

    def count(self, w):
        self.sboxes += w
        self.rounds[-1] += w


def build_aes(rounds):
    m = Model()
    x = m.new()
    m.cl.append(list(x))
    rec = []
    for _ in range(rounds):
        m.count(x)
        rec.append({"X": x})
        x = m.mc(m.sr(x))
        m.mark()
    return m, rec


def build_256(rounds, deltas):
    m = Model()
    x = [m.new(), m.new()]
    rec = []
    for r in range(rounds):
        ai, bi = (0, 1) if r % 2 == 0 else (1, 0)
        A, B = x[ai], x[bi]
        S = m.sr(A)
        m.count(A)
        T1 = m.mc(S)
        T2 = m.addc(T1, deltas[r])
        m.count(T2)
        W = m.mc(m.sr(T2))
        nb = m.xor(W, B)
        rec.append({"A": A, "B": B, "T1": T1, "T2": T2, "W": W})
        x[ai], x[bi] = S, nb
        m.mark()
    rec.append({"x0": x[0], "x1": x[1]})
    return m, rec


def build_512(rounds, deltas):
    m = Model()
    x = [m.new() for _ in range(4)]
    rec = []
    for r in range(rounds):
        o = r % 4
        ia, ib, ic, id_ = o, (o + 1) % 4, (o + 2) % 4, (o + 3) % 4
        a, b, c, d = x[ia], x[ib], x[ic], x[id_]
        m.count(a)
        m.count(c)
        t1 = m.mc(m.sr(a))
        nb = m.xor(b, t1)
        t2 = m.mc(m.sr(c))
        nd = m.xor(d, t2)
        na = m.sr(a)
        c1 = m.sr(c)
        c2 = m.addc(c1, deltas[r])
        m.count(c2)
        cf = m.mc(m.sr(c2))
        rec.append({"a": a, "b": b, "c": c, "d": d, "t1": t1, "t2": t2, "c1": c1, "c2": c2, "cf": cf})
        x[ia], x[ib], x[ic], x[id_] = na, nb, cf, nd
        m.mark()
    rec.append({"x0": x[0], "x1": x[1], "x2": x[2], "x3": x[3]})  # state before the final word rotation (a renaming)
    return m, rec


def build(width, rounds, deltas):
    if width == "aes":
        return build_aes(rounds)
    return (build_256 if width == 256 else build_512)(rounds, deltas)


def minimise(m, kmax, solver_name="cadical153", log=None):
    tot = ITotalizer(lits=m.sboxes, ubound=kmax, top_id=m.nv)
    with Solver(name=solver_name, bootstrap_with=m.cl + tot.cnf.clauses) as s:
        for k in range(0, kmax + 1):
            t = time.time()
            sat = s.solve(assumptions=[-tot.rhs[k]] if k < len(tot.rhs) else [])
            if log:
                log(f"  K<={k}: {'SAT' if sat else 'UNSAT'} ({time.time()-t:.1f}s)")
            if sat:
                model = set(l for l in s.get_model() if l > 0)
                return k, model
    return None, None


def check_patterns(m, rec, traces, solver_name="cadical153"):
    """Every observed activity pattern must be satisfiable in the model."""
    bad = 0
    with Solver(name=solver_name, bootstrap_with=m.cl) as s:
        for tr in traces:
            assum = []
            for rdict, odict in zip(rec, tr):
                for name, vars_ in rdict.items():
                    mask = odict[name]
                    assum += [v if (mask >> j & 1) else -v for j, v in enumerate(vars_)]
            if not s.solve(assumptions=assum):
                bad += 1
    return bad


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("width")          # aes | 256 | 512
    ap.add_argument("rounds", type=int)
    ap.add_argument("--kmax", type=int, default=400)
    ap.add_argument("--check", help="file of oracle traces (JSON lines)")
    ap.add_argument("--solver", default="cadical153")
    a = ap.parse_args()
    width = a.width if a.width == "aes" else int(a.width)
    deltas = [0xFFFF] * 15  # Delta_r has all 16 bytes nonzero (run.py related checks this)
    m, rec = build(width, a.rounds, deltas)
    if a.check:
        traces = [json.loads(l) for l in open(a.check)]
        bad = check_patterns(m, rec, traces, a.solver)
        print(json.dumps({"width": a.width, "rounds": a.rounds,
                          "traces": len(traces), "unsat_traces": bad}))
        sys.exit(1 if bad else 0)
    t0 = time.time()
    k, _ = minimise(m, a.kmax, a.solver, log=lambda s: print(s, file=sys.stderr, flush=True))
    print(json.dumps({"width": a.width, "mode": "related" if width != "aes" else "aes", "rounds": a.rounds,
                      "min_active_sboxes": k, "secs": round(time.time() - t0, 1)}), flush=True)

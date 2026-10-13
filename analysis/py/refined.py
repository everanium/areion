#!/usr/bin/env python3
"""Related-constant Areion-256 model refined with the exhaustive column
feasibility of T2 = MC(S) ^ Delta_r (tables in build/, per RC7 form of
P2)."""
import argparse, json, sys, time
from model import Model, minimise, check_patterns
from paths import feas_path


def build(rounds, table):
    m = Model()
    x = [m.new(), m.new()]
    rec = []
    for r in range(rounds):
        ai, bi = (0, 1) if r % 2 == 0 else (1, 0)
        A, B = x[ai], x[bi]
        S = m.sr(A)
        m.count(A)
        T2 = m.new()
        for c in range(4):
            sv, tv = S[4 * c:4 * c + 4], T2[4 * c:4 * c + 4]
            for s in range(16):
                for t in range(16):
                    if not table[r][c][s][t]:
                        m.cl.append([(-sv[i] if s >> i & 1 else sv[i]) for i in range(4)] +
                                    [(-tv[i] if t >> i & 1 else tv[i]) for i in range(4)])
        m.count(T2)
        W = m.mc(m.sr(T2))
        nb = m.xor(W, B)
        rec.append({"A": A, "B": B, "T2": T2, "W": W})
        x[ai], x[bi] = S, nb
    rec.append({"x0": x[0], "x1": x[1]})
    return m, rec


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("variant")
    ap.add_argument("rounds", type=int)
    ap.add_argument("--check", help="file of oracle traces (JSON lines) that must all be satisfiable")
    a = ap.parse_args()
    table = json.load(open(feas_path()))[a.variant]
    m, rec = build(a.rounds, table)
    if a.check:
        traces = [json.loads(l) for l in open(a.check)]
        bad = check_patterns(m, rec, traces)
        print(json.dumps({"width": 256, "mode": "related-refined", "variant": a.variant, "rounds": a.rounds,
                          "traces": len(traces), "unsat_traces": bad}))
        sys.exit(1 if bad else 0)
    t0 = time.time()
    k, _ = minimise(m, 400, log=lambda s: print(s, file=sys.stderr, flush=True))
    print(json.dumps({"width": 256, "mode": "related-refined", "variant": a.variant, "rounds": a.rounds,
                      "min_active_sboxes": k, "secs": round(time.time() - t0, 1)}), flush=True)

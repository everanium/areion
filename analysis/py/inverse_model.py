#!/usr/bin/env python3
"""Track 2: Backward related-constant and single-permutation byte-activity
models for InversePermute (P1^-1, P2^-1).

Verifies backward models against real InversePermute oracle traces
(trace-inv), compares forward vs backward minimum active S-boxes under
delta = free, delta = 0, and 1-byte single-permutation input differences,
and compares forward vs backward byte-level impossible differentials.
"""
import argparse
import collections
import concurrent.futures
import json
import math
import os
import subprocess
import sys
import time

import highspy
import numpy as np
from pysat.solvers import Solver

import model as model_mod
from model import Model, check_patterns, minimise
from paths import BUILD, feas_path
import refined


def isr(w):
    """Inverse ShiftRows on a 16-element byte-literal list."""
    o = [0] * 16
    for i in range(16):
        o[(i + 4 * (i % 4)) % 16] = w[i]
    return o


def build_inv_256_coarse(rounds, deltas):
    m = Model()
    x = [m.new(), m.new()]
    rec = []
    for r in range(rounds - 1, -1, -1):
        ai, bi = (0, 1) if r % 2 == 0 else (1, 0)
        S, Bp = x[ai], x[bi]
        A = isr(S)
        m.count(A)
        T1 = m.mc(S)
        T2 = m.addc(T1, deltas[r])
        m.count(T2)
        W = m.mc(m.sr(T2))
        B = m.xor(Bp, W)
        rec.append({"S": S, "Bp": Bp, "A": A, "B": B, "T1": T1, "T2": T2, "W": W})
        x[ai], x[bi] = A, B
        m.mark()
    rec.append({"x0": x[0], "x1": x[1]})
    return m, rec


def build_inv_256_refined(rounds, table):
    m = Model()
    x = [m.new(), m.new()]
    rec = []
    for r in range(rounds - 1, -1, -1):
        ai, bi = (0, 1) if r % 2 == 0 else (1, 0)
        S, Bp = x[ai], x[bi]
        A = isr(S)
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
        B = m.xor(Bp, W)
        rec.append({"S": S, "Bp": Bp, "A": A, "B": B, "T2": T2, "W": W})
        x[ai], x[bi] = A, B
        m.mark()
    rec.append({"x0": x[0], "x1": x[1]})
    return m, rec


def build_inv_512_coarse(rounds, deltas):
    m = Model()
    x = [m.new() for _ in range(4)]
    rec = []
    for r in range(rounds - 1, -1, -1):
        o = r % 4
        ia, ib, ic, id_ = o, (o + 1) % 4, (o + 2) % 4, (o + 3) % 4
        ap, bp, cf, dp = x[ia], x[ib], x[ic], x[id_]
        a = isr(ap)
        m.count(a)
        t1 = m.mc(ap)
        b = m.xor(bp, t1)
        cm = m.mc(cf)
        c2 = isr(cm)
        m.count(c2)
        c1 = m.addc(c2, deltas[r])
        c = isr(c1)
        m.count(c)
        t2 = m.mc(c1)
        d = m.xor(dp, t2)
        rec.append({
            "ap": ap, "bp": bp, "cf": cf, "dp": dp,
            "a": a, "b": b, "c": c, "d": d,
            "t1": t1, "t2": t2, "cm": cm, "c2": c2, "c1": c1,
        })
        x[ia], x[ib], x[ic], x[id_] = a, b, c, d
        m.mark()
    rec.append({"x0": x[0], "x1": x[1], "x2": x[2], "x3": x[3]})
    return m, rec


def solve_milp_generic(build_fn, rounds, inp_vars_fn, dmode="free", prefix_bounds=None, time_limit=10.0):
    """Solve any coarse model built via Model using HiGHS MILP."""
    cols = []
    orig_mc = model_mod.Model.mc

    def rec_mc(self, a):
        start = len(self.cl)
        b = orig_mc(self, a)
        for c in range(4):
            cols.append((start, len(self.cl), a[4 * c:4 * c + 4] + b[4 * c:4 * c + 4]))
        return b

    model_mod.Model.mc = rec_mc
    try:
        m, rec = build_fn(rounds)
    finally:
        model_mod.Model.mc = orig_mc

    inp = inp_vars_fn(rec)
    if dmode == "zero":
        for v in inp:
            m.cl.append([-v])

    drop = set()
    for s, e, _ in cols:
        drop.update(range(s, e))
    obj = collections.Counter(m.sboxes)
    n, ncol = m.nv, len(cols)
    h = highspy.Highs()
    h.setOptionValue("output_flag", False)
    h.setOptionValue("threads", 1)
    h.setOptionValue("mip_rel_gap", 0.0)
    h.setOptionValue("mip_abs_gap", 0.999)
    if time_limit:
        h.setOptionValue("time_limit", float(time_limit))

    nv = n + ncol
    idx = np.arange(nv, dtype=np.int32)
    cost = np.zeros(nv)
    for v, k in obj.items():
        cost[v - 1] = k
    h.addVars(nv, np.zeros(nv), np.ones(nv))
    h.changeColsIntegrality(nv, idx, np.array([highspy.HighsVarType.kInteger] * nv))
    h.changeColsCost(nv, idx, cost)
    inf = highspy.kHighsInf

    def row(lo, c_idx, vals, hi=inf):
        h.addRow(lo, hi, len(c_idx), np.array(c_idx, dtype=np.int32), np.array(vals, dtype=float))

    if dmode == "onebyte":
        row(1.0, [v - 1 for v in inp], [1.0] * len(inp), hi=1.0)

    for i, c in enumerate(m.cl):
        if i not in drop:
            row(1 - sum(1 for l in c if l < 0), [abs(l) - 1 for l in c], [1.0 if l > 0 else -1.0 for l in c])
    for j, (_, _, col) in enumerate(cols):
        d = n + j
        row(0, [v - 1 for v in col] + [d], [1.0] * 8 + [-5.0])
        for v in col:
            row(0, [d, v - 1], [1.0, -1.0])

    rounds_lits = [r for r in m.rounds if r][:rounds]
    if prefix_bounds:
        lits = []
        for r_idx, rl in enumerate(rounds_lits, 1):
            lits += rl
            if r_idx < rounds and r_idx in prefix_bounds and prefix_bounds[r_idx] > 0:
                cnt = collections.Counter(lits)
                row(prefix_bounds[r_idx], [v - 1 for v in cnt], [float(k) for k in cnt.values()])

    h.run()
    status = h.modelStatusToString(h.getModelStatus())
    info = h.getInfo()
    value, bound = info.objective_function_value, info.mip_dual_bound
    if status == "Optimal" and math.ceil(bound - 1e-6) == round(value) and abs(value - round(value)) <= 1e-6:
        return round(value), True
    lb = max(0, int(math.ceil(bound - 1e-6)))
    if prefix_bounds and (rounds - 1) in prefix_bounds:
        lb = max(lb, prefix_bounds[rounds - 1])
    return lb, False


def solve_bwd_curve(task):
    """Worker for parallel forward vs backward active S-box curve computation."""
    label, direction, kind, width, max_r, dmode, feas = task
    t0 = time.time()
    curve = []
    exact_flags = []
    prefix = {}
    deltas = [0] * 15 if dmode == "onebyte" else [0xFFFF] * 15
    for r in range(1, max_r + 1):
        if kind == "refined":
            if direction == "fwd":
                m, rec = refined.build(r, feas)
                inp = rec[0]["A"] + rec[0]["B"]
            else:
                m, rec = build_inv_256_refined(r, feas)
                inp = rec[0]["S"] + rec[0]["Bp"]
            if dmode == "zero":
                for v in inp:
                    m.cl.append([-v])
            k, _ = minimise(m, 400)
            curve.append(k)
            exact_flags.append(True)
            prefix[r] = k
        else:
            if direction == "fwd":
                bfn = lambda rr: model_mod.build(width, rr, deltas)
                ifn = (lambda rec: rec[0]["A"] + rec[0]["B"]) if width == 256 else (lambda rec: sum((rec[0][w] for w in "abcd"), []))
            else:
                bfn = (lambda rr: build_inv_256_coarse(rr, deltas)) if width == 256 else (lambda rr: build_inv_512_coarse(rr, deltas))
                ifn = (lambda rec: rec[0]["S"] + rec[0]["Bp"]) if width == 256 else (lambda rec: sum((rec[0][w] for w in ("ap", "bp", "cf", "dp")), []))
            # Note: for backward models where rounds r-1..0 are unrolled, the first round unrolled changes with r,
            # so prefix_bounds only apply directly when the round sequence is a prefix (or when deltas are uniform).
            use_pref = prefix if (direction == "fwd" or kind == "coarse") else None
            k, exact = solve_milp_generic(bfn, r, ifn, dmode=dmode, prefix_bounds=use_pref, time_limit=10.0)
            curve.append(k)
            exact_flags.append(exact)
            prefix[r] = k
    return (label, direction, kind, width, dmode, curve, exact_flags, round(time.time() - t0, 2))


def run_impdiff_comparison(r256, r512):
    """Compare forward vs backward byte-level impossible differentials for
    delta in ('free', 'full', 'zero')."""
    print("\n== Track 2.7: Forward vs Backward Byte-Level Impossible Differentials (impdiff)", flush=True)
    for width, max_r in ((256, r256), (512, r512)):
        nb = width // 128
        for dmode in ("free", "full", "zero"):
            for r in range(1, min(max_r, 6) + 1):
                res_dir = {}
                for direction in ("fwd", "bwd"):
                    if direction == "fwd":
                        m, rec = model_mod.build(width, r, [0xFFFF] * 15)
                        inp = (rec[0]["A"] + rec[0]["B"]) if width == 256 else sum((rec[0][w] for w in "abcd"), [])
                    else:
                        m, rec = (build_inv_256_coarse if width == 256 else build_inv_512_coarse)(r, [0xFFFF] * 15)
                        inp = (rec[0]["S"] + rec[0]["Bp"]) if width == 256 else sum((rec[0][w] for w in ("ap", "bp", "cf", "dp")), [])
                    if dmode == "full":
                        m.cl += [[v] for v in inp]
                    elif dmode == "zero":
                        m.cl += [[-v] for v in inp]
                    fin = rec[-1]
                    outv = sum((fin[f"x{i}"] for i in range(nb)), [])
                    cannot_inactive = []
                    cannot_active = []
                    with Solver(name="cadical153", bootstrap_with=m.cl) as s:
                        for j, v in enumerate(outv):
                            if not s.solve(assumptions=[-v]):
                                cannot_inactive.append(j)
                            if not s.solve(assumptions=[v]):
                                cannot_active.append(j)
                        allzero_sat = s.solve(assumptions=[-v for v in outv])
                    res_dir[direction] = (len(cannot_inactive), len(cannot_active), allzero_sat)
                fi, fa, fz = res_dir["fwd"]
                bi, ba, bz = res_dir["bwd"]
                print(f"Areion-{width} r={r:2d} delta={dmode:4s} | FWD: forced_active={fi:2d} forced_zero={fa:2d} allzero_sat={str(fz):5s} | BWD: forced_active={bi:2d} forced_zero={ba:2d} allzero_sat={str(bz):5s}", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--r256", type=int, default=10)
    ap.add_argument("--r512", type=int, default=15)
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument("--gobin", help="path to analysis/build/analysis binary for trace-inv")
    ap.add_argument("--trace-n", type=int, default=200)
    a = ap.parse_args()

    feas_all = json.load(open(feas_path()))

    # 1. Backward oracle verification against real traces of InversePermute
    if a.gobin:
        print(f"== Track 2.5: Backward Oracle Verification on P1^-1 vs P2^-1 (n={a.trace_n} traces)", flush=True)
        total_bad = 0
        for width, r in ((256, a.r256), (512, a.r512)):
            for v in ("pi", "shift"):
                p = subprocess.run([a.gobin, "trace-inv", str(width), v, str(r), str(a.trace_n)],
                                   capture_output=True, text=True, check=True)
                traces = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
                m_c, rec_c = (build_inv_256_coarse if width == 256 else build_inv_512_coarse)(r, [0xFFFF] * 15)
                bad_c = check_patterns(m_c, rec_c, traces)
                bad_r = 0
                if width == 256:
                    m_r, rec_r = build_inv_256_refined(r, feas_all[v])
                    bad_r = check_patterns(m_r, rec_r, traces)
                total_bad += bad_c + bad_r
                print(json.dumps({
                    "check": "oracle-inv", "width": width, "variant": v, "rounds": r,
                    "traces": len(traces), "unsat_coarse": bad_c,
                    "unsat_refined": bad_r if width == 256 else None
                }), flush=True)
        if total_bad:
            raise SystemExit(f"oracle-inv failed: {total_bad} unsat traces")

    # 2. Forward vs Backward Active S-Box Bounds
    print("\n== Track 2.6: Forward (Permute) vs Backward (InversePermute) Active S-Box Bounds", flush=True)
    tasks = []
    for direction in ("fwd", "bwd"):
        for dmode in ("free", "zero"):
            tasks.append(("related-coarse", direction, "coarse", 256, a.r256, dmode, None))
            tasks.append(("related-refined-shift", direction, "refined", 256, a.r256, dmode, feas_all["shift"]))
            tasks.append(("related-refined-pi", direction, "refined", 256, a.r256, dmode, feas_all["pi"]))
            tasks.append(("related-coarse", direction, "coarse", 512, a.r512, dmode, None))
        # Single-permutation 1-byte start difference (capped at 7 rounds for 512)
        tasks.append(("single-1byte", direction, "coarse", 256, a.r256, "onebyte", None))
        tasks.append(("single-1byte", direction, "coarse", 512, min(a.r512, 7), "onebyte", None))

    results = {}
    with concurrent.futures.ProcessPoolExecutor(max_workers=a.jobs) as ex:
        for label, direction, kind, width, dmode, curve, exact_flags, secs in ex.map(solve_bwd_curve, tasks):
            results[(label, direction, width, dmode)] = (curve, exact_flags, secs)

    for (label, width, dmode) in (
        ("related-coarse", 256, "free"),
        ("related-coarse", 256, "zero"),
        ("related-refined-shift", 256, "free"),
        ("related-refined-shift", 256, "zero"),
        ("related-refined-pi", 256, "free"),
        ("related-refined-pi", 256, "zero"),
        ("single-1byte", 256, "onebyte"),
        ("related-coarse", 512, "free"),
        ("related-coarse", 512, "zero"),
        ("single-1byte", 512, "onebyte"),
    ):
        for direction in ("fwd", "bwd"):
            curve, exact_flags, tot_s = results[(label, direction, width, dmode)]
            cols = " ".join(
                f"r{r}:{curve[r-1]:3d}{'' if exact_flags[r-1] else '*'}"
                for r in range(1, len(curve) + 1)
            )
            print(f"Areion-{width} | {label:21s} | delta={dmode:7s} | {direction.upper()} | {cols}  ({tot_s}s)", flush=True)

    # 3. Forward vs Backward Impossible Differentials
    run_impdiff_comparison(a.r256, a.r512)


if __name__ == "__main__":
    main()

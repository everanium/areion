#!/usr/bin/env python3
"""Track 1: Parameterized P2^(k) dependence-dissolution spectrum across
rounds r = 1..R for Areion-256 and Areion-512.

Computes for each perturbation level L0..L4p and each round count r:
  1. Oracle verification that real traces of (P1, P2^(k)) satisfy both
     the parameterized coarse byte-activity model and (for Areion-256)
     the parameterized refined column-feasibility model.
  2. Exact minimum active S-boxes in the coarse and refined models for
     both unconstrained input difference (delta = free) and identical
     inputs / equal subkeys (delta = 0).
  3. Per-round BCLR invariant subspace dimension dim W_pair(r) and
     cross-table constant-difference closure dim W_Delta(r).
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
from pathlib import Path

import highspy
import numpy as np

from bclr_full import closure, diffs, maps256, maps512, to_int
from layers import steps256, steps512
import model as model_mod
from model import check_patterns, minimise
from paths import BUILD
import refined


def load_dissolve_spec():
    path = os.environ.get("AREION_FEAS_DISSOLVE")
    if path and Path(path).exists():
        return json.load(open(path))
    found = sorted(BUILD.glob("feas_dissolve_*.json"), key=lambda p: p.stat().st_mtime)
    if not found:
        raise SystemExit("no feas_dissolve_*.json in build/; run via analysis/run.py dissolve")
    return json.load(open(found[-1]))


def build_coarse_with_cols(width, rounds, masks):
    """Build coarse model while recording MixColumns 8-byte tuples for MILP."""
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
        m, rec = model_mod.build(width, rounds, masks)
    finally:
        model_mod.Model.mc = orig_mc
    return m, rec, cols


def solve_milp_coarse(width, rounds, masks, dmode="free", prefix_bounds=None, time_limit=15.0):
    """Solve coarse byte-activity model using HiGHS MILP with prefix lower bounds."""
    m, rec, cols = build_coarse_with_cols(width, rounds, masks)
    if dmode == "zero":
        first = rec[0]
        inp = (first["A"] + first["B"]) if width == 256 else sum((first[w] for w in "abcd"), [])
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

    def row(lo, c_idx, vals):
        h.addRow(lo, inf, len(c_idx), np.array(c_idx, dtype=np.int32), np.array(vals, dtype=float))

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

    # If masks are periodic across all rounds (e.g. L3a, L3b, L4, L4p with dmode="free"),
    # any sub-window of w rounds also obeys the free-input bound for w rounds.
    if dmode == "free" and prefix_bounds and len(set(masks[:rounds])) == 1:
        for s in range(1, rounds):
            lits = []
            for w in range(1, rounds - s + 1):
                lits += rounds_lits[s + w - 1]
                if w < rounds and w in prefix_bounds and prefix_bounds[w] > 0:
                    cnt = collections.Counter(lits)
                    row(prefix_bounds[w], [v - 1 for v in cnt], [float(k) for k in cnt.values()])

    h.run()
    status = h.modelStatusToString(h.getModelStatus())
    info = h.getInfo()
    value, bound = info.objective_function_value, info.mip_dual_bound
    if status == "Optimal" and math.ceil(bound - 1e-6) == round(value) and abs(value - round(value)) <= 1e-6:
        return round(value), True
    # Return rigorous lower bound from MIP dual bound if time-limited
    lb = max(0, int(math.ceil(bound - 1e-6)))
    if prefix_bounds and (rounds - 1) in prefix_bounds:
        lb = max(lb, prefix_bounds[rounds - 1])
    return lb, False


def solve_curve(task):
    """Solve all rounds 1..max_r sequentially for one (kind, width, lid, dmode)
    so shorter rounds provide prefix/window lower bounds for longer rounds."""
    kind, width, lid, max_r, dmode, masks, feas = task
    t0 = time.time()
    curve = []
    exact_flags = []
    prefix = {}
    for r in range(1, max_r + 1):
        if kind == "refined":
            m, rec = refined.build(r, feas)
            if dmode == "zero":
                first = rec[0]
                for v in first["A"] + first["B"]:
                    m.cl.append([-v])
            k, _ = minimise(m, 400)
            curve.append(k)
            exact_flags.append(True)
            prefix[r] = k
        else:
            k, exact = solve_milp_coarse(width, r, masks, dmode=dmode, prefix_bounds=prefix, time_limit=10.0)
            curve.append(k)
            exact_flags.append(exact)
            prefix[r] = k
    return (kind, width, lid, dmode, curve, exact_flags, round(time.time() - t0, 2))


def cross_delta_closure(p1, rc2, rounds, width):
    """Dimension of the smallest subspace containing the cross-table round
    constant differences Delta_s = RC1_s ^ RC2_s (0 <= s < rounds) and
    invariant under every linear layer map of Areion-{width}."""
    nb = 2 if width == 256 else 4
    maps = maps256 if width == 256 else maps512
    seeds = []
    for s in range(rounds):
        delta = [a ^ b for a, b in zip(p1[s], rc2[s])]
        if any(delta):
            st = [[0] * 16 for _ in range(nb)]
            blk = (s % 2) if width == 256 else ((s + 2) % 4)
            st[blk] = delta
            seeds.append(to_int(st))
    return closure(seeds, maps, nb)


def pair_bclr_closure(p1, rc2, rounds, width):
    """Dimension of the BCLR subspace W for the pair (P1, P2^(k)) truncated
    to `rounds` rounds (6 affine/S-box steps per round in 256, 4 in 512)."""
    nb = 2 if width == 256 else 4
    maps = maps256 if width == 256 else maps512
    nsteps = 6 * rounds if width == 256 else 4 * rounds
    sf = (lambda T: steps256(T)[:nsteps]) if width == 256 else (lambda T: steps512(T)[:nsteps])
    D, _ = diffs([p1, rc2], sf, nb)
    return closure(D, maps, nb)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--r256", type=int, default=10)
    ap.add_argument("--r512", type=int, default=15)
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument("--gobin", help="path to analysis/build/analysis binary for trace-dissolve")
    ap.add_argument("--trace-n", type=int, default=100)
    a = ap.parse_args()

    spec = load_dissolve_spec()
    order = spec["order"]
    levels = spec["levels"]
    consts = json.load(open(BUILD / "consts.json"))
    p1 = [row[:] for row in consts["P1"]]
    if os.environ.get("AREION_RC7P1") == "pi":
        p1[7] = consts["P1rc7pi"]

    # 1. Oracle verification across all ladder levels
    if a.gobin:
        print(f"== Track 1.1: Oracle verification across {len(order)} ladder levels (n={a.trace_n} traces/level)", flush=True)
        total_bad = 0
        for lid in order:
            lv = levels[lid]
            masks = lv["masks"]
            feas = lv["feas"]
            for width, r in ((256, a.r256), (512, a.r512)):
                p = subprocess.run([a.gobin, "trace-dissolve", str(width), lid, str(r), str(a.trace_n)],
                                   capture_output=True, text=True, check=True)
                traces = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
                m_c, rec_c = model_mod.build(width, r, masks)
                bad_c = check_patterns(m_c, rec_c, traces)
                bad_r = 0
                if width == 256:
                    m_r, rec_r = refined.build(r, feas)
                    bad_r = check_patterns(m_r, rec_r, traces)
                total_bad += bad_c + bad_r
                print(json.dumps({
                    "check": "oracle-dissolve", "width": width, "level": lid, "name": lv["name"],
                    "rounds": r, "traces": len(traces),
                    "unsat_coarse": bad_c, "unsat_refined": bad_r if width == 256 else None
                }), flush=True)
        if total_bad:
            raise SystemExit(f"oracle-dissolve failed: {total_bad} unsat traces")

    # 2. Parameterized Coarse & Refined Active S-Box Bounds across L0..L4p and r=1..R
    print("\n== Track 1.2: Parameterized Related-Constant Active S-Box Bounds (coarse & refined, delta=free & delta=0)", flush=True)
    tasks = []
    for lid in order:
        lv = levels[lid]
        masks = lv["masks"]
        feas = lv["feas"]
        for dmode in ("free", "zero"):
            tasks.append(("coarse", 256, lid, a.r256, dmode, masks, None))
            tasks.append(("refined", 256, lid, a.r256, dmode, masks, feas))
            tasks.append(("coarse", 512, lid, a.r512, dmode, masks, None))

    results = {}
    with concurrent.futures.ProcessPoolExecutor(max_workers=a.jobs) as ex:
        for kind, width, lid, dmode, curve, exact_flags, secs in ex.map(solve_curve, tasks):
            results[(kind, width, lid, dmode)] = (curve, exact_flags, secs)

    for width, max_r, kinds in ((256, a.r256, ("coarse", "refined")), (512, a.r512, ("coarse",))):
        for kind in kinds:
            for dmode in ("free", "zero"):
                for lid in order:
                    lv = levels[lid]
                    curve, exact_flags, tot_s = results[(kind, width, lid, dmode)]
                    cols = " ".join(
                        f"r{r}:{curve[r-1]:3d}{'' if exact_flags[r-1] else '*'}"
                        for r in range(1, max_r + 1)
                    )
                    print(f"Areion-{width} | {kind:7s} | delta={dmode:4s} | {lid:3s} {lv['name']:12s} | {cols}  ({tot_s}s)", flush=True)

    # 3. Per-Round BCLR Invariant Subspace Growth dim W_Delta(r) and dim W_pair(r)
    print("\n== Track 1.3: Per-Round BCLR Subspace Dimension Growth dim W_Delta(r) / dim W_pair(r)", flush=True)
    for width, max_r in ((256, a.r256), (512, a.r512)):
        for lid in order:
            lv = levels[lid]
            rc2 = lv["rc"]
            d_delta = [cross_delta_closure(p1, rc2, r, width) for r in range(1, max_r + 1)]
            d_pair = [pair_bclr_closure(p1, rc2, r, width) for r in range(1, max_r + 1)]
            cols = " ".join(f"r{r}:{d_delta[r-1]:3d}/{d_pair[r-1]:3d}" for r in range(1, max_r + 1))
            print(f"Areion-{width} BCLR (W_Delta/W_pair of {width}) | {lid:3s} {lv['name']:12s} | {cols}", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Minima of the trail models of Areion-512 with the MILP solver HiGHS,
for the round counts the SAT descent of bounds.py / weighted.py does not
reach in reasonable time.

The model is the one of trails.py (KIND linear, single, related) or of
wmodel.py (--weights: the weighted models, in bits), built by the same
code; its clauses become linear rows (a clause l1 v ... v lk becomes
sum(l) >= 1, a negative literal entering as 1 - x), with two rows taken
from the structure instead of its clauses:
  MixColumns  each column (8 bytes, branch number 5) is
              sum(column) >= 5 d, column_i <= d, with a binary d,
              in place of the clauses that forbid 1 .. 4 active bytes;
  windows     'at least B(w)' over every window of w < R rounds is one
              row on the window's S-box literals (bounds.py encodes it
              with a counter).
The objective is the number of S-box literals (with multiplicity in the
weighted models). Both rows state the same sets of solutions as the
clauses they replace, so the minimum is the one bounds.py computes. To
compare the two solvers, run this script without --sat-table on round
counts the SAT table holds.

A minimum is accepted only when HiGHS reports an optimal solution with an
integer objective and a dual bound that rounds up to it. Neither solver emits
a checkable proof; the SAT search works in exact arithmetic, HiGHS in
floating point with tolerances, so its minima are marked as such
wherever they are used. They also serve as windows for longer round
counts, so an error in one would carry over to the longer ones.

The table (--table) holds the minima found here; --sat-table names the
table of bounds.py or weighted.py for the same model, whose values take
precedence and serve as windows.

    python3 analysis/py/milp.py KIND --upto R --table FILE [--sat-table FILE]
                                [--weights CHAIN_JSON] [--threads N] [--log FILE]
"""
import argparse
import collections
import importlib.metadata
import json
import math
import os
import sys
import time

import highspy
import numpy as np

import model as model_mod

# The columns of every MixColumns call, recorded while the model is built
# (the clauses are left as they are, and dropped from the MILP).
_COLUMNS = []
_mc = model_mod.Model.mc


def _recording_mc(self, a):
    start = len(self.cl)
    b = _mc(self, a)
    for c in range(4):
        _COLUMNS.append((start, len(self.cl), a[4 * c:4 * c + 4] + b[4 * c:4 * c + 4]))
    return b


model_mod.Model.mc = _recording_mc

from bounds import load_table, save_table, split_bound  # noqa: E402
from trails import build  # noqa: E402
from wmodel import weighted_model, weights  # noqa: E402


import multiprocessing as mp

_CUBE_STATE = {}


def _build_highs(m, rounds, table, cols_list, threads, log):
    drop = set()
    for s, e, _ in cols_list:
        drop.update(range(s, e))
    obj = collections.Counter(m.sboxes)
    n, ncol = m.nv, len(cols_list)
    h = highspy.Highs()
    h.setOptionValue("output_flag", bool(log))
    if log:
        h.setOptionValue("log_to_console", False)
        h.setOptionValue("log_file", log)
    h.setOptionValue("threads", int(threads))
    h.setOptionValue("mip_rel_gap", 0.0)
    h.setOptionValue("mip_abs_gap", 0.999)      # integer objective: a gap below 1 closes it
    nv = n + ncol
    idx = np.arange(nv, dtype=np.int32)
    cost = np.zeros(nv)
    for v, k in obj.items():
        cost[v - 1] = k
    h.addVars(nv, np.zeros(nv), np.ones(nv))
    h.changeColsIntegrality(nv, idx, np.array([highspy.HighsVarType.kInteger] * nv))
    h.changeColsCost(nv, idx, cost)
    inf = highspy.kHighsInf

    def row(lo, cols, vals, hi=inf):
        h.addRow(lo, hi, len(cols), np.array(cols, dtype=np.int32), np.array(vals, dtype=float))

    for i, c in enumerate(m.cl):
        if i not in drop:
            row(1 - sum(1 for l in c if l < 0), [abs(l) - 1 for l in c], [1.0 if l > 0 else -1.0 for l in c])
    for j, (_, _, col) in enumerate(cols_list):
        d = n + j
        row(0, [v - 1 for v in col] + [d], [1.0] * 8 + [-5.0])
        for v in col:
            row(0, [d, v - 1], [1.0, -1.0])
    for s in range(rounds):
        lits = []
        for w in range(1, rounds - s + 1):
            lits += m.rounds[s + w - 1]
            if w < rounds and table.get(w, 0) > 0:
                cnt = collections.Counter(lits)
                row(table[w], [v - 1 for v in cnt], [float(k) for k in cnt.values()])
    return h, obj


def _init_cube_worker(lp, rounds, mid_idx, cost_idx, cost_val, best_ub, lb):
    h = highspy.Highs()
    h.setOptionValue("output_flag", False)
    h.setOptionValue("threads", 1)
    h.setOptionValue("mip_rel_gap", 0.0)
    h.setOptionValue("mip_abs_gap", 0.999)
    h.passModel(lp)
    mid_row = lp.num_row_
    h.addRow(-highspy.kHighsInf, highspy.kHighsInf, len(mid_idx),
             np.array(mid_idx, dtype=np.int32), np.ones(len(mid_idx), dtype=float))
    ub_row = lp.num_row_ + 1
    h.addRow(-highspy.kHighsInf, highspy.kHighsInf, len(cost_idx),
             np.array(cost_idx, dtype=np.int32), np.array(cost_val, dtype=float))
    _CUBE_STATE.clear()
    _CUBE_STATE.update(h=h, rounds=rounds, mid_row=mid_row, ub_row=ub_row, best_ub=best_ub, lb=lb)


def _solve_cube_worker(c_val):
    h = _CUBE_STATE["h"]
    rounds = _CUBE_STATE["rounds"]
    mid_row = _CUBE_STATE["mid_row"]
    ub_row = _CUBE_STATE["ub_row"]
    best_ub = _CUBE_STATE["best_ub"]
    lb = _CUBE_STATE["lb"]

    ub = best_ub.value
    if ub <= lb:
        return None
    h.changeRowBounds(mid_row, float(c_val), float(c_val))
    if ub < 999999:
        h.changeRowBounds(ub_row, -highspy.kHighsInf, float(ub - 1))
    else:
        h.changeRowBounds(ub_row, -highspy.kHighsInf, highspy.kHighsInf)
    h.run()
    status = h.modelStatusToString(h.getModelStatus())
    if status == "Infeasible":
        return None
    info = h.getInfo()
    value, bound = info.objective_function_value, info.mip_dual_bound
    if status != "Optimal" or not math.isfinite(bound) or math.ceil(bound - 1e-6) != round(value) or abs(value - round(value)) > 1e-6:
        raise SystemExit(f"HiGHS cube {c_val} did not settle {rounds} rounds: {status}, value {value}, bound {bound}")
    val = int(round(value))
    with best_ub.get_lock():
        if val < best_ub.value:
            best_ub.value = val
    return val


def solve(m, rounds, table, threads, log):
    cols_list = list(_COLUMNS)
    if threads <= 1 or rounds < 7 or log:
        h, _ = _build_highs(m, rounds, table, cols_list, 1, log)
        h.run()
        status = h.modelStatusToString(h.getModelStatus())
        info = h.getInfo()
        value, bound = info.objective_function_value, info.mip_dual_bound
        if status != "Optimal" or not math.isfinite(bound) or math.ceil(bound - 1e-6) != round(value) or abs(value - round(value)) > 1e-6:
            raise SystemExit(f"HiGHS did not settle {rounds} rounds: {status}, value {value}, bound {bound}")
        return round(value)

    h_base, obj = _build_highs(m, rounds, table, cols_list, 1, None)
    lp = h_base.getLp()
    mid_lits = list(dict.fromkeys(m.rounds[rounds // 2]))
    mid_idx = [v - 1 for v in mid_lits]
    cost_idx = [v - 1 for v in obj.keys()]
    cost_val = [float(k) for k in obj.values()]
    lb = split_bound(rounds, table)
    ctx = mp.get_context("fork")
    best_ub = ctx.Value("i", 999999)
    cubes = list(range(len(mid_lits) + 1))
    cubes.sort(key=lambda c: (c == 0, abs(c - 6), c))
    with ctx.Pool(min(threads, len(cubes)), initializer=_init_cube_worker,
                  initargs=(lp, rounds, mid_idx, cost_idx, cost_val, best_ub, lb)) as pool:
        for res in pool.imap_unordered(_solve_cube_worker, cubes, chunksize=1):
            if res is not None and res < best_ub.value:
                with best_ub.get_lock():
                    if res < best_ub.value:
                        best_ub.value = res
    if best_ub.value >= 999999:
        raise SystemExit(f"HiGHS cubes found no feasible trail for {rounds} rounds")
    return int(best_ub.value)


def main():
    default_threads = int(os.environ.get("AREION_THREADS", max(1, (os.cpu_count() or 2) - 2)))
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kind", choices=("linear", "single", "related"))
    ap.add_argument("--upto", type=int, required=True)
    ap.add_argument("--table", required=True, help="table of the minima found by HiGHS (read and updated)")
    ap.add_argument("--sat-table", help="table of the SAT search for the same model (read only)")
    ap.add_argument("--weights", help="JSON of the Go subcommand chain: the weighted model of wmodel.py")
    ap.add_argument("--threads", type=int, default=default_threads)
    ap.add_argument("--log", help="HiGHS log file")
    a = ap.parse_args()
    w = weights(json.load(open(a.weights))) if a.weights else None
    unit = "min_bits" if w else "min_active_sboxes"
    try:
        version = importlib.metadata.version("highspy")
    except importlib.metadata.PackageNotFoundError:
        version = "unknown"
    print(json.dumps({"solver": "highs", "highspy": version}), flush=True)
    for r in range(1, a.upto + 1):
        sat, mine = load_table(a.sat_table), load_table(a.table)
        table = {**mine, **sat}
        if r in table:
            print(json.dumps({"kind": a.kind, "width": "512", "rounds": r, unit: table[r],
                              "solver": "sat" if r in sat else "highs", "cached": True}), flush=True)
            continue
        t0 = time.time()
        _COLUMNS.clear()
        m = weighted_model(a.kind, r, w)[0] if w else build(a.kind, 512, r)
        k = solve(m, r, table, a.threads, a.log)
        mine = {**load_table(a.table), r: k}
        save_table(a.table, mine)
        print(json.dumps({"kind": a.kind, "width": "512", "rounds": r, unit: k, "solver": "highs",
                          "lower_bound_from_windows": split_bound(r, table),
                          "secs": round(time.time() - t0, 1)}), flush=True)


if __name__ == "__main__":
    sys.exit(main())


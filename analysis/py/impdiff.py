#!/usr/bin/env python3
"""Section C: related-constant impossible differentials between P1 and P2.
SoEM22 outputs P1(u ^ k1) ^ P2(u ^ k2) ^ k1 ^ k2, i.e. the 'difference'
between P1 and P2 on inputs that differ by delta = k1 ^ k2. A byte of
P1(x) ^ P2(x ^ delta) that can never be zero (for an r-round truncated
trail) would be a distinguisher. Checked with the byte-activity model
(model.py, mode related: Delta_r added every round), for delta free and
for delta with every byte active: UNSAT means no truncated trail has
that output byte inactive."""
import argparse
import concurrent.futures
import json
import multiprocessing as mp
import os
import sys
from model import build
from pysat.solvers import Solver


def _solve_cell(task):
    width, r, dmode = task
    nb = width // 128
    m, rec = build(width, r, [0xFFFF] * 15)
    inp = list(range(1, 16 * nb + 1))
    if dmode == 'full':
        m.cl += [[v] for v in inp]
    fin = rec[-1]
    outv = sum((fin[f'x{i}'] for i in range(nb)), [])
    unsat = []
    with Solver(name='cadical153', bootstrap_with=m.cl) as s:
        for j, v in enumerate(outv):
            if not s.solve(assumptions=[-v]):
                unsat.append(j)
        allzero_sat = s.solve(assumptions=[-v for v in outv])
    return {
        'width': width, 'rounds': r, 'delta': dmode,
        'output bytes that cannot be inactive': unsat,
        'all-zero output admitted': allzero_sat,
    }


def main():
    default_jobs = int(os.environ.get("AREION_THREADS", max(1, (os.cpu_count() or 2) - 2)))
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("limits", nargs="*", type=int, help="optional [r256 r512] round limits")
    ap.add_argument("--jobs", type=int, default=default_jobs)
    ap.add_argument("--threads", type=int, default=default_jobs)
    a = ap.parse_args()
    limits = a.limits[:2] if len(a.limits) >= 2 else [10, 15]
    workers = max(1, a.threads if a.threads != default_jobs else a.jobs)
    tasks = [
        (width, r, dmode)
        for width, R in ((256, limits[0]), (512, limits[1]))
        for r in range(1, R + 1)
        for dmode in ('free', 'full')
    ]
    ctx = mp.get_context("fork")
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as ex:
        for rec_ in ex.map(_solve_cell, tasks):
            print(json.dumps(rec_), flush=True)


if __name__ == "__main__":
    main()


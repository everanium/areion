#!/usr/bin/env python3
"""Section C: related-constant impossible differentials between P1 and P2.
SoEM22 outputs P1(u ^ k1) ^ P2(u ^ k2) ^ k1 ^ k2, i.e. the 'difference'
between P1 and P2 on inputs that differ by delta = k1 ^ k2. A byte of
P1(x) ^ P2(x ^ delta) that can never be zero (for an r-round truncated
trail) would be a distinguisher. Checked with the byte-activity model
(model.py, mode related: Delta_r added every round), for delta free and
for delta with every byte active: UNSAT means no truncated trail has
that output byte inactive."""
import json
import sys
from model import build
from pysat.solvers import Solver

out = []
limits = [int(v) for v in sys.argv[1:3]] if len(sys.argv) >= 3 else [10, 15]
for width, R in ((256, limits[0]), (512, limits[1])):
    nb = width // 128
    for r in range(1, R + 1):
        for dmode in ('free', 'full'):
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
            rec_ = {'width': width, 'rounds': r, 'delta': dmode,
                    'output bytes that cannot be inactive': unsat,
                    'all-zero output admitted': allzero_sat}
            print(json.dumps(rec_), flush=True)
            out.append(rec_)

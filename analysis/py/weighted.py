#!/usr/bin/env python3
"""Weighted trail bounds of Areion-512, charging the S-box chain of F3 by
its exact correlation or probability instead of the product rule.

In F3 of Areion-512 (F3,r(x) = F0(F1(x) ^ k_r), notation of Frank Denis,
ePrint 2026/1935) a byte of the word c passes through two S-boxes in
series, y = S(x) and z = S(y ^ k), with nothing between them but a
round-constant byte k; y also feeds F0(c). It is the only place in
Areion where two S-boxes meet that way: elsewhere a byte passes from one
S-box to the next through MixColumns or through an XOR with another word
of the state. A constant does not randomise the value between the two
S-boxes: the linear correlation of the chain sums over its middle mask
(Denis, section 4.1), and a differential of the chain holds for the two
inputs that satisfy both transitions at once (section 3.2), neither of
which the per-S-box rule sees. Where an XOR with another word sits in
between, the per-S-box treatment rests on the usual Markov heuristic,
as everywhere else in these models. The models of trails.py count
such a chain as two active S-boxes, and the product rule turns that into
2^-6 (linear, correlation) or 2^-12 (differential). The exact values over
every constant byte (Go subcommand chain; Frank Denis, ePrint 2026/1935,
sections 3.2 and 4) are larger:

  linear, both S-boxes active, summed over the mask on y ^ k: |C| <= 3/8
      (11/32 without the F0 branch), about 2^-1.42;
  differential, one table: 2^-7 for the pair of S-boxes;
  differential, P1 against P2 (k1 != k2): 2^-6, no more than one S-box.

Every value is rounded down to whole bits, so the weights can only lower
the bounds. Each round's cost is charged on its own literals:

  linear   S-box of a (shared by F0 and F1): 3 bits; chain with one
           S-box active: 3 bits; chain with both active: 1 bit (the
           exact 1.42 rounded down);
  single   S-box of a: 6 bits; active chain (both S-boxes are active
           together in one permutation): 7 bits;
  related  S-box of a: 6 bits; active chain, one or both S-boxes: 6 bits.

The weighted minimum over r rounds is the smallest number of bits of a
trail of the model; its window bounds, and the descent of bounds.py, carry
over unchanged, since the weights are local to a round and do not depend
on the constants. Areion-256 has no such chain (its round constant sits
between the two halves of F2, with MixColumns in between) and keeps the
counts of trails.py.

From the tables the script prints the weighted counterparts of sections H
and I of the README: the known-input estimate of a linear relation
between P1 and P2 over 15 rounds, and the boomerang estimates of
Areion-512 under the four assignments of the tables.

    python3 analysis/py/weighted.py --weights CHAIN_JSON --prefix PREFIX
                                    [--linear R] [--single R] [--related R] [--start R]
The tables are read from and written to PREFIX + <kind>.json; --start R
searches only rounds R and up, so that a long round can run beside the
process filling the shorter ones.
"""
import argparse
import json
import sys
import time

from pysat.card import ITotalizer
from pysat.solvers import Solver

import boomerang
from bounds import SOLVER, add_windows, load_table, save_table, split_bound
from wmodel import weighted_model, weights


def descend(kind, rounds, w, table, hint, log):
    """bounds.descend on the weighted model. hint = (plain literals, k): the
    first trail is sought among those with at most k active S-boxes, so
    that the weighted counter starts from a small bound."""
    t0 = time.time()
    m, plain = weighted_model(kind, rounds, w)
    lb = split_bound(rounds, table)
    add_windows(m, rounds, table)
    with Solver(name=SOLVER, bootstrap_with=m.cl) as s:
        def cost():
            model_ = set(l for l in s.get_model() if l > 0)
            return [sum(1 for v in r if v in model_) for r in m.rounds]
        sat = False
        if hint is not None:
            tot0 = ITotalizer(lits=plain, ubound=hint + 1, top_id=max(m.nv, s.nof_vars()))
            s.append_formula(tot0.cnf.clauses)
            sat = s.solve(assumptions=[-tot0.rhs[hint]] if hint < len(tot0.rhs) else [])
        if not sat and not s.solve():
            raise SystemExit("model has no trail at all")
        witness = cost()
        best = sum(witness)
        if log:
            log(f"  first trail: {best} bits ({time.time() - t0:.1f} s)")
        tot = ITotalizer(lits=m.sboxes, ubound=best, top_id=max(m.nv, s.nof_vars()))
        s.append_formula(tot.cnf.clauses)
        while best > lb:
            t = time.time()
            sat = s.solve(assumptions=[-tot.rhs[best - 1]])
            if log:
                log(f"  bits<={best - 1}: {'SAT' if sat else 'UNSAT'} ({time.time() - t:.1f} s)")
            if not sat:
                break
            witness = cost()
            best = sum(witness)
    return dict(min_bits=best, lower_bound_from_windows=lb, witness=witness, secs=round(time.time() - t0, 1))


def fill(kind, upto, w, path, plain_table, log, start=1):
    """Rounds start .. upto missing from the table; another process may fill
    other rounds of the same table, so each result is merged into the table
    as it is on disk."""
    table = load_table(path)
    for r in range(start, upto + 1):
        if r in table:
            res = dict(min_bits=table[r], cached=True)
        else:
            res = descend(kind, r, w, table, plain_table.get(r), log)
            table = {**load_table(path), **table, r: res["min_bits"]}
            save_table(path, table)
        print(json.dumps({"kind": kind, "width": "512", "rounds": r, **res}), flush=True)
    return load_table(path)


def report(lin, single, related):
    if lin:
        b = boomerang.Table(lin)
        k = b.get(15)
        star = "*" if b.lowered else ""
        print(f"== linear, Areion-512, 15 rounds: at least {k}{star} bits per permutation; no term of a "
              f"linear relation between P1 and P2 (one trail through each) exceeds 2^-{2 * k} "
              f"(threshold 2^-171, the correlation 2^341 known inputs detect)")
    if not single or not related:
        return
    # estimate() charges 2 * W_BITS per unit and pair; the tables here are in bits
    boomerang.W_BITS = 1
    tables = {"single": boomerang.Table(single), "related": boomerang.Table(related)}
    print("== boomerang estimates, Areion-512, weighted halves (threshold 2^-341)")
    head = "".join(f" {name:>9} {'split':>8}" for name in ("strict", "1 free", "2 free"))
    print(f"   {'top / bottom':18} {'R':>3}{head}")
    for top in ("single", "related"):
        for bot in ("single", "related"):
            for R in range(2, 16):
                cells = ""
                for free in (0, 1, 2):
                    e, arg = boomerang.estimate(R, tables[top].get, lambda s_, r: tables[bot].get(r), free)
                    mark = ""
                    if e is not None:
                        for t in tables.values():
                            t.lowered = False
                        tables[top].get(arg[0])
                        tables[bot].get(arg[1])
                        mark = "*" if any(t.lowered for t in tables.values()) else ""
                    cells += f" {('-' if e is None else f'2^-{e}') + mark:>9} {str(arg or '-'):>8}"
                print(f"   {top + ' / ' + bot:18} {R:>3}{cells}", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--weights", required=True, help="JSON output of the Go subcommand chain")
    ap.add_argument("--prefix", required=True, help="path prefix of the weighted tables")
    ap.add_argument("--plain-prefix", help="path prefix of the tables of bounds.py, for the first trail")
    ap.add_argument("--linear", type=int, default=0, help="rounds of the linear table")
    ap.add_argument("--single", type=int, default=0, help="rounds of the single-permutation table")
    ap.add_argument("--related", type=int, default=0, help="rounds of the related-constant table")
    ap.add_argument("--start", type=int, default=1,
                    help="first round to search; shorter missing rounds are left to another process")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    w = weights(json.load(open(a.weights)))
    print(json.dumps({"weights_bits": w}), flush=True)
    log = None if a.quiet else (lambda s: print(s, file=sys.stderr, flush=True))
    tabs = {}
    for kind, upto in (("linear", a.linear), ("single", a.single), ("related", a.related)):
        plain = load_table(f"{a.plain_prefix}{kind}_512.json") if a.plain_prefix else {}
        path = f"{a.prefix}{kind}.json"
        sat = fill(kind, upto, w, path, plain, log, a.start) if upto else load_table(path)
        milp = load_table(f"{a.prefix}{kind}_milp.json")    # rounds settled by milp.py, if any
        tabs[kind] = {**milp, **sat}
        if tabs[kind]:
            row = " ".join(f"{r}:{v}{'m' if r not in sat else ''}" for r, v in sorted(tabs[kind].items()))
            print(f"== weighted {kind}, Areion-512, bits per round count (m: HiGHS): {row}", flush=True)
    report(tabs["linear"], tabs["single"], tabs["related"])

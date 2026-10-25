#!/usr/bin/env python3
"""Boomerang estimates for quartets under the four assignments of the two
constant tables, from bounds on the number of active S-boxes of the two
halves.

The pair (P1, P2) is treated as public permutations with inverses, the
setting in which their independence is assumed; the SoEM22 interface
offers neither inverses nor the permutations individually. The only
"keys" are the two constant tables, so a quartet takes, in each half,
either the same permutation for both pairs (table difference 0: a
differential of one permutation, kind single) or P1 against P2 (table
difference Delta: the related-constant model, kind related). The four
(top, bottom) combinations are evaluated; single / single is the
ordinary boomerang on one permutation, the reference case.

For R rounds split into a top of r1 rounds and a bottom of r2 rounds, the
estimate of the boomerang probability is 2^(-2 * 6 * (B_top(r1) + B_bot(r2))):
B = minimum number of active S-boxes of the half, 2^-6 = the maximum
differential probability of the AES S-box, the product over S-boxes and
over the two pairs of each half. The product rule is a heuristic, not a
bound (section G), and so is the estimate: it ignores the gain and the
incompatibilities of the switch between the halves. Three variants:
  strict      r1 + r2 = R, the switch costs nothing extra;
  1 free      r1 + r2 = R - 1, one whole middle round is free: a round is
              exactly free for a quartet when both differences are
              inactive on the words that feed its S-boxes;
  2 free      r1 + r2 = R - 2, two free middle rounds, a sensitivity check.
Splits with an empty half reduce to a differential of the other half and
are not listed. A value 2^-0 means that the model gives no bound for
that split, not that a quartet is known.

A length missing from a table is replaced by the window lower bound of
bounds.py (the largest sum of known minima over a split into shorter
windows); a smaller count only raises the estimate. Estimates that use
such a value are marked with *.

The bottom half starts at round r1. For the coarse models B depends on
the length only; for the refined Areion-256 related-constant model
(refined.py, both RC7 forms of P2) it is computed for the actual rounds.

    python3 analysis/py/boomerang.py --prefix PREFIX [--width 256|512] [--refined]
The tables written by bounds.py are read from PREFIX + single_<width>.json
and PREFIX + related_<width>.json.
"""
import argparse
import concurrent.futures
import json
import multiprocessing as mp
import os
import sys

from bounds import split_bound
from model import minimise
from paths import feas_path

W_BITS = 6
ROUNDS = {256: 10, 512: 15}


def load(path):
    if not os.path.exists(path):
        return {}
    return {int(k): v for k, v in json.load(open(path)).items()}


class Table:
    """Known minima; a missing length gets the window lower bound."""

    def __init__(self, known):
        self.known = known
        self.lowered = False

    def get(self, r):
        if r in self.known:
            return self.known[r]
        if not self.known or r < 1:
            return None
        self.lowered = True
        return split_bound(r, self.known)


_refined_cache = {}
_feas_data = None


def _solve_refined_task(task):
    variant, start, length = task
    import refined
    global _feas_data
    if _feas_data is None:
        _feas_data = json.load(open(feas_path()))
    m, _ = refined.build(length, _feas_data[variant][start:start + length])
    k, _ = minimise(m, 400)
    return task, k


def prefill_refined(workers):
    global _feas_data
    _feas_data = json.load(open(feas_path()))
    tasks = [
        (variant, start, length)
        for variant in ("pi", "shift")
        for start in range(10)
        for length in range(1, 10 - start)
        if (variant, start, length) not in _refined_cache
    ]
    if not tasks:
        return
    if workers <= 1:
        for t in tasks:
            k_key, val = _solve_refined_task(t)
            _refined_cache[k_key] = val
        return
    ctx = mp.get_context("fork")
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as ex:
        for k_key, val in ex.map(_solve_refined_task, tasks):
            _refined_cache[k_key] = val


def refined_min(variant, start, length):
    """Refined related-constant minimum of Areion-256 over rounds start .. start+length-1."""
    key = (variant, start, length)
    if key not in _refined_cache:
        _, k = _solve_refined_task(key)
        _refined_cache[key] = k
    return _refined_cache[key]


def estimate(R, btop, bbot, free):
    """Smallest exponent over the splits with free middle rounds; btop(r1)
    and bbot(start, r2) return a bound or None when unknown."""
    best, arg = None, None
    span = R - free
    if span < 2:
        return None, None
    for r1 in range(1, span):
        r2 = span - r1
        start = r1 + free
        a, b = btop(r1), bbot(start, r2)
        if a is None or b is None:
            return None, None
        e = 2 * W_BITS * (a + b)
        if best is None or e < best:
            best, arg = e, (r1, r2)
    return best, arg


def main():
    default_jobs = int(os.environ.get("AREION_THREADS", max(1, (os.cpu_count() or 2) - 2)))
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prefix", required=True, help="path prefix of the bounds tables")
    ap.add_argument("--width", type=int, choices=(256, 512))
    ap.add_argument("--refined", action="store_true", help="Areion-256 related halves from refined.py, both RC7 forms")
    ap.add_argument("--jobs", type=int, default=default_jobs)
    ap.add_argument("--threads", type=int, default=default_jobs)
    a = ap.parse_args()
    workers = max(1, a.threads if a.threads != default_jobs else a.jobs)
    for width in ([a.width] if a.width else [256, 512]):
        single = Table(load(f"{a.prefix}single_{width}.json"))
        related = Table(load(f"{a.prefix}related_{width}.json"))
        variants = [None]
        if width == 256 and a.refined:
            prefill_refined(workers)
            variants = ["pi", "shift"]
        for variant in variants:
            def rel_top(r1, variant=variant):
                return refined_min(variant, 0, r1) if variant else related.get(r1)

            def rel_bot(start, r2, variant=variant):
                return refined_min(variant, start, r2) if variant else related.get(r2)

            halves = {"single": (lambda r: single.get(r), lambda s, r: single.get(r)),
                      "related": (rel_top, rel_bot)}
            tag = f"Areion-{width}" + (f", related halves refined, RC7 of P2 {variant}" if variant else "")
            print(f"== {tag}")
            head = "".join(f" {name:>9} {'split':>8}" for name in ("strict", "1 free", "2 free"))
            print(f"   {'top / bottom':18} {'R':>3}{head}")
            fmt = lambda e: "-" if e is None else f"2^-{e}"
            for top in ("single", "related"):
                for bot in ("single", "related"):
                    for R in range(2, ROUNDS[width] + 1):
                        cells = ""
                        for free in (0, 1, 2):
                            e, arg = estimate(R, halves[top][0], halves[bot][1], free)
                            mark = ""
                            if e is not None:     # was a window lower bound used in the chosen split?
                                single.lowered = related.lowered = False
                                halves[top][0](arg[0])
                                halves[bot][1](arg[0] + free, arg[1])
                                mark = "*" if single.lowered or related.lowered else ""
                            cells += f" {fmt(e) + mark:>9} {str(arg or '-'):>8}"
                        print(f"   {top + ' / ' + bot:18} {R:>3}{cells}", flush=True)
            sys.stdout.flush()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Minimum number of active S-boxes for truncated trail models of Areion,
with two additions to the SAT search that leave the result unchanged.

Models (KIND, built by trails.py):
  linear         linear trails, shared S-box layer counted once      (linear.py)
  linear-double  the same, the shared layer counted once per branch  (linear.py --double)
  single         differential trails of one permutation             (model.py, zero Delta)
  related        related-constant differential trails P1(u) vs P2(u ^ delta),
                 Delta_r nonzero in every byte (model.py, coarse model)
WIDTH is aes (plain AES rounds; linear and single only), 256 or 512.

Window bounds (Matsui-style conditions). If B(w) is the minimum for w
rounds, every w consecutive rounds of an R-round trail carry at least B(w)
active S-boxes: the constraints of the models are local to a round, so the
restriction of a trail to a window is a trail of the window, and the round
function is the same in every round up to renaming the words (period 2 for
Areion-256, 4 for Areion-512; the coarse related model adds a nonzero
Delta in every byte of every round), so B depends on the length of the
window only. The script reads B(w) for w < R from a table it fills itself
(--table) and adds "at least B(w)" for every window; the lower bound
obtained by splitting R into windows is where the search starts. Not
valid for the refined Areion-256 model, whose constraints depend on the
round (refined.py), and not used for it.

Cube-and-conquer (--jobs N > 1). The proof that k active S-boxes are not
reachable is split by the exact number of active S-boxes in the rounds
given by --cube (default: the middle round): every cube adds "exactly v"
for its round(s), the cubes over all v cover every trail, and each is
solved by one of N processes, each keeping one solver whose learnt clauses
carry over between its cubes and between values of k. k is reachable iff
some cube is satisfiable. A single solver runs alone for --budget seconds
(it finds trails quickly; the last, unsatisfiable step is the slow one)
and keeps running beside the cubes; whichever side finishes first gives
the result, and a better trail found by either side moves both on. On
the linear Areion-512 cells of 5 and 6 rounds this split saves little or
nothing against the single solver.

Rounds at once (--upto with --rounds-at-once N). The missing rounds of
the table are searched at the same time, one solver each; a round that
starts before a shorter one has finished has fewer window conditions,
which makes it slower but leaves its minimum unchanged.

    python3 analysis/py/bounds.py KIND WIDTH ROUNDS [--table FILE] [--jobs N] [--budget S] [--cube R1,R2]
                                  [--cubes-only] [--no-windows]
    python3 analysis/py/bounds.py KIND WIDTH --upto ROUNDS --table FILE [--jobs N | --rounds-at-once N]
"""
import argparse
import itertools
import json
import multiprocessing as mp
import os
import signal
import sys
import time

from pysat.card import CardEnc, EncType, ITotalizer
from pysat.solvers import Solver

from trails import build

SOLVER = os.environ.get("AREION_SAT", "cadical195")


# ---------------------------------------------------------------- windows

def at_least_prefix(m, lits, targets):
    """Counter over lits with s[i][j] -> 'at least j of lits[:i] are true';
    asserts s[i][j] for every (i, j) in targets. Only the direction needed
    for soundness is encoded: s[i][j] implies its justification."""
    jmax = max(j for _, j in targets)
    prev = {0: None}                          # j -> literal for prefix i-1 (None: true for j = 0)
    level = []
    for i, x in enumerate(lits, start=1):
        cur = {0: None}
        for j in range(1, min(i, jmax) + 1):
            s = m.new(1)[0]
            cur[j] = s
            # s -> prev[j] or x
            c1 = [-s, x]
            if j in prev and prev[j] is not None:
                c1.append(prev[j])
            m.cl.append(c1)
            # s -> prev[j] or prev[j-1]
            if prev.get(j - 1) is not None:
                c2 = [-s, prev[j - 1]]
                if prev.get(j) is not None:
                    c2.append(prev[j])
                m.cl.append(c2)
        level.append(cur)
        prev = cur
    for i, j in targets:
        if j <= 0:
            continue
        lit = level[i - 1].get(j)
        if lit is None:                       # j > i: unreachable, the model is empty
            f = m.new(1)[0]                   # an explicit contradiction (an empty clause
            m.cl += [[f], [-f]]               # is rejected by some solvers)
        else:
            m.cl.append([lit])


def add_windows(m, rounds, table):
    """'At least B(w)' for every window of w < rounds consecutive rounds."""
    used = 0
    for s in range(rounds):
        lits, ends, targets = [], [], []
        for w in range(1, rounds - s + 1):
            lits += m.rounds[s + w - 1]
            if w < rounds and table.get(w, 0) > 0:
                targets.append((len(lits), table[w]))
        if targets:
            at_least_prefix(m, lits, targets)
            used += len(targets)
    return used


def split_bound(rounds, table):
    """Largest sum of window bounds over a split of the rounds into windows."""
    best = [0] * (rounds + 1)
    for r in range(1, rounds + 1):
        for w in range(1, r + 1):
            if w < rounds and w in table:
                best[r] = max(best[r], best[r - w] + table[w])
    return best[rounds]


# ---------------------------------------------------------------- cubes

_W = {}                                       # per-process state


def _default_sigterm():
    """Worker processes end on SIGTERM at once (the parent's handler unwinds)."""
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


def _worker_init(kind, width, rounds, table, windows, cube_rounds, ubound, target):
    _default_sigterm()
    m = build(kind, width, rounds)
    if windows:
        add_windows(m, rounds, table)
    tot = ITotalizer(lits=m.sboxes, ubound=ubound, top_id=m.nv)
    m.nv = max(m.nv, tot.top_id)
    s = Solver(name=SOLVER, bootstrap_with=m.cl + tot.cnf.clauses)
    _W.update(m=m, s=s, rhs=tot.rhs, cube_rounds=cube_rounds, target=target)


def _worker_cube(task):
    """Solves one cube under 'at most k active S-boxes'. A task whose k is
    above the current target (a trail with fewer S-boxes was found
    meanwhile) is skipped: it can only repeat that finding."""
    values, k = task
    m, s, rhs, cube_rounds = _W["m"], _W["s"], _W["rhs"], _W["cube_rounds"]
    if k > _W["target"].value:
        return values, k, None, None
    sel = m.nv + 1
    m.nv += 1
    top = m.nv
    for r, v in zip(cube_rounds, values):
        enc = CardEnc.equals(lits=m.rounds[r], bound=v, top_id=top, encoding=EncType.seqcounter)
        top = max(top, enc.nv)
        for c in enc.clauses:
            s.add_clause(c + [-sel])
    m.nv = top
    assumptions = [sel] + ([-rhs[k]] if k < len(rhs) else [])
    sat = s.solve(assumptions=assumptions)
    witness = None
    if sat:
        model_ = set(l for l in s.get_model() if l > 0)
        witness = [sum(1 for v in r if v in model_) for r in m.rounds]
    s.add_clause([-sel])                      # retire this cube's constraints
    return values, k, sat, witness


def cubes_for(sizes, lo, k):
    cubes = [v for v in itertools.product(*[range(lo, min(n, k) + 1) for n in sizes]) if sum(v) <= k]
    cubes.sort(key=sum)
    return cubes


def descend_cubes(kind, width, rounds, table, windows, best, witness, lb, jobs, cube_rounds, child, log):
    """Proves that best - 1 active S-boxes are unreachable by cubes over a
    pool of jobs processes, while the single solver of child (descend in
    a process, see start_descend) keeps looking for better trails. A better
    trail from either side lowers the target: cubes still queued for the
    old target are skipped. Returns (minimum, witness, number of cubes
    solved)."""
    m = build(kind, width, rounds)
    sizes = [len(m.rounds[r]) for r in cube_rounds]
    lo = table.get(1, 0) if windows else 0
    ubound = best if best is not None else len(m.sboxes)
    ctx = mp.get_context("fork")
    target = ctx.Value("i", ubound, lock=False)
    solved = 0
    with ctx.Pool(jobs, initializer=_worker_init,
                  initargs=(kind, width, rounds, table, windows, cube_rounds, ubound, target)) as pool:
        while True:
            k = best - 1 if best is not None else ubound
            if k < lb:
                return best, witness, solved
            target.value = k
            cubes = cubes_for(sizes, lo, k)
            it = pool.imap_unordered(_worker_cube, [(v, k) for v in cubes])
            t0, done, unsat = time.time(), 0, 0
            while done < len(cubes):
                try:
                    values, kk, sat, wit = it.next(timeout=1)
                    done += 1
                    if sat is not None:
                        solved += 1
                    if sat is False:
                        unsat += 1
                        if log and (unsat % max(1, len(cubes) // 10) == 0 or unsat == len(cubes)):
                            log(f"  k<={k}: {unsat}/{len(cubes)} cubes UNSAT ({time.time() - t0:.0f} s)")
                    elif sat and (best is None or sum(wit) < best):
                        best, witness = sum(wit), wit
                        if log:
                            log(f"  k<={k}: cube SAT, {best} active S-boxes ({time.time() - t0:.0f} s)")
                except mp.TimeoutError:
                    pass
                for b, w, fin in (child.poll() if child else []):
                    if fin:
                        if log:
                            log(f"  single solver finished: {b}")
                        return b, w, solved
                    if best is None or b < best:
                        best, witness = b, w
                        if log:
                            log(f"  single solver: {best} active S-boxes")
                if best is not None and best - 1 < k:
                    break                     # restart at the new target; queued cubes are skipped
            else:
                if unsat != len(cubes):           # every cube of this k answered, none SAT
                    raise SystemExit(f"cube accounting failed at k={k}: {unsat} of {len(cubes)} UNSAT")
                if log:
                    log(f"  k<={k}: UNSAT over {len(cubes)} cubes ({time.time() - t0:.0f} s)")
                if best is None:
                    return None, None, solved
                return best, witness, solved


# ---------------------------------------------------------------- search

def descend(kind, width, rounds, table, windows, lb, log, report=None):
    """One incremental solver: find any trail, then demand fewer active
    S-boxes than the best found until that is unsatisfiable. Returns
    (minimum, witness, windows used); the minimum is also settled when the
    best count meets the window lower bound lb. report(best, witness, done)
    is called after every improvement and at the end."""
    m = build(kind, width, rounds)
    used = add_windows(m, rounds, table) if windows else 0
    with Solver(name=SOLVER, bootstrap_with=m.cl) as s:
        def count():
            model_ = set(l for l in s.get_model() if l > 0)
            return [sum(1 for v in r if v in model_) for r in m.rounds]
        t = time.time()
        if not s.solve():
            raise SystemExit("model has no trail at all")
        witness = count()
        best = sum(witness)
        if log:
            log(f"  first trail: {best} active S-boxes ({time.time() - t:.1f} s)")
        if report:
            report(best, witness, False)
        tot = ITotalizer(lits=m.sboxes, ubound=best, top_id=max(m.nv, s.nof_vars()))
        s.append_formula(tot.cnf.clauses)
        while best > lb:
            t = time.time()
            sat = s.solve(assumptions=[-tot.rhs[best - 1]])
            if log:
                log(f"  k<={best - 1}: {'SAT' if sat else 'UNSAT'} ({time.time() - t:.1f} s)")
            if not sat:
                break
            witness = count()
            best = sum(witness)
            if report:
                report(best, witness, False)
        if report:
            report(best, witness, True)
        return best, witness, used


def _descend_child(q, args):
    _default_sigterm()
    kind, width, rounds, table, windows, lb, quiet = args
    log = None if quiet else (lambda x: print(x, file=sys.stderr, flush=True))
    descend(kind, width, rounds, table, windows, lb, log,
            report=lambda b, w, d: q.put((b, w, d)))


class Child:
    """descend() in a child process (CaDiCaL cannot be interrupted, a
    process can be terminated); its improvements arrive through a queue."""

    def __init__(self, kind, width, rounds, table, windows, lb, quiet):
        ctx = mp.get_context("fork")
        self.q = ctx.Queue()
        self.p = ctx.Process(target=_descend_child,
                             args=(self.q, (kind, width, rounds, table, windows, lb, quiet)), daemon=True)
        self.p.start()

    def poll(self, timeout=0):
        """Reports (best, witness, finished) received so far; waits up to
        timeout seconds for the first one."""
        out = []
        try:
            out.append(self.q.get(timeout=timeout) if timeout else self.q.get_nowait())
            while True:
                out.append(self.q.get_nowait())
        except Exception:                     # queue.Empty
            pass
        if not out and not self.p.is_alive() and self.p.exitcode not in (0, None):
            raise SystemExit(f"descend process failed (exit code {self.p.exitcode})")
        return out

    def stop(self):
        if self.p.is_alive():
            self.p.terminate()
        self.p.join()


def minimum(kind, width, rounds, table, windows=True, jobs=1, cube_rounds=None, log=None, budget=120,
            cubes_only=False):
    """jobs = 1: one incremental solver (descend). jobs > 1: the same solver
    in a child process; if it has not finished after budget seconds, the
    proof that best - 1 is unreachable is split into cubes over the jobs
    while the child keeps descending. cubes_only: no single solver, the
    whole search runs on cubes (a check of the cube path)."""
    t0 = time.time()
    lb = split_bound(rounds, table) if windows else 0
    used = add_windows(build(kind, width, rounds), rounds, table) if windows else 0
    if jobs <= 1:
        k, witness, used = descend(kind, width, rounds, table, windows, lb, log)
        return dict(min_active_sboxes=k, lower_bound_from_windows=lb, windows=used,
                    cubes=0, witness=witness, secs=round(time.time() - t0, 1))
    if cube_rounds is None:
        cube_rounds = [rounds // 2]
    if cubes_only:
        k, witness, solved = descend_cubes(kind, width, rounds, table, windows, None, None, lb,
                                           jobs, cube_rounds, None, log)
        if k is None:
            raise SystemExit("model has no trail at all")
        return dict(min_active_sboxes=k, lower_bound_from_windows=lb, windows=used,
                    cubes=solved, cube_rounds=cube_rounds, jobs=jobs, witness=witness,
                    secs=round(time.time() - t0, 1))
    child = Child(kind, width, rounds, table, windows, lb, log is None)
    try:
        best, witness, deadline = None, None, time.time() + budget
        while time.time() < deadline:
            for b, w, fin in child.poll(timeout=min(1.0, max(0.01, deadline - time.time()))):
                best, witness = b, w
                if fin:
                    return dict(min_active_sboxes=b, lower_bound_from_windows=lb, windows=used,
                                cubes=0, witness=w, secs=round(time.time() - t0, 1))
        if log:
            log(f"  {budget} s: {best} active S-boxes so far; cubes from here on")
        k, witness, solved = descend_cubes(kind, width, rounds, table, windows, best, witness, lb,
                                           jobs, cube_rounds, child, log)
    finally:
        child.stop()
    if k is None:
        raise SystemExit("model has no trail at all")
    return dict(min_active_sboxes=k, lower_bound_from_windows=lb, windows=used,
                cubes=solved, cube_rounds=cube_rounds, jobs=jobs, witness=witness,
                secs=round(time.time() - t0, 1))


def load_table(path):
    if path and os.path.exists(path):
        return {int(k): v for k, v in json.load(open(path)).items()}
    return {}


def save_table(path, table):
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump({str(k): v for k, v in sorted(table.items())}, f)
    os.replace(tmp, path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kind")
    ap.add_argument("width")
    ap.add_argument("rounds", type=int, nargs="?")
    ap.add_argument("--upto", type=int, help="fill the table for 1 .. UPTO rounds")
    ap.add_argument("--table", help="JSON table of known minima {rounds: value}, read and updated")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--cube", help="comma list of round indices (0-based) to split on")
    ap.add_argument("--no-windows", action="store_true")
    ap.add_argument("--budget", type=float, default=120,
                    help="with --jobs > 1: seconds of the single solver alone before cubes join it")
    ap.add_argument("--cubes-only", action="store_true",
                    help="with --jobs > 1: no single solver, the whole search on cubes (checks the cube path)")
    ap.add_argument("--rounds-at-once", type=int, default=1,
                    help="with --upto: search this many missing rounds at the same time, one solver each")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    # SIGTERM (as from timeout) unwinds like Ctrl-C, so the finally blocks
    # stop the solver processes instead of leaving them running. A single
    # solver in this process has no children to stop and would delay a
    # Python handler until its current solve returns (hours on long cells),
    # so it keeps the default action.
    if a.jobs > 1 or a.rounds_at_once > 1:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    width = a.width if a.width == "aes" else int(a.width)
    table = load_table(a.table)
    log = None if a.quiet else (lambda s: print(s, file=sys.stderr, flush=True))
    cube = [int(x) for x in a.cube.split(",")] if a.cube else None
    if a.rounds_at_once > 1 and not a.upto:
        raise SystemExit("--rounds-at-once needs --upto")

    def done(r, res):
        res = {"kind": a.kind, "width": a.width, "rounds": r, **res}
        print(json.dumps(res), flush=True)
        if a.table and res.get("min_active_sboxes") is not None and not a.no_windows:
            table[r] = res["min_active_sboxes"]
            # merged with the file, which another process may have extended meanwhile
            save_table(a.table, {**load_table(a.table), **table})

    todo = range(1, a.upto + 1) if a.upto else [a.rounds]
    for r in todo:
        if a.upto and r in table:
            print(json.dumps({"kind": a.kind, "width": a.width, "rounds": r, "min_active_sboxes": table[r],
                              "cached": True}), flush=True)
    pending = [r for r in todo if not (a.upto and r in table)]
    if a.rounds_at_once > 1:
        # Rounds in parallel, each on one solver. A round started before a
        # shorter one finished searches with fewer window conditions, which
        # leaves its minimum unchanged.
        # A pool, not an executor: Pool.terminate() stops solvers in mid-solve
        # on an error or a signal, an executor waits for them.
        pool = mp.get_context("fork").Pool(a.rounds_at_once, initializer=_default_sigterm)
        try:
            running = {}
            while pending or running:
                while pending and len(running) < a.rounds_at_once:
                    r = pending.pop(0)
                    running[r] = pool.apply_async(minimum, (a.kind, width, r, dict(table), not a.no_windows,
                                                            1, None, None, a.budget))
                for r in [r for r, res in running.items() if res.ready()]:
                    done(r, running.pop(r).get())
                time.sleep(1)
        finally:
            pool.terminate()
            pool.join()
    else:
        for r in pending:
            done(r, minimum(a.kind, width, r, table, windows=not a.no_windows, jobs=a.jobs,
                            cube_rounds=cube, log=log, budget=a.budget, cubes_only=a.cubes_only))

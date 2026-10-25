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
import fcntl
import itertools
import json
import math
import multiprocessing as mp
import os
import subprocess
import sys
import time

import highspy
import numpy as np
from pysat.card import ITotalizer
from pysat.solvers import Solver

import bounds
import model as model_mod
from model import Model, check_patterns, minimise
from paths import BUILD, feas_path
import refined

SOLVER = os.environ.get("AREION_SAT", "cadical195")
CACHE_PATH = BUILD / "inverse_bounds.json"
CACHE_LOCK = BUILD / "inverse_bounds.lock"
_MP_CTX = mp.get_context("fork")


def _cache_key(label, direction, width, dmode):
    return f"{label}:{direction}:{width}:{dmode}"


def load_bounds_cache(no_cache=False):
    if no_cache:
        return {}
    BUILD.mkdir(exist_ok=True)
    data = {}
    for kind, label, dmode in (
        ("related", "related-coarse", "free"),
        ("single", "single-nonzero", "nonzero"),
    ):
        for width in (256, 512):
            key = _cache_key(label, "fwd", width, dmode)
            found = sorted(BUILD.glob(f"bounds_*_{kind}_{width}.json"), key=lambda p: p.stat().st_mtime)
            if found:
                try:
                    tbl = {int(r): int(v) for r, v in json.load(open(found[-1])).items()}
                    data.setdefault(key, {}).update(tbl)
                except Exception:
                    pass
    if CACHE_PATH.exists():
        try:
            raw = json.load(open(CACHE_PATH))
            for k, tbl in raw.items():
                data.setdefault(k, {}).update({int(r): int(v) for r, v in tbl.items()})
        except Exception:
            pass
    return data


def save_bound_entry(key, r, val, no_cache=False):
    if no_cache:
        return
    BUILD.mkdir(exist_ok=True)
    with open(CACHE_LOCK, "a+") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            raw = {}
            if CACHE_PATH.exists():
                try:
                    raw = json.load(open(CACHE_PATH))
                except Exception:
                    raw = {}
            raw.setdefault(key, {})[str(int(r))] = int(val)
            tmp = CACHE_PATH.with_name(f"{CACHE_PATH.name}.{os.getpid()}.tmp")
            with open(tmp, "w") as f:
                json.dump(
                    {k: {str(rk): rv for rk, rv in sorted(((int(x), y) for x, y in v.items()))}
                     for k, v in sorted(raw.items())},
                    f,
                    indent=2,
                )
            os.replace(tmp, CACHE_PATH)
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)



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


def build_cross_256_coarse(rounds, deltas):
    """Coupled 2r-round differential model of C_r(x) = P2_r^-1(P1_r(x)) on Areion-256."""
    m = Model()
    x = [m.new(), m.new()]
    fwd_rec = []
    states = [x[0] + x[1]]
    for r in range(rounds):
        ai, bi = (0, 1) if r % 2 == 0 else (1, 0)
        A, B = x[ai], x[bi]
        S = m.sr(A)
        m.count(A)
        T1 = m.mc(S)
        T2 = T1
        m.count(T2)
        W = m.mc(m.sr(T2))
        nb = m.xor(W, B)
        fwd_rec.append({"A": A, "B": B, "S": S, "T1": T1, "T2": T2, "W": W, "nb": nb})
        x[ai], x[bi] = S, nb
        states.append(x[0] + x[1])
        m.mark()

    bwd_rec = []
    for r in range(rounds - 1, -1, -1):
        ai, bi = (0, 1) if r % 2 == 0 else (1, 0)
        S, Bp = x[ai], x[bi]
        f = fwd_rec[r]
        if r == rounds - 1:
            A = f["A"]
            T1 = f["T1"]
            T2 = T1
            if deltas[r] != 0:
                m.count(T2)
                W = m.mc(m.sr(T2))
                B = m.xor(Bp, W)
            else:
                W = f["W"]
                B = f["B"]
        else:
            A = isr(S)
            m.count(A)
            T1 = m.mc(S)
            T2 = T1
            m.count(T2)
            W = m.mc(m.sr(T2))
            B = m.xor(Bp, W)
        bwd_rec.append({"S": S, "Bp": Bp, "A": A, "B": B, "T1": T1, "T2": T2, "W": W})
        x[ai], x[bi] = A, B
        states.append(x[0] + x[1])
        m.mark()
    return m, fwd_rec, bwd_rec, states


def build_cross_512_cancelled(rounds, deltas):
    """Coupled 2r-round differential model of C_r(x) = P2_r^-1(P1_r(x)) on Areion-512
    with exact algebraic cancellation of unbranched S-box pairs (SB(a_{r-1}), SB(c2_{r-1})
    at d=1 and SB(c2_{r-2}) at d=2)."""
    m = Model()
    x = [m.new() for _ in range(4)]
    fwd_rec = []
    states = [sum(x, [])]
    for r in range(rounds):
        o = r % 4
        ia, ib, ic, id_ = o, (o + 1) % 4, (o + 2) % 4, (o + 3) % 4
        a, b, c, d = x[ia], x[ib], x[ic], x[id_]
        d_from_top = rounds - r
        if d_from_top == 1 and deltas[r] != 0:
            m.count(c)
            t1 = m.mc(m.sr(a))
            nb = m.xor(b, t1)
            t2 = m.mc(m.sr(c))
            nd = m.xor(d, t2)
            na = m.sr(a)
            c1 = m.sr(c)
            c2 = c1
            cf = m.mc(m.sr(c2))
        elif d_from_top == 2 and deltas[r] != 0 and deltas[r + 1] != 0:
            m.count(a)
            m.count(c)
            t1 = m.mc(m.sr(a))
            nb = m.xor(b, t1)
            t2 = m.mc(m.sr(c))
            nd = m.xor(d, t2)
            na = m.sr(a)
            c1 = m.sr(c)
            c2 = c1
            cf = m.mc(m.sr(c2))
        else:
            m.count(a)
            m.count(c)
            t1 = m.mc(m.sr(a))
            nb = m.xor(b, t1)
            t2 = m.mc(m.sr(c))
            nd = m.xor(d, t2)
            na = m.sr(a)
            c1 = m.sr(c)
            c2 = c1
            m.count(c2)
            cf = m.mc(m.sr(c2))
        fwd_rec.append({
            "a": a, "b": b, "c": c, "d": d, "t1": t1, "t2": t2,
            "na": na, "nb": nb, "nd": nd, "c1": c1, "c2": c2, "cf": cf,
        })
        x[ia], x[ib], x[ic], x[id_] = na, nb, cf, nd
        states.append(sum(x, []))
        m.mark()

    bwd_rec = []
    for r in range(rounds - 1, -1, -1):
        o = r % 4
        ia, ib, ic, id_ = o, (o + 1) % 4, (o + 2) % 4, (o + 3) % 4
        ap, bp, cf, dp = x[ia], x[ib], x[ic], x[id_]
        f = fwd_rec[r]
        d_depth = rounds - r
        if d_depth == 1 and deltas[r] != 0:
            a = f["a"]
            t1 = f["t1"]
            b = f["b"]
            cm = m.sr(f["c2"])
            c2 = f["c2"]
            c1 = c2
            c = f["c"]
            m.count(c)
            t2 = f["t2"]
            d = f["d"]
        elif d_depth == 2 and deltas[r + 1] != 0 and deltas[r] != 0:
            a = f["a"]
            m.count(a)
            t1 = f["t1"]
            b = f["b"]
            cm = m.sr(f["c2"])
            c2 = f["c2"]
            c1 = c2
            c = f["c"]
            m.count(c)
            t2 = f["t2"]
            d = m.xor(dp, t2)
            for j in range(16):
                m.cl += [[-f["d"][j], dp[j], d[j]], [f["d"][j], dp[j], -d[j]]]
        elif d_depth == 3 and deltas[r + 2] != 0:
            a = isr(ap)
            m.count(a)
            t1 = m.mc(ap)
            b = m.xor(bp, t1)
            cm = m.sr(f["c2"])
            c2 = f["c2"]
            m.count(c2)
            c1 = c2
            c = isr(c1)
            m.count(c)
            t2 = m.mc(c1)
            d = m.xor(dp, t2)
        else:
            a = isr(ap)
            m.count(a)
            t1 = m.mc(ap)
            b = m.xor(bp, t1)
            cm = m.mc(cf)
            c2 = isr(cm)
            m.count(c2)
            c1 = c2
            c = isr(c1)
            m.count(c)
            t2 = m.mc(c1)
            d = m.xor(dp, t2)
        bwd_rec.append({
            "ap": ap, "bp": bp, "cf": cf, "dp": dp,
            "a": a, "b": b, "c": c, "d": d, "t1": t1, "t2": t2, "cm": cm, "c2": c2, "c1": c1,
        })
        x[ia], x[ib], x[ic], x[id_] = a, b, c, d
        states.append(sum(x, []))
        m.mark()
    return m, fwd_rec, bwd_rec, states


def build_cross_512_shared(rounds, deltas):
    """Coupled 2r-round differential model of C_r(x) = P2_r^-1(P1_r(x)) on Areion-512
    where shared turnaround S-box layers (SB(a_{r-1}), SB(c2_{r-1}) at d=1 and SB(c2_{r-2})
    at d=2) are counted once rather than cancelled algebraically."""
    m = Model()
    x = [m.new() for _ in range(4)]
    fwd_rec = []
    states = [sum(x, [])]
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
        c2 = c1
        m.count(c2)
        cf = m.mc(m.sr(c2))
        fwd_rec.append({
            "a": a, "b": b, "c": c, "d": d, "t1": t1, "t2": t2,
            "na": na, "nb": nb, "nd": nd, "c1": c1, "c2": c2, "cf": cf,
        })
        x[ia], x[ib], x[ic], x[id_] = na, nb, cf, nd
        states.append(sum(x, []))
        m.mark()

    bwd_rec = []
    for r in range(rounds - 1, -1, -1):
        o = r % 4
        ia, ib, ic, id_ = o, (o + 1) % 4, (o + 2) % 4, (o + 3) % 4
        ap, bp, cf, dp = x[ia], x[ib], x[ic], x[id_]
        f = fwd_rec[r]
        d_depth = rounds - r
        if d_depth == 1:
            a = f["a"]
            t1 = f["t1"]
            b = f["b"]
            cm = m.sr(f["c2"])
            c2 = f["c2"]
            c1 = c2
            if deltas[r] != 0:
                c = isr(c1)
                m.count(c)
                t2 = f["t2"]
                d = f["d"]
            else:
                c = f["c"]
                t2 = f["t2"]
                d = f["d"]
        elif d_depth == 2 and deltas[r + 1] != 0:
            a = f["a"]
            m.count(a)
            t1 = f["t1"]
            b = f["b"]
            cm = m.sr(f["c2"])
            c2 = f["c2"]
            c1 = c2
            if deltas[r] != 0:
                c = f["c"]
                m.count(c)
            else:
                c = f["c"]
            t2 = f["t2"]
            d = m.xor(dp, t2)
        elif d_depth == 3 and deltas[r + 2] != 0:
            a = isr(ap)
            m.count(a)
            t1 = m.mc(ap)
            b = m.xor(bp, t1)
            cm = m.sr(f["c2"])
            c2 = f["c2"]
            m.count(c2)
            c1 = c2
            c = isr(c1)
            m.count(c)
            t2 = m.mc(c1)
            d = m.xor(dp, t2)
        else:
            a = isr(ap)
            m.count(a)
            t1 = m.mc(ap)
            b = m.xor(bp, t1)
            cm = m.mc(cf)
            c2 = isr(cm)
            m.count(c2)
            c1 = c2
            c = isr(c1)
            m.count(c)
            t2 = m.mc(c1)
            d = m.xor(dp, t2)
        bwd_rec.append({
            "ap": ap, "bp": bp, "cf": cf, "dp": dp,
            "a": a, "b": b, "c": c, "d": d, "t1": t1, "t2": t2, "cm": cm, "c2": c2, "c1": c1,
        })
        x[ia], x[ib], x[ic], x[id_] = a, b, c, d
        states.append(sum(x, []))
        m.mark()
    return m, fwd_rec, bwd_rec, states


_CUBE_STATE = None


def _init_cube_pool(lp, cost_idx, cost_val, best_lb, best_ub):
    import highspy
    import numpy as np
    global _CUBE_STATE
    h = highspy.Highs()
    h.setOptionValue("output_flag", False)
    h.setOptionValue("threads", 1)
    h.setOptionValue("mip_rel_gap", 0.0)
    h.setOptionValue("mip_abs_gap", 0.999)
    h.passModel(lp)
    ub_row = lp.num_row_
    h.addRow(-highspy.kHighsInf, highspy.kHighsInf, len(cost_idx),
             np.array(cost_idx, dtype=np.int32), np.array(cost_val, dtype=float))
    _CUBE_STATE = (h, ub_row, best_lb, best_ub)


def _solve_cube_worker(task):
    import math
    import highspy
    mode, arg = task
    h, ub_row, best_lb, best_ub = _CUBE_STATE
    if best_lb.value >= best_ub.value:
        return None
    if mode == "full":
        ub = best_ub.value
        h.changeRowBounds(ub_row, float(best_lb.value), float(ub) if ub < 10**8 else highspy.kHighsInf)
        h.setOptionValue("mip_abs_gap", 0.999)
        h.setOptionValue("random_seed", int(arg))
        h.run()
        status = h.modelStatusToString(h.getModelStatus())
        if status == "Infeasible":
            return ("infeas", ub + 1, True)
        info = h.getInfo()
        val, bnd = info.objective_function_value, info.mip_dual_bound
        if status == "Optimal" and math.ceil(bnd - 1e-6) == round(val) and abs(val - round(val)) <= 1e-4:
            v = int(round(val))
            with best_ub.get_lock():
                if v < best_ub.value:
                    best_ub.value = v
            with best_lb.get_lock():
                if v > best_lb.value:
                    best_lb.value = v
            return ("exact", v, True)
        return None
    else:
        t_val = int(arg)
        if t_val < best_lb.value or t_val >= best_ub.value:
            return None
        h.changeRowBounds(ub_row, -highspy.kHighsInf, float(t_val))
        h.setOptionValue("mip_abs_gap", float(t_val) + 0.5)
        h.setOptionValue("random_seed", (t_val % 97) + 1)
        h.run()
        status = h.modelStatusToString(h.getModelStatus())
        if status == "Infeasible":
            with best_lb.get_lock():
                if t_val + 1 > best_lb.value:
                    best_lb.value = t_val + 1
            return ("infeas", t_val + 1, True)
        info = h.getInfo()
        val = info.objective_function_value
        if status == "Optimal" and abs(val - round(val)) <= 1e-4 and round(val) <= t_val:
            v = int(round(val))
            with best_ub.get_lock():
                if v < best_ub.value:
                    best_ub.value = v
            return ("feas", v, True)
        return None


def _run_highs_with_cubes(h, obj, start_lb, threads, time_limit, init_ub=10**9):
    """Run HiGHS directly if threads <= 1, else run a portfolio + target-threshold worker pool across `threads` processes."""
    if threads <= 1 or (time_limit and time_limit > 0):
        h.setOptionValue("threads", max(1, int(threads)))
        if time_limit and time_limit > 0:
            h.setOptionValue("time_limit", float(time_limit))
        h.run()
        status = h.modelStatusToString(h.getModelStatus())
        info = h.getInfo()
        val, bnd = info.objective_function_value, info.mip_dual_bound
        exact = (status == "Optimal" and math.ceil(bnd - 1e-6) == round(val) and abs(val - round(val)) <= 1e-6)
        k = round(val) if exact else max(0, int(math.ceil(bnd - 1e-6)))
        return k, exact

    lp = h.getLp()
    h_lp = highspy.Highs()
    h_lp.setOptionValue("output_flag", False)
    h_lp.setOptionValue("threads", 1)
    lp_relax = highspy.HighsLp()
    lp_relax.num_col_ = lp.num_col_
    lp_relax.num_row_ = lp.num_row_
    lp_relax.col_cost_ = lp.col_cost_
    lp_relax.col_lower_ = lp.col_lower_
    lp_relax.col_upper_ = lp.col_upper_
    lp_relax.row_lower_ = lp.row_lower_
    lp_relax.row_upper_ = lp.row_upper_
    lp_relax.a_matrix_ = lp.a_matrix_
    h_lp.passModel(lp_relax)
    h_lp.run()
    lp_lb = int(math.ceil(h_lp.getInfo().objective_function_value - 1e-6)) if h_lp.modelStatusToString(h_lp.getModelStatus()) == "Optimal" else 0
    proven_lb = max(int(start_lb), lp_lb)
    proven_ub = int(init_ub)
    if proven_lb >= proven_ub and proven_ub < 10**8:
        return proven_ub, True

    cost_idx = [v - 1 for v in obj.keys()]
    cost_val = [float(k_v) for k_v in obj.values()]
    max_t = proven_ub - 1 if proven_ub < 10**8 else proven_lb + 60
    n_thresh = max(1, int(threads) - 2)
    if max_t - proven_lb + 1 <= n_thresh:
        thresh_list = list(range(proven_lb, max_t + 1))
    else:
        wave1 = [proven_lb + 1 + 2 * i for i in range(n_thresh) if proven_lb + 1 + 2 * i <= max_t]
        w1_set = set(wave1)
        wave2 = [t for t in range(proven_lb, max_t + 1) if t not in w1_set]
        thresh_list = wave1 + wave2
    tasks = [("full", 1), ("full", 2)] + [("thresh", t) for t in thresh_list]

    best_lb = _MP_CTX.Value("i", proven_lb)
    best_ub = _MP_CTX.Value("i", proven_ub)
    with _MP_CTX.Pool(processes=int(threads), initializer=_init_cube_pool,
                      initargs=(lp, cost_idx, cost_val, best_lb, best_ub)) as pool:
        for res in pool.imap_unordered(_solve_cube_worker, tasks, chunksize=1):
            if res is None:
                continue
            kind, v, _ = res
            if kind == "exact":
                proven_lb = v
                proven_ub = v
                break
            elif kind == "infeas":
                if v > proven_lb:
                    proven_lb = v
            elif kind == "feas":
                if v < proven_ub:
                    proven_ub = v
            if proven_lb >= proven_ub:
                break
        pool.terminate()
    if proven_ub < 10**8 and proven_lb >= proven_ub:
        return proven_ub, True
    return proven_lb, False


def solve_milp_generic(build_fn, rounds, inp_vars_fn, state_vars_fn=None,
                       dmode="free", prefix_bounds=None, subwin_bounds=None, s1b_bounds=None,
                       time_limit=0.0, threads=1, init_ub=10**9):
    """Solve any coarse or refined model built via Model using HiGHS MILP."""
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

    def add_lifted_row(lits, st_vars, b_nz, b_1b):
        diff = b_1b - b_nz
        if diff <= 0 or not st_vars:
            return
        cnt = collections.Counter(lits)
        for u in st_vars:
            cnt[u] += diff
        row(b_1b + diff, [v - 1 for v in cnt], [float(val) for val in cnt.values()])

    if dmode == "onebyte":
        row(1.0, [v - 1 for v in inp], [1.0] * len(inp), hi=1.0)
    elif dmode == "nonzero":
        min_in = 2.0 if init_ub < 10**8 else 1.0
        row(min_in, [v - 1 for v in inp], [1.0] * len(inp))

    st_list = None
    if dmode in ("nonzero", "onebyte") and state_vars_fn is not None:
        st_list = state_vars_fn(rec, rounds)
        for st in st_list:
            cnt_st = collections.Counter(st)
            row(1.0, [v - 1 for v in cnt_st], [float(val) for val in cnt_st.values()])

    for i, c in enumerate(m.cl):
        if i not in drop:
            row(1 - sum(1 for l in c if l < 0), [abs(l) - 1 for l in c], [1.0 if l > 0 else -1.0 for l in c])
    for j, (_, _, col) in enumerate(cols):
        d = n + j
        row(0, [v - 1 for v in col] + [d], [1.0] * 8 + [-5.0])
        for v in col:
            row(0, [d, v - 1], [1.0, -1.0])

    rounds_lits = [r for r in m.rounds if r][:rounds]
    if len(rounds_lits) < rounds:
        rounds_lits = [rec[r]["A"] + rec[r]["T2"] for r in range(rounds)]

    if prefix_bounds and prefix_bounds is not subwin_bounds:
        lits = []
        for r_idx, rl in enumerate(rounds_lits, 1):
            lits += rl
            if r_idx < rounds and r_idx in prefix_bounds and prefix_bounds[r_idx] > 0:
                cnt = collections.Counter(lits)
                row(prefix_bounds[r_idx], [v - 1 for v in cnt], [float(k) for k in cnt.values()])

    if subwin_bounds:
        for s in range(0, rounds):
            lits = []
            st_s = st_list[s] if (st_list and s < len(st_list)) else (inp if s == 0 else None)
            for w in range(1, rounds - s + 1):
                lits += rounds_lits[s + w - 1]
                if w < rounds:
                    b = subwin_bounds.get(w, 0)
                    if b > 0:
                        cnt = collections.Counter(lits)
                        row(b, [v - 1 for v in cnt], [float(k) for k in cnt.values()])
                    if dmode in ("nonzero", "onebyte") and s1b_bounds and st_s:
                        add_lifted_row(lits, st_s, b, s1b_bounds.get(w, 0))

    start_lb = bounds.split_bound(rounds, subwin_bounds) if subwin_bounds else 0
    if prefix_bounds:
        start_lb = max(start_lb, prefix_bounds.get(rounds - 1, 0))
    use_threads = threads if (threads > 1 and rounds >= 8 and ncol in (8 * rounds, 12 * rounds)) else 1
    val, exact = _run_highs_with_cubes(h, obj, start_lb, use_threads, time_limit, init_ub=init_ub)
    if exact:
        return val, True
    lb = val
    if prefix_bounds and (rounds - 1) in prefix_bounds:
        lb = max(lb, prefix_bounds[rounds - 1])
    return lb, False


def solve_sat_single_curve(build_fn, rounds, inp_vars_fn, dmode, prefix_bounds, subwin_bounds):
    """Solve single-permutation (nonzero or onebyte) or related-coarse model via CaDiCaL SAT + window counters."""
    m, rec = build_fn(rounds)
    inp = inp_vars_fn(rec)
    if dmode == "zero":
        for v in inp:
            m.cl.append([-v])
    elif dmode == "nonzero":
        m.cl.append(list(inp))
    elif dmode == "onebyte":
        m.cl.append(list(inp))
        for i in range(len(inp)):
            for j in range(i + 1, len(inp)):
                m.cl.append([-inp[i], -inp[j]])

    if subwin_bounds:
        bounds.add_windows(m, rounds, subwin_bounds)
    if prefix_bounds and dmode in ("onebyte", "zero"):
        lits, targets = [], []
        for w in range(1, rounds):
            lits += m.rounds[w - 1]
            if prefix_bounds.get(w, 0) > 0:
                targets.append((len(lits), prefix_bounds[w]))
        if targets:
            bounds.at_least_prefix(m, lits, targets)

    lb = bounds.split_bound(rounds, subwin_bounds) if subwin_bounds else 0
    if prefix_bounds:
        lb = max(lb, prefix_bounds.get(rounds - 1, 0))
        if subwin_bounds:
            for w in range(1, rounds):
                if w in prefix_bounds and (rounds - w) in subwin_bounds:
                    lb = max(lb, prefix_bounds[w] + subwin_bounds[rounds - w])

    with Solver(name=SOLVER, bootstrap_with=m.cl) as s:
        if not s.solve():
            raise SystemExit("model has no trail at all")
        mod = set(l for l in s.get_model() if l > 0)
        best = sum(1 for v in m.sboxes if v in mod)
        if best <= lb:
            return best, True
        tot = ITotalizer(lits=m.sboxes, ubound=best, top_id=max(m.nv, s.nof_vars()))
        s.append_formula(tot.cnf.clauses)
        while best > lb:
            if not s.solve(assumptions=[-tot.rhs[best - 1]]):
                break
            mod = set(l for l in s.get_model() if l > 0)
            best = sum(1 for v in m.sboxes if v in mod)
        return best, True


def solve_bwd_curve(task):
    """Worker for parallel forward vs backward active S-box curve computation."""
    label, direction, kind, width, max_r, dmode, feas, subwin, time_limit, no_cache, threads = task
    t0 = time.time()
    curve = []
    exact_flags = []
    key = _cache_key(label, direction, width, dmode)
    prefix = {}
    deltas = [0] * 15 if dmode in ("nonzero", "onebyte") else [0xFFFF] * 15
    for r in range(1, max_r + 1):
        cache_all = load_bounds_cache(no_cache)
        cached = cache_all.get(key, {})
        if r in cached:
            k, exact = cached[r], True
        elif kind == "refined":
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
            exact = True
            save_bound_entry(key, r, k, no_cache)
        else:
            if direction == "fwd":
                bfn = lambda rr: model_mod.build(width, rr, deltas)
                ifn = (lambda rec: rec[0]["A"] + rec[0]["B"]) if width == 256 else (lambda rec: sum((rec[0][w] for w in "abcd"), []))
                sfn = (lambda rec, rr: [rec[s]["A"] + rec[s]["B"] for s in range(rr)] + [rec[-1]["x0"] + rec[-1]["x1"]]) if width == 256 else (
                    lambda rec, rr: [sum((rec[s][w] for w in "abcd"), []) for s in range(rr)] + [sum((rec[-1][f"x{i}"] for i in range(4)), [])])
            else:
                bfn = (lambda rr: build_inv_256_coarse(rr, deltas)) if width == 256 else (lambda rr: build_inv_512_coarse(rr, deltas))
                ifn = (lambda rec: rec[0]["S"] + rec[0]["Bp"]) if width == 256 else (lambda rec: sum((rec[0][w] for w in ("ap", "bp", "cf", "dp")), []))
                sfn = (lambda rec, rr: [rec[s]["S"] + rec[s]["Bp"] for s in range(rr)] + [rec[-1]["x0"] + rec[-1]["x1"]]) if width == 256 else (
                    lambda rec, rr: [sum((rec[s][w] for w in ("ap", "bp", "cf", "dp")), []) for s in range(rr)] + [sum((rec[-1][f"x{i}"] for i in range(4)), [])])
            sw = prefix if dmode in ("free", "nonzero") else subwin
            s1b_c = cache_all.get(_cache_key("single-1byte", direction, width, "onebyte"), {}) if dmode in ("nonzero", "onebyte") else None
            init_ub = 10**9
            if dmode == "nonzero" and s1b_c and r in s1b_c:
                init_ub = s1b_c[r]
            if width == 256 and dmode in ("nonzero", "onebyte") and not (time_limit and time_limit > 0):
                k, exact = solve_sat_single_curve(bfn, r, ifn, dmode, prefix, sw)
            else:
                k, exact = solve_milp_generic(
                    bfn, r, ifn, state_vars_fn=sfn, dmode=dmode,
                    prefix_bounds=prefix, subwin_bounds=sw, s1b_bounds=s1b_c,
                    time_limit=time_limit, threads=threads, init_ub=init_ub)
                if not exact and width == 256 and dmode == "zero" and not (time_limit and time_limit > 0):
                    k, exact = solve_sat_single_curve(bfn, r, ifn, dmode, prefix, sw)
            if exact:
                save_bound_entry(key, r, k, no_cache)
        curve.append(k)
        exact_flags.append(exact)
        prefix[r] = k
    return (label, direction, kind, width, dmode, curve, exact_flags, round(time.time() - t0, 2))


def solve_cross_sat_windowed(width, mode_kind, r, dmode, snz, s1b_fwd, cnz_c_map, cnz_s_map, c1b_c_map=None):
    """Solve coupled 2r-round cross-composition model to exact optimality via CaDiCaL SAT + window counters."""
    if width == 256:
        m, frec, brec, states = build_cross_256_coarse(r, [0xFFFF] * 15)
    elif mode_kind == "cancelled":
        m, frec, brec, states = build_cross_512_cancelled(r, [0xFFFF] * 15)
    else:
        m, frec, brec, states = build_cross_512_shared(r, [0xFFFF] * 15)
        if r >= 2:
            f = frec[r - 2]
            dp, d = brec[1]["dp"], brec[1]["d"]
            for j in range(16):
                m.cl += [[-f["d"][j], dp[j], d[j]], [f["d"][j], dp[j], -d[j]]]

    inp = states[0]
    m.cl.append(list(inp))
    if dmode == "onebyte":
        for i in range(len(inp)):
            for j in range(i + 1, len(inp)):
                m.cl.append([-inp[i], -inp[j]])
    for st in states[r:]:
        m.cl.append(list(st))

    rlits = m.rounds[:2 * r]
    fwd_lits = rlits[:r]
    bwd_lits = rlits[r:2 * r]

    if width == 256:
        full_fwd = [frec[k]["A"] + frec[k]["T2"] for k in range(r)]
        full_bwd = [brec[k]["A"] + brec[k]["T2"] for k in range(r)]
        canc_fwd, canc_bwd = fwd_lits, bwd_lits
        shar_fwd, shar_bwd = fwd_lits, bwd_lits
    else:
        full_fwd = [frec[k]["a"] + frec[k]["c"] + frec[k]["c2"] for k in range(r)]
        full_bwd = [brec[k]["a"] + brec[k]["c2"] + brec[k]["c"] for k in range(r)]
        canc_fwd = [
            (frec[k]["c"] if k == r - 1 else (frec[k]["a"] + frec[k]["c"] if k == r - 2 else full_fwd[k]))
            for k in range(r)
        ]
        canc_bwd = [
            (brec[k]["c"] if k == 0 else (brec[k]["a"] + brec[k]["c"] if k == 1 else full_bwd[k]))
            for k in range(r)
        ]
        shar_fwd = list(full_fwd)
        shar_bwd = list(canc_bwd)

    for seq in (full_fwd, full_bwd):
        for s in range(r):
            lits, targets = [], []
            for w in range(1, r - s + 1):
                lits += seq[s + w - 1]
                if snz.get(w, 0) > 0:
                    targets.append((len(lits), snz[w]))
            if targets:
                bounds.at_least_prefix(m, lits, targets)

    unshared_fwd = r if width == 256 else (max(0, r - 2) if mode_kind == "cancelled" else r)
    unshared_bwd_start = 1 if width == 256 else 2
    for s in range(unshared_fwd):
        lits, targets = [], []
        for w in range(1, unshared_fwd - s + 1):
            lits += fwd_lits[s + w - 1]
            if snz.get(w, 0) > 0:
                targets.append((len(lits), snz[w]))
        if targets:
            bounds.at_least_prefix(m, lits, targets)
    for s in range(unshared_bwd_start, r):
        lits, targets = [], []
        for w in range(1, r - s + 1):
            lits += bwd_lits[s + w - 1]
            if snz.get(w, 0) > 0:
                targets.append((len(lits), snz[w]))
        if targets:
            bounds.at_least_prefix(m, lits, targets)

    if width == 256:
        for k in range(1, r + 1):
            if cnz_s_map.get(k, 0) > 0:
                lits = sum(fwd_lits[r - k:r], []) + sum(bwd_lits[:k], [])
                bounds.at_least_prefix(m, lits, [(len(lits), cnz_s_map[k])])
    else:
        for k in range(1, r + 1):
            if cnz_c_map and cnz_c_map.get(k, 0) > 0:
                lits = sum(canc_fwd[r - k:r], []) + sum(canc_bwd[:k], [])
                bounds.at_least_prefix(m, lits, [(len(lits), cnz_c_map[k])])
            if cnz_s_map and cnz_s_map.get(k, 0) > 0:
                lits = sum(shar_fwd[r - k:r], []) + sum(shar_bwd[:k], [])
                bounds.at_least_prefix(m, lits, [(len(lits), cnz_s_map[k])])

    if dmode == "onebyte":
        lits, targets = [], []
        for w in range(1, r + 1):
            lits += full_fwd[w - 1]
            if s1b_fwd.get(w, 0) > 0:
                targets.append((len(lits), s1b_fwd[w]))
        if targets:
            bounds.at_least_prefix(m, lits, targets)

    cnz_own = cnz_c_map if (width == 512 and mode_kind == "cancelled") else cnz_s_map
    first_r = s1b_fwd.get(r, 0) if dmode == "onebyte" else snz.get(r, 0)
    lb = cnz_own.get(r - 1, 0) if cnz_own else 0
    if width == 256:
        lb = max(lb, first_r + snz.get(r - 1, 0))
    else:
        if mode_kind == "shared":
            lb = max(lb, first_r + snz.get(r - 2, 0))
            canc_r = (c1b_c_map.get(r, 0) if (dmode == "onebyte" and c1b_c_map) else 0)
            if cnz_c_map:
                canc_r = max(canc_r, cnz_c_map.get(r, 0))
            if canc_r > 0:
                lb = max(lb, (first_r + snz.get(r, 0) + canc_r + 1) // 2)
        else:
            first_rm2 = s1b_fwd.get(r - 2, 0) if dmode == "onebyte" else snz.get(r - 2, 0)
            lb = max(lb, first_rm2 + snz.get(r - 2, 0))
    if cnz_own:
        lb = max(lb, cnz_own.get(r, 0))
        for w in range(1, r - (0 if width == 256 else 1)):
            first_w = s1b_fwd.get(w, 0) if dmode == "onebyte" else snz.get(w, 0)
            lb = max(lb, first_w + cnz_own.get(r - w, 0) + snz.get(w, 0))
    if dmode == "onebyte" and width == 512 and mode_kind == "shared" and c1b_c_map:
        lb = max(lb, c1b_c_map.get(r, 0))

    with Solver(name=SOLVER, bootstrap_with=m.cl) as s:
        if not s.solve():
            raise SystemExit("cross model has no trail at all")
        mod = set(l for l in s.get_model() if l > 0)
        best = sum(1 for v in m.sboxes if v in mod)
        if best <= lb:
            return best, True
        tot = ITotalizer(lits=m.sboxes, ubound=best, top_id=max(m.nv, s.nof_vars()))
        s.append_formula(tot.cnf.clauses)
        while best > lb:
            if not s.solve(assumptions=[-tot.rhs[best - 1]]):
                break
            mod = set(l for l in s.get_model() if l > 0)
            best = sum(1 for v in m.sboxes if v in mod)
        return best, True


def solve_cross_curve(task):
    """Worker for coupled 2r-round C_r(x) = P2_r^-1(P1_r(x)) differential active S-box bounds."""
    label, width, mode_kind, max_r, dmode, snz, s1b_fwd, cnz_in, time_limit, no_cache, threads = task
    t0 = time.time()
    key = _cache_key(label, "2r", width, dmode)

    prefix = {}
    curve = []
    exact_flags = []
    for r in range(1, max_r + 1):
        cache_all = load_bounds_cache(no_cache)
        cached = cache_all.get(key, {})
        cnz_c_cache = cache_all.get(_cache_key("cross-cancelled", "2r", 512, "nonzero"), {})
        cnz_s_cache = cache_all.get(_cache_key("cross-shared", "2r", width, "nonzero"), {})
        c1b_c_cache = cache_all.get(_cache_key("cross-cancelled", "2r", 512, "onebyte"), {})
        c1b_s_cache = cache_all.get(_cache_key("cross-shared", "2r", width, "onebyte"), {})
        s1b_bwd = cache_all.get(_cache_key("single-1byte", "bwd", width, "onebyte"), {})
        snz_bwd = cache_all.get(_cache_key("single-nonzero", "bwd", width, "nonzero"), snz)
        if r in cached:
            k, exact = cached[r], True
            prefix[r] = k
            curve.append(k)
            exact_flags.append(exact)
            continue

        cnz_map = cnz_in if cnz_in is not None else prefix
        c_map = {**cnz_c_cache, **(cnz_map if (width == 512 and mode_kind == "cancelled") else {})}
        s_map = {**cnz_s_cache, **(cnz_map if mode_kind == "shared" else {})}
        if width == 256 and not (time_limit and time_limit > 0):
            k, exact = solve_cross_sat_windowed(
                width, mode_kind, r, dmode, snz, s1b_fwd, c_map, s_map, c1b_c_cache)
            if exact:
                save_bound_entry(key, r, k, no_cache)
            prefix[r] = k
            curve.append(k)
            exact_flags.append(exact)
            continue

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
            if width == 256:
                m, frec, brec, states = build_cross_256_coarse(r, [0xFFFF] * 15)
            elif mode_kind == "cancelled":
                m, frec, brec, states = build_cross_512_cancelled(r, [0xFFFF] * 15)
            else:
                m, frec, brec, states = build_cross_512_shared(r, [0xFFFF] * 15)
                if r >= 2:
                    f = frec[r - 2]
                    dp, d = brec[1]["dp"], brec[1]["d"]
                    for j in range(16):
                        m.cl += [[-f["d"][j], dp[j], d[j]], [f["d"][j], dp[j], -d[j]]]
        finally:
            model_mod.Model.mc = orig_mc

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

        nv = n + ncol
        idx = np.arange(nv, dtype=np.int32)
        cost = np.zeros(nv)
        for v, k_v in obj.items():
            cost[v - 1] = k_v
        h.addVars(nv, np.zeros(nv), np.ones(nv))
        h.changeColsIntegrality(nv, idx, np.array([highspy.HighsVarType.kInteger] * nv))
        h.changeColsCost(nv, idx, cost)
        inf = highspy.kHighsInf

        def row(lo, c_idx, vals, hi=inf):
            h.addRow(lo, hi, len(c_idx), np.array(c_idx, dtype=np.int32), np.array(vals, dtype=float))

        def add_lifted_row(lits, st_vars, b_nz, b_1b):
            diff = b_1b - b_nz
            if diff <= 0 or not st_vars:
                return
            cnt = collections.Counter(lits)
            for u in st_vars:
                cnt[u] += diff
            row(b_1b + diff, [v - 1 for v in cnt], [float(val) for val in cnt.values()])

        init_ub = 10**9
        if dmode == "nonzero":
            c1b_own = cache_all.get(_cache_key(label, "2r", width, "onebyte"), {})
            if r in c1b_own:
                init_ub = c1b_own[r]

        inp = states[0]
        if dmode == "onebyte":
            row(1.0, [v - 1 for v in inp], [1.0] * len(inp), hi=1.0)
        else:
            min_in = 2.0 if init_ub < 10**8 else 1.0
            row(min_in, [v - 1 for v in inp], [1.0] * len(inp))
        for st in states[1:]:
            cnt_st = collections.Counter(st)
            row(1.0, [v - 1 for v in cnt_st], [float(val) for val in cnt_st.values()])

        for i, c in enumerate(m.cl):
            if i not in drop:
                row(1 - sum(1 for l in c if l < 0), [abs(l) - 1 for l in c], [1.0 if l > 0 else -1.0 for l in c])
        for j, (_, _, col) in enumerate(cols):
            d = n + j
            row(0, [v - 1 for v in col] + [d], [1.0] * 8 + [-5.0])
            for v in col:
                row(0, [d, v - 1], [1.0, -1.0])

        rlits = m.rounds[:2 * r]
        fwd_lits = rlits[:r]
        bwd_lits = rlits[r:2 * r]

        if width == 256:
            full_fwd = [frec[k]["A"] + frec[k]["T2"] for k in range(r)]
            full_bwd = [brec[k]["A"] + brec[k]["T2"] for k in range(r)]
            canc_fwd, canc_bwd = fwd_lits, bwd_lits
            shar_fwd, shar_bwd = fwd_lits, bwd_lits
        else:
            full_fwd = [frec[k]["a"] + frec[k]["c"] + frec[k]["c2"] for k in range(r)]
            full_bwd = [brec[k]["a"] + brec[k]["c2"] + brec[k]["c"] for k in range(r)]
            canc_fwd = [
                (frec[k]["c"] if k == r - 1 else (frec[k]["a"] + frec[k]["c"] if k == r - 2 else full_fwd[k]))
                for k in range(r)
            ]
            canc_bwd = [
                (brec[k]["c"] if k == 0 else (brec[k]["a"] + brec[k]["c"] if k == 1 else full_bwd[k]))
                for k in range(r)
            ]
            shar_fwd = list(full_fwd)
            shar_bwd = list(canc_bwd)
        for s in range(0, r):
            for w in range(1, r - s + 1):
                if snz.get(w, 0) > 0:
                    l_f = sum(full_fwd[s:s + w], [])
                    cnt = collections.Counter(l_f)
                    row(snz[w], [v - 1 for v in cnt], [float(k_v) for k_v in cnt.values()])
                    add_lifted_row(l_f, states[s], snz[w], s1b_fwd.get(w, 0))
                    l_b = sum(full_bwd[s:s + w], [])
                    cnt_b = collections.Counter(l_b)
                    row(snz_bwd.get(w, snz[w]), [v - 1 for v in cnt_b], [float(k_v) for k_v in cnt_b.values()])
                    add_lifted_row(l_b, states[r + s], snz_bwd.get(w, snz[w]), s1b_bwd.get(w, 0))

        unshared_fwd = r if width == 256 else (max(0, r - 2) if mode_kind == "cancelled" else r)
        unshared_bwd_start = 1 if width == 256 else 2
        for s in range(0, unshared_fwd):
            for w in range(1, unshared_fwd - s + 1):
                if snz.get(w, 0) > 0:
                    l_f = sum(fwd_lits[s:s + w], [])
                    cnt = collections.Counter(l_f)
                    row(snz[w], [v - 1 for v in cnt], [float(k_v) for k_v in cnt.values()])
                    add_lifted_row(l_f, states[s], snz[w], s1b_fwd.get(w, 0))
        for s in range(unshared_bwd_start, r):
            for w in range(1, r - s + 1):
                if snz.get(w, 0) > 0:
                    l_b = sum(bwd_lits[s:s + w], [])
                    cnt = collections.Counter(l_b)
                    row(snz_bwd.get(w, snz[w]), [v - 1 for v in cnt], [float(k_v) for k_v in cnt.values()])
                    add_lifted_row(l_b, states[r + s], snz_bwd.get(w, snz[w]), s1b_bwd.get(w, 0))

        if width == 256:
            for k_idx in range(1, r + 1):
                if s_map.get(k_idx, 0) > 0:
                    l_m = sum(fwd_lits[r - k_idx:r], []) + sum(bwd_lits[:k_idx], [])
                    cnt = collections.Counter(l_m)
                    row(s_map[k_idx], [v - 1 for v in cnt], [float(v) for v in cnt.values()])
                    add_lifted_row(l_m, states[r - k_idx], s_map[k_idx], c1b_s_cache.get(k_idx, 0))
        else:
            for k_idx in range(1, r + 1):
                if c_map.get(k_idx, 0) > 0:
                    l_c = sum(canc_fwd[r - k_idx:r], []) + sum(canc_bwd[:k_idx], [])
                    cnt = collections.Counter(l_c)
                    row(c_map[k_idx], [v - 1 for v in cnt], [float(v) for v in cnt.values()])
                    add_lifted_row(l_c, states[r - k_idx], c_map[k_idx], c1b_c_cache.get(k_idx, 0))
                if s_map.get(k_idx, 0) > 0:
                    l_s = sum(shar_fwd[r - k_idx:r], []) + sum(shar_bwd[:k_idx], [])
                    cnt = collections.Counter(l_s)
                    row(s_map[k_idx], [v - 1 for v in cnt], [float(v) for v in cnt.values()])
                    add_lifted_row(l_s, states[r - k_idx], s_map[k_idx], c1b_s_cache.get(k_idx, 0))

        if dmode == "onebyte":
            for w in range(1, r + 1):
                if s1b_fwd.get(w, 0) > 0:
                    cnt = collections.Counter(sum(full_fwd[:w], []))
                    row(s1b_fwd[w], [v - 1 for v in cnt], [float(k_v) for k_v in cnt.values()])
            for w in range(1, unshared_fwd + 1):
                if s1b_fwd.get(w, 0) > 0:
                    cnt = collections.Counter(sum(fwd_lits[:w], []))
                    row(s1b_fwd[w], [v - 1 for v in cnt], [float(k_v) for k_v in cnt.values()])
            if width == 512 and mode_kind == "shared" and c1b_c_cache.get(r, 0) > 0:
                cnt = collections.Counter(sum(canc_fwd, []) + sum(canc_bwd, []))
                row(c1b_c_cache[r], [v - 1 for v in cnt], [float(k_v) for k_v in cnt.values()])

        start_lb = prefix.get(r - 1, 0) if dmode == "nonzero" else 0
        if width == 512:
            if mode_kind == "cancelled":
                start_lb = max(start_lb, c_map.get(r, 0),
                               (s1b_fwd.get(unshared_fwd, 0) if dmode == "onebyte" else snz.get(unshared_fwd, 0)) + snz.get(r - unshared_bwd_start, 0))
            else:
                start_lb = max(start_lb, c_map.get(r, 0), s_map.get(r, 0),
                               (c1b_c_cache.get(r, 0) if dmode == "onebyte" else 0),
                               (s1b_fwd.get(unshared_fwd, 0) if dmode == "onebyte" else snz.get(unshared_fwd, 0)) + snz.get(r - unshared_bwd_start, 0))
        use_threads = threads if (threads > 1 and width == 512 and r >= 8) else 1
        k, exact = _run_highs_with_cubes(
            h, obj, start_lb, use_threads, time_limit, init_ub=init_ub)
        if exact:
            save_bound_entry(key, r, k, no_cache)
        prefix[r] = k
        curve.append(k)
        exact_flags.append(exact)
    return (label, width, dmode, curve, exact_flags, round(time.time() - t0, 2))


def solve_cross_sat_single(task):
    """Pure CaDiCaL SAT solver (zero window cuts) for small-round cross-composition verification."""
    label, width, mode_kind, max_r, dmode = task
    curve = []
    for r in range(1, max_r + 1):
        if width == 256:
            m, _, _, states = build_cross_256_coarse(r, [0xFFFF] * 15)
        elif mode_kind == "cancelled":
            m, _, _, states = build_cross_512_cancelled(r, [0xFFFF] * 15)
        else:
            m, _, _, states = build_cross_512_shared(r, [0xFFFF] * 15)
        inp = states[0]
        m.cl.append(list(inp))
        if dmode == "onebyte":
            for i in range(len(inp)):
                for j in range(i + 1, len(inp)):
                    m.cl.append([-inp[i], -inp[j]])
        for st in states[1:]:
            m.cl.append(list(st))
        k, _ = minimise(m, 200)
        curve.append(k)
    return (label, width, dmode, curve)


def eval_cross_traces(m, rec_all, inp_vars, traces, lb_nonzero, lb_onebyte):
    """Check that every trace satisfies m.cl and has active S-box count >= proven bounds."""
    bad_sat = 0
    bad_bound = 0
    min_obs_nz = None
    min_obs_1b = None
    with Solver(name="cadical153", bootstrap_with=m.cl) as s:
        for tr in traces:
            assum = []
            vmap = {}
            for rdict, odict in zip(rec_all, tr):
                for name, vars_ in rdict.items():
                    mask = odict[name]
                    for j, v in enumerate(vars_):
                        bit = (mask >> j) & 1
                        vmap[v] = bit
                        assum.append(v if bit else -v)
            if not s.solve(assumptions=assum):
                bad_sat += 1
            sboxes = sum(vmap[v] for v in m.sboxes)
            in_wt = sum(vmap[v] for v in inp_vars)
            if min_obs_nz is None or sboxes < min_obs_nz:
                min_obs_nz = sboxes
            if sboxes < lb_nonzero:
                bad_bound += 1
            if in_wt == 1:
                if min_obs_1b is None or sboxes < min_obs_1b:
                    min_obs_1b = sboxes
                if sboxes < lb_onebyte:
                    bad_bound += 1
    return bad_sat, bad_bound, min_obs_nz, min_obs_1b


def _impdiff_worker(task):
    width, dmode, r = task
    nb = width // 128
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
    return (width, dmode, r,
            f"Areion-{width} r={r:2d} delta={dmode:4s} | FWD: forced_active={fi:2d} forced_zero={fa:2d} allzero_sat={str(fz):5s} | BWD: forced_active={bi:2d} forced_zero={ba:2d} allzero_sat={str(bz):5s}")


def run_impdiff_comparison(r256, r512, max_rounds=7, threads=1):
    """Compare forward vs backward byte-level impossible differentials for
    delta in ('free', 'full', 'zero')."""
    print("\n== Track 2.7: Forward vs Backward Byte-Level Impossible Differentials (impdiff)", flush=True)
    tasks = []
    for width, max_r in ((256, r256), (512, r512)):
        for dmode in ("free", "full", "zero"):
            for r in range(1, min(max_r, max_rounds) + 1):
                tasks.append((width, dmode, r))
    if threads > 1:
        with concurrent.futures.ProcessPoolExecutor(max_workers=threads, mp_context=_MP_CTX) as ex:
            lines = [line for _, _, _, line in ex.map(_impdiff_worker, tasks)]
        for line in lines:
            print(line, flush=True)
    else:
        for t in tasks:
            _, _, _, line = _impdiff_worker(t)
            print(line, flush=True)


def main():
    default_threads = int(os.environ.get("AREION_THREADS", max(1, (os.cpu_count() or 2) - 2)))
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--r256", type=int, default=10)
    ap.add_argument("--r512", type=int, default=15)
    ap.add_argument("--rounds", type=int, default=9,
                    help="max round depth for 512 single-permutation, cross-composition, and impdiff")
    ap.add_argument("--time-limit", type=float, default=0.0,
                    help="per-cell HiGHS MILP time limit in seconds (0 = no limit)")
    ap.add_argument("--no-cache", action="store_true",
                    help="ignore cached bounds in analysis/build/inverse_bounds.json")
    ap.add_argument("--jobs", type=int, default=default_threads)
    ap.add_argument("--threads", type=int, default=None,
                    help="total worker threads/processes across parallel curves and MILP cubes (default: --jobs or $AREION_THREADS)")
    ap.add_argument("--gobin", help="path to analysis/build/analysis binary for trace-inv")
    ap.add_argument("--trace-n", type=int, default=200)
    a = ap.parse_args()
    total_threads = max(1, a.threads if a.threads is not None else a.jobs)

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
    r512_single = min(a.r512, a.rounds)
    stage1_fast = []
    stage1_heavy = []
    for direction in ("fwd", "bwd"):
        stage1_fast.append(("related-coarse", direction, "coarse", 256, a.r256, "free", None, None, a.time_limit, a.no_cache, 1))
        stage1_fast.append(("related-coarse", direction, "coarse", 512, a.r512, "free", None, None, a.time_limit, a.no_cache, 1))
        stage1_fast.append(("single-nonzero", direction, "coarse", 256, a.r256, "nonzero", None, None, a.time_limit, a.no_cache, 1))
        stage1_heavy.append(("single-nonzero", direction, "coarse", 512, r512_single, "nonzero", None, None, a.time_limit, a.no_cache, total_threads))

    results = {}
    with concurrent.futures.ProcessPoolExecutor(max_workers=total_threads, mp_context=_MP_CTX) as ex:
        for label, direction, kind, width, dmode, curve, exact_flags, secs in ex.map(solve_bwd_curve, stage1_fast):
            results[(label, direction, width, dmode)] = (curve, exact_flags, secs)
    for task in stage1_heavy:
        label, direction, kind, width, dmode, curve, exact_flags, secs = solve_bwd_curve(task)
        results[(label, direction, width, dmode)] = (curve, exact_flags, secs)

    rel_free = {}
    snz_bounds = {}
    for width in (256, 512):
        c_rf, _, _ = results[("related-coarse", "fwd", width, "free")]
        rel_free[width] = {r: c_rf[r - 1] for r in range(1, len(c_rf) + 1)}
        c_snz, _, _ = results[("single-nonzero", "fwd", width, "nonzero")]
        snz_bounds[width] = {r: c_snz[r - 1] for r in range(1, len(c_snz) + 1)}

    stage2_fast = []
    stage2_heavy = []
    for direction in ("fwd", "bwd"):
        for dmode in ("free", "zero"):
            stage2_fast.append(("related-refined-shift", direction, "refined", 256, a.r256, dmode, feas_all["shift"], rel_free[256], a.time_limit, a.no_cache, 1))
            stage2_fast.append(("related-refined-pi", direction, "refined", 256, a.r256, dmode, feas_all["pi"], rel_free[256], a.time_limit, a.no_cache, 1))
        stage2_fast.append(("related-coarse", direction, "coarse", 256, a.r256, "zero", None, rel_free[256], a.time_limit, a.no_cache, 1))
        stage2_fast.append(("related-coarse", direction, "coarse", 512, a.r512, "zero", None, rel_free[512], a.time_limit, a.no_cache, 1))
        stage2_fast.append(("single-1byte", direction, "coarse", 256, a.r256, "onebyte", None, snz_bounds[256], a.time_limit, a.no_cache, 1))
        stage2_heavy.append(("single-1byte", direction, "coarse", 512, r512_single, "onebyte", None, snz_bounds[512], a.time_limit, a.no_cache, total_threads))

    with concurrent.futures.ProcessPoolExecutor(max_workers=total_threads, mp_context=_MP_CTX) as ex:
        for label, direction, kind, width, dmode, curve, exact_flags, secs in ex.map(solve_bwd_curve, stage2_fast):
            results[(label, direction, width, dmode)] = (curve, exact_flags, secs)
    for task in stage2_heavy:
        label, direction, kind, width, dmode, curve, exact_flags, secs = solve_bwd_curve(task)
        results[(label, direction, width, dmode)] = (curve, exact_flags, secs)

    for (label, width, dmode) in (
        ("related-coarse", 256, "free"),
        ("related-coarse", 256, "zero"),
        ("related-refined-shift", 256, "free"),
        ("related-refined-shift", 256, "zero"),
        ("related-refined-pi", 256, "free"),
        ("related-refined-pi", 256, "zero"),
        ("single-nonzero", 256, "nonzero"),
        ("single-1byte", 256, "onebyte"),
        ("related-coarse", 512, "free"),
        ("related-coarse", 512, "zero"),
        ("single-nonzero", 512, "nonzero"),
        ("single-1byte", 512, "onebyte"),
    ):
        for direction in ("fwd", "bwd"):
            curve, exact_flags, tot_s = results[(label, direction, width, dmode)]
            cols = " ".join(
                f"r{r}:{curve[r-1]:3d}{'' if exact_flags[r-1] else '*'}"
                for r in range(1, len(curve) + 1)
            )
            print(f"Areion-{width} | {label:21s} | delta={dmode:7s} | {direction.upper()} | {cols}  ({tot_s}s)", flush=True)

    # 2b. Coupled 2r-round Cross-Composition C_r(x) = P2_r^-1(P1_r(x)) Differential Active S-Box Bounds
    s1b_fwd = {}
    for width in (256, 512):
        c_1b, _, _ = results[("single-1byte", "fwd", width, "onebyte")]
        s1b_fwd[width] = {r: c_1b[r - 1] for r in range(1, len(c_1b) + 1)}

    r256_cross = a.r256
    r512_cross = min(a.r512, a.rounds)
    cross_s1 = [
        ("cross-shared", 256, "shared", r256_cross, "nonzero", snz_bounds[256], s1b_fwd[256], None, a.time_limit, a.no_cache, 1),
        ("cross-cancelled", 512, "cancelled", r512_cross, "nonzero", snz_bounds[512], s1b_fwd[512], None, a.time_limit, a.no_cache, total_threads),
        ("cross-shared", 512, "shared", r512_cross, "nonzero", snz_bounds[512], s1b_fwd[512], None, a.time_limit, a.no_cache, total_threads),
    ]
    cross_res = {}
    for task in cross_s1:
        label, width, dmode, curve, exact_flags, secs = solve_cross_curve(task)
        cross_res[(label, width, dmode)] = (curve, exact_flags, secs)

    cnz_256 = {r: cross_res[("cross-shared", 256, "nonzero")][0][r - 1] for r in range(1, r256_cross + 1)}
    cnz_512_c = {r: cross_res[("cross-cancelled", 512, "nonzero")][0][r - 1] for r in range(1, r512_cross + 1)}
    cnz_512_s = {r: cross_res[("cross-shared", 512, "nonzero")][0][r - 1] for r in range(1, r512_cross + 1)}

    cross_s2 = [
        ("cross-shared", 256, "shared", r256_cross, "onebyte", snz_bounds[256], s1b_fwd[256], cnz_256, a.time_limit, a.no_cache, 1),
        ("cross-cancelled", 512, "cancelled", r512_cross, "onebyte", snz_bounds[512], s1b_fwd[512], cnz_512_c, a.time_limit, a.no_cache, total_threads),
        ("cross-shared", 512, "shared", r512_cross, "onebyte", snz_bounds[512], s1b_fwd[512], cnz_512_s, a.time_limit, a.no_cache, total_threads),
    ]
    for task in cross_s2:
        label, width, dmode, curve, exact_flags, secs = solve_cross_curve(task)
        cross_res[(label, width, dmode)] = (curve, exact_flags, secs)

    for (label, width, dmode) in (
        ("cross-shared", 256, "nonzero"),
        ("cross-shared", 256, "onebyte"),
        ("cross-cancelled", 512, "nonzero"),
        ("cross-cancelled", 512, "onebyte"),
        ("cross-shared", 512, "nonzero"),
        ("cross-shared", 512, "onebyte"),
    ):
        curve, exact_flags, tot_s = cross_res[(label, width, dmode)]
        cols = " ".join(
            f"r{r}:{curve[r-1]:3d}{'' if exact_flags[r-1] else '*'}"
            for r in range(1, len(curve) + 1)
        )
        print(f"Areion-{width} | {label:21s} | delta={dmode:7s} | 2r  | {cols}  ({tot_s}s)", flush=True)

    # 2c. Pure CaDiCaL SAT vs HiGHS MILP agreement check on small-round cross-composition models
    sat_tasks = [
        ("cross-shared", 256, "shared", min(r256_cross, 3), "nonzero"),
        ("cross-shared", 256, "shared", min(r256_cross, 3), "onebyte"),
        ("cross-cancelled", 512, "cancelled", min(r512_cross, 4), "nonzero"),
        ("cross-cancelled", 512, "cancelled", min(r512_cross, 4), "onebyte"),
        ("cross-shared", 512, "shared", min(r512_cross, 4), "nonzero"),
        ("cross-shared", 512, "shared", min(r512_cross, 4), "onebyte"),
    ]
    sat_res = {}
    with concurrent.futures.ProcessPoolExecutor(max_workers=total_threads, mp_context=_MP_CTX) as ex:
        for label, width, dmode, sat_curve in ex.map(solve_cross_sat_single, sat_tasks):
            sat_res[(label, width, dmode)] = sat_curve
    for label, width, _, max_r_sat, dmode in sat_tasks:
        sat_curve = sat_res[(label, width, dmode)]
        highs_curve = cross_res[(label, width, dmode)][0][:max_r_sat]
        status = "same" if sat_curve == highs_curve else "DIFFER"
        print(f"== {label} {width} {dmode} (SAT/HiGHS r=1..{max_r_sat}): {sat_curve} / {highs_curve} -> {status}", flush=True)
        if status != "same":
            raise SystemExit(f"SAT/HiGHS mismatch on {label} {width} {dmode}: {sat_curve} vs {highs_curve}")

    # 2d. Coupled 2r-round Cross-Composition Oracle Verification (trace-cross)
    if a.gobin:
        print(f"\n== Track 2.6b: Cross-Composition Oracle Verification on C_r(x) = P2_r^-1(P1_r(x)) (n={a.trace_n} traces)", flush=True)
        total_bad_cross = 0
        for width, max_r_c in ((256, r256_cross), (512, r512_cross)):
            for r in range(1, max_r_c + 1):
                p = subprocess.run([a.gobin, "trace-cross", str(width), "shift", str(r), str(a.trace_n)],
                                   capture_output=True, text=True, check=True)
                traces = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
                if width == 256:
                    m_s, frec_s, brec_s, st_s = build_cross_256_coarse(r, [0xFFFF] * 15)
                    fin_s = {"x0": st_s[-1][:16], "x1": st_s[-1][16:32]}
                    lb_nz = cross_res[("cross-shared", 256, "nonzero")][0][r - 1]
                    lb_1b = cross_res[("cross-shared", 256, "onebyte")][0][r - 1]
                    bad_s, bad_b_s, min_nz_s, min_1b_s = eval_cross_traces(
                        m_s, frec_s + brec_s + [fin_s], st_s[0], traces, lb_nz, lb_1b)
                    total_bad_cross += bad_s + bad_b_s
                    print(json.dumps({
                        "check": "oracle-cross", "width": 256, "rounds": r, "traces": len(traces),
                        "unsat_shared": bad_s, "below_bound_shared": bad_b_s,
                        "min_obs_shared": [min_nz_s, min_1b_s], "bounds_shared": [lb_nz, lb_1b],
                    }), flush=True)
                else:
                    m_s, frec_s, brec_s, st_s = build_cross_512_shared(r, [0xFFFF] * 15)
                    fin_s = {f"x{i}": st_s[-1][16 * i:16 * i + 16] for i in range(4)}
                    lb_nz_s = cross_res[("cross-shared", 512, "nonzero")][0][r - 1]
                    lb_1b_s = cross_res[("cross-shared", 512, "onebyte")][0][r - 1]
                    bad_s, bad_b_s, min_nz_s, min_1b_s = eval_cross_traces(
                        m_s, frec_s + brec_s + [fin_s], st_s[0], traces, lb_nz_s, lb_1b_s)

                    m_c, frec_c, brec_c, st_c = build_cross_512_cancelled(r, [0xFFFF] * 15)
                    fin_c = {f"x{i}": st_c[-1][16 * i:16 * i + 16] for i in range(4)}
                    lb_nz_c = cross_res[("cross-cancelled", 512, "nonzero")][0][r - 1]
                    lb_1b_c = cross_res[("cross-cancelled", 512, "onebyte")][0][r - 1]
                    bad_c, bad_b_c, min_nz_c, min_1b_c = eval_cross_traces(
                        m_c, frec_c + brec_c + [fin_c], st_c[0], traces, lb_nz_c, lb_1b_c)
                    total_bad_cross += bad_s + bad_b_s + bad_c + bad_b_c
                    print(json.dumps({
                        "check": "oracle-cross", "width": 512, "rounds": r, "traces": len(traces),
                        "unsat_shared": bad_s, "below_bound_shared": bad_b_s,
                        "min_obs_shared": [min_nz_s, min_1b_s], "bounds_shared": [lb_nz_s, lb_1b_s],
                        "unsat_cancelled": bad_c, "below_bound_cancelled": bad_b_c,
                        "min_obs_cancelled": [min_nz_c, min_1b_c], "bounds_cancelled": [lb_nz_c, lb_1b_c],
                    }), flush=True)
        if total_bad_cross:
            raise SystemExit(f"oracle-cross failed: {total_bad_cross} violations")

    # 3. Forward vs Backward Impossible Differentials
    run_impdiff_comparison(a.r256, a.r512, a.rounds, threads=total_threads)


if __name__ == "__main__":
    main()


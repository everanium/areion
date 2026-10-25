#!/usr/bin/env python3
"""Section F: P2 = sigma o P1(sigma^-1 x ^ a) ^ b, a column rotation
combined with translations. sigma^-1 o P2 o sigma is the permutation
with constants sigma^-1(RC2), so the case reduces to a related-constant
differential between P1 and that permutation, with Delta_r =
RC1_r ^ sigma^-1(RC2_r); some of those have a zero byte, so the bound
is recomputed with the exact byte masks (coarse byte model)."""
import argparse
import concurrent.futures
import json
import multiprocessing as mp
import os
import sys
import time
from model import build, minimise
from layers import P1, P2pi, P2sh


def rot(b, k):
    o = [0] * 16
    for i in range(16):
        o[(i + 4 * k) % 16] = b[i]
    return o


def _solve_rot(task):
    width, R, name, k = task
    T = P2pi if name == 'pi' else P2sh
    masks = []
    for r in range(15):
        d = [x ^ y for x, y in zip(P1[r], rot(T[r], (4 - k) % 4))]
        masks.append(sum(1 << j for j in range(16) if d[j]))
    m, _ = build(width, R, masks)
    t = time.time()
    kmin, _ = minimise(m, 300)
    return {
        "width": width, "P2": name, "rotation": k, "rounds": R,
        "zero bytes in Delta": [16 - bin(x).count('1') for x in masks[:R]],
        "min_active_sboxes": kmin, "secs": round(time.time() - t, 1),
    }


def main():
    default_jobs = int(os.environ.get("AREION_THREADS", max(1, (os.cpu_count() or 2) - 2)))
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("width", type=int)
    ap.add_argument("--jobs", type=int, default=default_jobs)
    ap.add_argument("--threads", type=int, default=default_jobs)
    a = ap.parse_args()
    width = a.width
    R = 10 if width == 256 else 15
    workers = max(1, min(8, a.threads if a.threads != default_jobs else a.jobs))
    tasks = [(width, R, name, k) for name in ('pi', 'shift') for k in range(4)]
    ctx = mp.get_context("fork")
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as ex:
        for res in ex.map(_solve_rot, tasks):
            print(json.dumps(res), flush=True)


if __name__ == "__main__":
    main()


#!/usr/bin/env python3
"""Runs the P1 / P2 analysis of Areion under its two round-constant
tables. Every check prints its result to stdout; with --record the
output is also written to analysis/results/<check>.txt
(with _quick, _rc7p2-pi, _rc7p1-pi or _highs added for those options),
headed by the command that produced it.

    python3 analysis/run.py list
    python3 analysis/run.py <check> [--quick] [--record] [--rc7p1 shift|pi] [--rc7p2 shift|pi]
    python3 analysis/run.py linear|boomerang|weighted [--jobs N] [--rounds R]
    python3 analysis/run.py linear|weighted --solver highs [--rounds R] [--linear-rounds R]
    python3 analysis/run.py all --quick

Requirements: Go (the module's own version), Python 3.9 or later with
python-sat (and highspy for --solver highs), and for the hintegral check
a C compiler, make and an x86-64 CPU with AES-NI.
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BUILD = HERE / "build"
PY = HERE / "py"
RESULTS = HERE / "results"
GOBIN = BUILD / "analysis"
CBIN = BUILD / "integral"
RC7P2 = "shift"  # RC7 form of P2 for the checks that run one table (the library's); set by --rc7p2
RC7P1 = "shift"  # RC7 form of P1 (the library's is the published shift form); set by --rc7p1
JOBS = int(os.environ.get("AREION_THREADS", max(1, (os.cpu_count() or 2) - 2)))  # worker processes/threads; set by --threads or --jobs
ROUNDS = None  # cap on the round counts of the Areion-512 bounds tables; set by --rounds
LINEAR_ROUNDS = None  # weighted: separate cap on the weighted linear table; set by --linear-rounds
SOLVER = "sat"  # solver of the Areion-512 tables of linear / weighted (sat or highs); set by --solver
TIME_LIMIT = 0.0  # per-cell HiGHS MILP time limit in seconds for dissolve / inverse (0 = no limit); set by --time-limit


def sh(cmd, out, stdin=None, env=None):
    """Run cmd, echo and collect its stdout; fail on a non-zero exit."""
    cmd = [str(c) for c in cmd]
    p = subprocess.run(cmd, cwd=ROOT, stdin=stdin, capture_output=True, text=True, env=env)
    out.append(p.stdout)
    sys.stdout.write(p.stdout)
    sys.stdout.flush()
    if p.returncode != 0:
        sys.stderr.write(p.stderr)
        raise SystemExit(f"command failed ({p.returncode}): {' '.join(map(str, cmd))}")
    return p.stdout


def py(script, *args):
    return [sys.executable, str(PY / script), *map(str, args)]


def go(*args):
    return [str(GOBIN), *map(str, args)]


# ---------- preparation ----------

def generate(path, cmd, note=None, always=False):
    """Write cmd's stdout to path atomically, so an interrupted run never
    leaves a partial file that a later run would take as complete."""
    if path.exists() and not always:
        return
    if note:
        print(note, flush=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    with open(tmp, "w") as f:
        subprocess.run(cmd, cwd=ROOT, stdout=f, check=True)
    os.replace(tmp, path)


def source_hash():
    """Digest of the Go sources, so tables built by an older program are not reused."""
    h = hashlib.sha256()
    for p in sorted((HERE / "go").glob("*.go")):
        h.update(p.name.encode() + p.read_bytes())
    return h.hexdigest()[:12]


def prepare(need_feas=False, need_c=False):
    BUILD.mkdir(exist_ok=True)
    # go build is incremental, so the program always matches the sources
    tmp = BUILD / f"analysis.{os.getpid()}.tmp"
    subprocess.run(["go", "build", "-o", str(tmp), "./analysis/go"], cwd=ROOT, check=True)
    os.replace(tmp, GOBIN)
    generate(BUILD / "consts.json", [str(GOBIN), "consts"], always=True)
    generate(BUILD / "kat.txt", [str(GOBIN), "kat"], always=True)
    if need_feas:
        feas = BUILD / f"feas_p1{RC7P1}_{source_hash()}.json"
        generate(feas, [str(GOBIN), "feas"],
                 "building column feasibility tables (once per program version; about a minute on 16 cores)")
        os.environ["AREION_FEAS"] = str(feas)  # read by py/refined.py
    if need_c:
        if not have_aesni():
            raise SystemExit("hintegral needs an x86-64 CPU with AES-NI (Linux /proc/cpuinfo)")
        write_consts_h()
        # make rebuilds only when integral.c or consts.h changed
        subprocess.run(["make", "-s", "-C", str(HERE / "c"), f"BUILD={BUILD}"], check=True)


def have_aesni():
    try:
        flags = open("/proc/cpuinfo").read().split()
    except OSError:
        flags = []
    return platform.machine() in ("x86_64", "AMD64") and "aes" in flags


def write_consts_h():
    c = json.load(open(BUILD / "consts.json"))

    def arr(name, t):
        rows = ",\n".join("  {" + ",".join(f"0x{b:02x}" for b in r) + "}" for r in t)
        return f"static const unsigned char {name}[15][16] = {{\n{rows}\n}};\n"

    p1pi = "static const unsigned char RC7P1PI[16] = {" + ",".join(f"0x{b:02x}" for b in c["P1rc7pi"]) + "};\n"
    text = ("/* Generated by analysis/run.py from build/consts.json. */\n"
            + arr("RC1", c["P1"]) + arr("RC2PI", c["P2pi"]) + arr("RC2SH", c["P2shift"]) + p1pi)
    h = BUILD / "consts.h"
    if not h.exists() or h.read_text() != text:  # unchanged header keeps make from rebuilding
        tmp = BUILD / f"consts.h.{os.getpid()}.tmp"
        tmp.write_text(text)
        os.replace(tmp, h)


# ---------- checks ----------

def c_ref(q, out):
    sh(["go", "test", "-count=1", "./analysis/go"], out)
    sh(go("check"), out)


def c_oracle(q, out):
    n = 50 if q else 400
    for w, r in ((256, 10), (512, 15)):
        for v in ("pi", "shift"):
            path = BUILD / f"trace_{w}_{v}_p1{RC7P1}.jsonl"
            tmp = BUILD / f"{path.name}.{os.getpid()}.tmp"  # parallel runs share build/
            with open(tmp, "w") as f:
                subprocess.run(go("trace", w, v, r, n), cwd=ROOT, stdout=f, check=True)
            os.replace(tmp, path)
            sh(py("model.py", w, r, "--check", path), out)
            if w == 256:  # the refined model behind the Areion-256 bounds
                sh(py("refined.py", v, r, "--check", path), out)


def c_related(q, out):
    # the coarse model takes Delta_r nonzero in every byte; confirm it for the selected P1
    c = json.load(open(BUILD / "consts.json"))
    p1 = [r[:] for r in c["P1"]]
    if RC7P1 == "pi":
        p1[7] = c["P1rc7pi"]
    zero = sum(a == b for t in (c["P2pi"], c["P2shift"]) for r in range(15) for a, b in zip(p1[r], t[r]))
    line = f"zero bytes in Delta_r = RC1_r ^ RC2_r over 15 rounds, both RC7 forms of P2: {zero}\n"
    out.append(line)
    sys.stdout.write(line)
    if zero:
        raise SystemExit("the coarse model assumes Delta_r nonzero in every byte")
    sh(py("model.py", "aes", 4), out)
    for w, rounds in ((256, [10] if q else range(1, 11)), (512, [4] if q else range(1, 16))):
        for r in rounds:
            sh(py("model.py", w, r), out)


def c_refined(q, out):
    for v in ("pi", "shift"):
        for r in (range(1, 5) if q else range(1, 11)):
            sh(py("refined.py", v, r), out)


def c_symmetry(q, out):
    sh(go("sym"), out)
    sh(go("symctl"), out)


def c_sbox(q, out):
    sh(py("sbox_selfeq.py"), out)
    sh(go("sboxsub"), out)
    sh(py("lines_check.py"), out)


def c_subspace(q, out):
    sh(py("gentrail.py"), out)


def c_bclr(q, out):
    sh(py("layers.py"), out)
    sh(py("bclr_full.py"), out)
    sh(py("bclr_quot.py"), out)


def c_cosets(q, out):
    sh(go("diag"), out)
    if q:
        sh(go("coset2", 256, "quick"), out)
    else:
        sh(go("coset2", 256), out)
        sh(go("coset2", 512), out)


def c_impdiff(q, out):
    sh(py("impdiff.py", *((3, 3) if q else (10, 15)), "--threads", JOBS), out)


def c_values(q, out):
    if q:
        sh(go("uniform", 256, 2, RC7P2), out)
    else:
        sh(go("zero", RC7P2), out)
        if RC7P2 == "shift":
            sh(go("zero", "pi"), out)  # full rounds reach word 7, where the two forms differ
        sh(go("uniform", 256, 4, RC7P2), out)
        sh(go("uniform", 512, 6, RC7P2), out)


def c_integral(q, out):
    if q:
        sh(go("integral", 256, 3, 2, RC7P2), out)
    else:
        sh(go("integral", 256, 4, 3, RC7P2), out)
        sh(go("integral", 512, 6, 3, RC7P2), out)


def c_hintegral(q, out):
    sh([str(CBIN), "kat"], out, stdin=open(BUILD / "kat.txt"))
    # self-test: one order-4 set, two thread counts, identical output
    a = sh([str(CBIN), "sum", 256, 3, 4, 1, 0, 10, 1, RC7P2], out)
    b = sh([str(CBIN), "sum", 256, 3, 4, 1, 0, 7, 1, RC7P2], out)
    if a != b:
        raise SystemExit("hintegral self-test: output depends on the thread count")
    if q:
        return
    t = str(JOBS)
    for r in (3, 4, 5):
        for b_ in (0, 1):
            sh([str(CBIN), "sum", 256, r, 4, b_, 0, t, r * 10 + b_, RC7P2], out)
    for r in (5, 6, 7, 8):
        for b_ in range(4):
            sh([str(CBIN), "sum", 512, r, 4, b_, 0, t, r * 10 + b_, RC7P2], out)
    if RC7P2 == "shift":
        for b_ in range(4):  # round 8 is the first to use word 7, where the two forms differ
            sh([str(CBIN), "sum", 512, 8, 4, b_, 0, t, 80 + b_, "pi"], out)
    sh([str(CBIN), "sum", 256, 4, 5, 1, 1, t, 451, RC7P2], out)
    sh([str(CBIN), "sum", 512, 6, 5, 1, 1, t, 651, RC7P2], out)


def c_affine(q, out):
    sh(py("affeq.py"), out)
    sh(py("affeq_rel.py", 256, "--threads", JOBS), out)
    if not q:
        sh(py("affeq_rel.py", 512, "--threads", JOBS), out)


def model_hash():
    """Digest of the trail models, so tables built by older models are not
    reused. The search code (bounds.py) is left out: it finds the minima
    of the models but does not define them, so it can change without
    discarding the tables."""
    h = hashlib.sha256()
    for name in ("model.py", "linear.py", "trails.py"):
        h.update(name.encode() + (PY / name).read_bytes())
    return h.hexdigest()[:12]


def table_prefix():
    return BUILD / f"bounds_{model_hash()}_"


def fill(kind, width, upto, out):
    """Fill the cached table of minima for 1 .. upto rounds (resumes where it stopped).
    --rounds caps the Areion-512 tables only: the Areion-256 ones are cheap."""
    if ROUNDS is not None and width == 512:
        upto = min(upto, ROUNDS)
    path = f"{table_prefix()}{kind}_{width}.json"
    if SOLVER == "highs" and width == 512 and kind == "linear":
        # rounds missing from the SAT table, by the MILP solver, in a table of their own
        sh(py("milp.py", kind, "--upto", upto, "--table", f"{table_prefix()}{kind}_{width}_milp.json",
              "--sat-table", path, "--threads", JOBS), out)
        return
    sh(py("bounds.py", kind, width, "--upto", upto, "--table", path, "--rounds-at-once", JOBS,
          "--threads", JOBS, "--quiet"), out)


def c_linear(q, out):
    sh(py("linear.py", "aes", 4), out)          # 4 AES rounds: 25, as for differences
    # the three search paths agree: one solver without windows, with windows, cube-and-conquer
    t = BUILD / f"bounds_check_{os.getpid()}.json"
    t.write_text('{"1": 0, "2": 2, "3": 6, "4": 11}')   # linear Areion-512 r1..4
    try:
        res = []
        for extra in (["--no-windows"], [], ["--jobs", max(2, JOBS), "--cubes-only"]):
            line = sh(py("bounds.py", "linear", 512, 5, "--table", t, "--quiet", *extra), out)
            res.append(json.loads(line.strip().splitlines()[-1])["min_active_sboxes"])
    finally:
        t.unlink()
    if len(set(res)) != 1:
        raise SystemExit(f"search paths disagree on linear Areion-512, 5 rounds: {res}")
    if q:
        return
    fill("linear", 256, 10, out)
    fill("linear", 512, 15, out)
    # the Areion-512 table as computed (SAT, and HiGHS where --solver highs filled it)
    # and its window bound over the 15 rounds
    sat = read_table(f"{table_prefix()}linear_512.json")
    milp = read_table(f"{table_prefix()}linear_512_milp.json") if SOLVER == "highs" else {}
    table = {**milp, **sat}
    row = " ".join(f"{r}:{v}{'' if r in sat else 'h'}" for r, v in sorted(table.items()))
    note(f"== linear Areion-512, minima per round count (h: HiGHS): {row}", out)
    note(f"== linear Areion-512, 15 rounds: at least {window_bound(15, table)} active S-boxes "
         f"(windows of the round counts above)", out)


def read_table(path):
    return {int(k): v for k, v in json.load(open(path)).items()} if os.path.exists(path) else {}


def window_bound(rounds, table):
    """Largest sum of known minima over a split of the rounds into shorter windows (bounds.py)."""
    best = [0] * (rounds + 1)
    for r in range(1, rounds + 1):
        best[r] = max([best[r - w] + table[w] for w in range(1, r + 1) if w < rounds and w in table] + [0])
    return best[rounds]


def note(line, out):
    out.append(line + "\n")
    print(line, flush=True)


def c_boomerang(q, out):
    r256, r512 = (4, 4) if q else (9, 14)
    for kind in ("single", "related"):
        fill(kind, 256, r256, out)
        fill(kind, 512, r512, out)
    sh(py("boomerang.py", "--prefix", table_prefix(), *([] if q else ["--refined"])), out)


def weighted_tables():
    """The chain weights and the path prefix of the weighted tables."""
    chain = BUILD / f"chain_{source_hash()}.json"
    generate(chain, [str(GOBIN), "chain"],
             note="exact weights of the S-box chain of F3 (once per program version; about 2 min on 16 cores)")
    # tables keyed by the trail models, the weighted models and the weights (not the search)
    h = hashlib.sha256()
    h.update(model_hash().encode() + (PY / "wmodel.py").read_bytes() + chain.read_bytes())
    return chain, BUILD / f"weighted_{h.hexdigest()[:12]}_"


def c_weighted(q, out):
    chain, prefix = weighted_tables()
    lin, single, related = (4, 4, 4) if q else (15, 14, 14)
    if ROUNDS is not None:
        lin, single = min(lin, ROUNDS), min(single, ROUNDS)  # the related table ignores the cap
    if LINEAR_ROUNDS is not None:
        lin = min(lin, LINEAR_ROUNDS)
    if SOLVER == "highs":
        # linear and single by the MILP solver (tables <kind>_milp.json); related stays on
        # SAT, whose window bound settles every round count at once
        for kind, upto in (("linear", lin), ("single", single)):
            sh(py("milp.py", kind, "--upto", upto, "--weights", chain, "--table", f"{prefix}{kind}_milp.json",
                  "--sat-table", f"{prefix}{kind}.json", "--threads", JOBS), out)
        lin = single = 0
    sh(py("weighted.py", "--weights", chain, "--prefix", prefix, "--plain-prefix", table_prefix(),
          "--linear", lin, "--single", single, "--related", related, "--quiet"), out)


def c_solvers(q, out):
    """HiGHS alone, from an empty table, against the SAT tables of linear,
    single and weighted, on every round count the SAT tables hold."""
    chain, wprefix = weighted_tables()
    upto = 4 if q else 15
    cases = (("linear", None, f"{table_prefix()}linear_512.json"),
             ("single", None, f"{table_prefix()}single_512.json"),
             ("linear", chain, f"{wprefix}linear.json"),
             ("single", chain, f"{wprefix}single.json"))
    bad = []
    for kind, weights, sat_path in cases:
        sat = read_table(sat_path)
        n = min(upto, max((r for r in range(1, upto + 1) if all(k in sat for k in range(1, r + 1))), default=0))
        if n == 0:
            note(f"== {kind}{' weighted' if weights else ''}: no SAT table yet; run linear / boomerang / weighted first", out)
            continue
        t = BUILD / f"solvers_check_{os.getpid()}.json"
        try:
            sh(py("milp.py", kind, "--upto", n, "--table", t, "--threads", JOBS,
                  *(["--weights", weights] if weights else [])), out)
            mine = read_table(t)
        finally:
            if t.exists():
                t.unlink()
        name = f"{kind}{' weighted' if weights else ''} Areion-512"
        rows = " ".join(f"{r}:{sat[r]}/{mine.get(r)}" for r in range(1, n + 1))
        same = all(sat[r] == mine.get(r) for r in range(1, n + 1))
        note(f"== {name}, rounds 1..{n} (SAT/HiGHS): {rows} -> {'same' if same else 'DIFFERENT'}", out)
        if not same:
            bad.append(name)
    if bad:
        raise SystemExit(f"SAT and HiGHS disagree: {', '.join(bad)}")


def c_dissolve(q, out):
    feas_d = BUILD / f"feas_dissolve_p1{RC7P1}_{source_hash()}.json"
    generate(feas_d, [str(GOBIN), "feas-dissolve"],
             note="building ladder column feasibility tables (once per program version; a few seconds)")
    os.environ["AREION_FEAS_DISSOLVE"] = str(feas_d)
    r256, r512 = (5, 6) if q else (10, 15)
    if ROUNDS is not None:
        r256, r512 = min(r256, ROUNDS), min(r512, ROUNDS)
    tlim_args = ["--time-limit", TIME_LIMIT] if TIME_LIMIT and TIME_LIMIT > 0 else []
    sh(py("dissolve.py", "--r256", r256, "--r512", r512, "--jobs", JOBS, "--threads", JOBS,
          "--gobin", GOBIN, "--trace-n", 25 if q else 100, *tlim_args), out)
    sh(go("dissolve", r256, r512, *(["quick"] if q else [])), out)


def c_inverse(q, out):
    r256, r512 = (5, 6) if q else (10, 15)
    tlim_args = ["--time-limit", TIME_LIMIT] if TIME_LIMIT and TIME_LIMIT > 0 else []
    rnd_args = ["--rounds", ROUNDS] if ROUNDS is not None else []
    sh(go("cross", r256, r512, *(["quick"] if q else [])), out)
    sh(py("inverse_model.py", "--r256", r256, "--r512", r512, "--jobs", JOBS, "--threads", JOBS,
          "--gobin", GOBIN, "--trace-n", 50 if q else 200, *rnd_args, *tlim_args), out)


def c_clearing(q, out):
    sh(py("clearing_cost.py", *(["--quick"] if q else [])), out)


CHECKS = {
    # name: (function, needs feas.json, needs C, description, full runtime, quick runtime)
    "ref": (c_ref, False, False, "reference rounds and oracle match the library", "seconds", "seconds"),
    "oracle": (c_oracle, True, False, "real activity traces satisfy the coarse and refined models", "minutes", "about 1 min"),
    "related": (c_related, False, False, "related-constant bounds P1 vs P2, coarse model", "minutes", "seconds"),
    "refined": (c_refined, True, False, "related-constant Areion-256 with column feasibility", "minutes", "seconds"),
    "symmetry": (c_symmetry, False, False, "symmetries of the constant-free round (A)", "seconds", "seconds"),
    "sbox": (c_sbox, False, False, "S-box: commuting maps, linear structures, affine subspaces, cycles, lines (A, B1, B4, F)", "seconds", "seconds"),
    "subspace": (c_subspace, False, False, "generic subspace trails, exact propagation (B2)", "about 4 min", "about 4 min"),
    "bclr": (c_bclr, False, False, "layered form and the BCLR criterion (B3)", "seconds", "seconds"),
    "cosets": (c_cosets, False, False, "weak cosets: direction check and coset trails (B4)", "about 20 min", "seconds"),
    "impdiff": (c_impdiff, False, False, "byte-level impossible output patterns of P1 ^ P2 (C)", "up to 1 h", "seconds"),
    "values": (c_values, False, False, "byte values of P1_r(x) ^ P2_r(x ^ delta) (C)", "about 30 min", "seconds"),
    "integral": (c_integral, False, False, "Lambda-set sums of order 1..3 (D)", "about 30 min", "seconds"),
    "hintegral": (c_hintegral, False, True, "Lambda-set sums of order 4 and 5, AES-NI (D)", "about 4 h", "seconds"),
    "affine": (c_affine, False, False, "byte-structured affine equivalence (F)", "minutes", "seconds"),
    "linear": (c_linear, False, False, "linear trail bounds, one table for P1, P2 and both RC7 forms (H)",
               "--rounds 7: about 5 h; --solver highs --rounds 10: about 1 h; resumes", "a few minutes"),
    "boomerang": (c_boomerang, True, False, "boomerang estimates, four assignments of the two tables (I)",
                  "--rounds 7: about 2 h; uncapped: open-ended; resumes", "a few minutes"),
    "weighted": (c_weighted, False, False, "Areion-512 bounds, the S-box chain of F3 at its exact maximum over the constants (H, I)",
                 "--solver highs --rounds 10 --linear-rounds 8: about 20 h; resumes", "a few minutes"),
    "solvers": (c_solvers, False, False, "SAT and HiGHS minima agree on the round counts both reach (H, I)",
                "about 15 min (more as the SAT tables grow)", "a few minutes"),
    "dissolve": (c_dissolve, False, False, "parameterized P2^(k) dependence-dissolution spectrum across rounds (J)",
                 "about 2 min", "about 15 s"),
    "inverse": (c_inverse, True, False, "InversePermute backward & cross-composition C_r(x) = P2_r^-1(P1_r(x)) analysis (K)",
                "--rounds 7: about 15 min; --rounds 10: hours; resumes", "about 20 s"),
    "clearing": (c_clearing, False, False, "epilogue register and stack clearing instruction & runtime cost (L)",
                 "about 2 min", "about 25 s"),
}
HEAVY = ("linear", "boomerang", "weighted")  # skipped by 'all' without --quick: run them on their own


def run(name, quick, record):
    fn, feas, c, desc, _, _ = CHECKS[name]
    form = ("" if RC7P2 == "shift" else f" --rc7p2 {RC7P2}") + ("" if RC7P1 == "shift" else f" --rc7p1 {RC7P1}")
    if (name in HEAVY or name in ("dissolve", "inverse")) and ROUNDS is not None:
        form += f" --rounds {ROUNDS}"
    if name == "weighted" and LINEAR_ROUNDS is not None:
        form += f" --linear-rounds {LINEAR_ROUNDS}"
    if name in ("linear", "weighted") and SOLVER != "sat":
        form += f" --solver {SOLVER}"
    if name in ("dissolve", "inverse") and TIME_LIMIT and TIME_LIMIT > 0:
        form += f" --time-limit {TIME_LIMIT:g}"
    header = f"$ python3 analysis/run.py {name}{' --quick' if quick else ''}{form}\n"
    print(f"== {name}: {desc}", flush=True)
    prepare(need_feas=feas, need_c=c)
    out = []
    t0 = time.time()
    fn(quick, out)
    print(f"== {name}: done in {time.time() - t0:.0f} s", flush=True)
    if record:
        RESULTS.mkdir(exist_ok=True)
        suffix = (("_quick" if quick else "") + ("" if RC7P2 == "shift" else "_rc7p2-" + RC7P2)
                  + ("" if RC7P1 == "shift" else "_rc7p1-" + RC7P1)
                  + ("_" + SOLVER if name in ("linear", "weighted") and SOLVER != "sat" else ""))
        (RESULTS / f"{name}{suffix}.txt").write_text(header + "".join(out))


def main():
    global RC7P2, RC7P1, JOBS, ROUNDS, LINEAR_ROUNDS, SOLVER, TIME_LIMIT
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("check", help="'list', 'all', 'clean' or a check name")
    ap.add_argument("--quick", action="store_true", help="reduced rounds / orders / seeds")
    ap.add_argument("--record", action="store_true",
                    help="write analysis/results/<check>.txt (with _quick, _rc7p2-pi, _rc7p1-pi or _highs added for those options)")
    ap.add_argument("--rc7p1", choices=("shift", "pi"), default="shift",
                    help="RC7 form of P1 for every check except ref, never in comparisons with the library: shift (published) or pi (plain pi word 7)")
    ap.add_argument("--jobs", type=int, default=JOBS,
                    help=f"worker processes for SAT / MILP bounds and parallel checks (default {JOBS})")
    ap.add_argument("--threads", type=int, default=None,
                    help=f"worker threads/processes across SAT, HiGHS MILP cubes, and C checks (default: --jobs or $AREION_THREADS)")
    ap.add_argument("--rounds", type=int, help="cap the Areion-512 round counts of the linear / boomerang / weighted / inverse tables")
    ap.add_argument("--linear-rounds", type=int, help="weighted: cap the weighted linear table separately (default: --rounds)")
    ap.add_argument("--solver", choices=("sat", "highs"), default="sat",
                    help="linear / weighted: fill the Areion-512 tables with the MILP solver HiGHS")
    ap.add_argument("--time-limit", type=float, default=0.0,
                    help="dissolve / inverse: per-cell HiGHS MILP time limit in seconds (default 0 = no limit)")
    ap.add_argument("--rc7p2", choices=("shift", "pi"), default="shift",
                    help="RC7 form of P2 for values, integral and hintegral; the other checks that depend on P2 run both forms")
    a = ap.parse_args()
    RC7P2 = a.rc7p2
    RC7P1 = a.rc7p1
    JOBS = max(1, a.threads if a.threads is not None else a.jobs)
    ROUNDS, LINEAR_ROUNDS, SOLVER, TIME_LIMIT = a.rounds, a.linear_rounds, a.solver, a.time_limit
    os.environ["AREION_THREADS"] = str(JOBS)
    os.environ["GOMAXPROCS"] = str(JOBS)
    os.environ["AREION_RC7P1"] = RC7P1  # read by the Go, Python and C programs
    if a.check == "list":
        for k, (_, _, _, d, full, quick) in CHECKS.items():
            print(f"{k:14} {d}  [full: {full}; --quick: {quick}]")
    elif a.check == "clean":
        if BUILD.exists():
            BUILD.relative_to(HERE)  # never leaves analysis/
            shutil.rmtree(BUILD)
    elif a.check == "all":
        failed = []
        for k in CHECKS:
            if k in HEAVY and not a.quick:
                print(f"== {k}: skipped by 'all' (open-ended); run it on its own with --rounds", flush=True)
                continue
            if k == "hintegral" and not have_aesni():
                print("== hintegral: skipped (needs an x86-64 CPU with AES-NI)", flush=True)
                continue
            try:
                run(k, a.quick, a.record)
            except (SystemExit, subprocess.CalledProcessError) as e:
                print(f"== {k}: FAILED ({e})", flush=True)
                failed.append(k)
        if failed:
            raise SystemExit(f"failed checks: {', '.join(failed)}")
    elif a.check in CHECKS:
        run(a.check, a.quick, a.record)
    else:
        raise SystemExit(f"unknown check {a.check!r}; see 'list'")


if __name__ == "__main__":
    main()

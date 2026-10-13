"""Locations and constants shared by the analysis scripts. BUILD holds
generated inputs (consts.json, kat.txt, feasibility tables, traces);
analysis/run.py fills it. AREION_RC7P1=pi switches P1 to the pi form of
RC7 (the library uses the published, shifted form)."""
import json
import os
from pathlib import Path

BUILD = Path(os.environ.get("AREION_ANALYSIS_BUILD", Path(__file__).resolve().parents[1] / "build"))


RC7P1 = os.environ.get("AREION_RC7P1", "shift") or "shift"
if RC7P1 not in ("pi", "shift"):
    raise SystemExit(f"unknown RC7 form for P1: {RC7P1}")
def feas_path():
    """Feasibility tables: AREION_FEAS (set by run.py, named per program
    version), else the newest table built for this RC7 form of P1."""
    if "AREION_FEAS" in os.environ:
        return Path(os.environ["AREION_FEAS"])
    found = sorted(BUILD.glob(f"feas_p1{RC7P1}_*.json"), key=lambda p: p.stat().st_mtime)
    if not found:
        raise SystemExit("no feasibility tables in build/; run analysis/run.py refined once")
    return found[-1]


def constants(library=False):
    """P1, P2 (pi form) and P2 (shift form) as lists of 15 rows of 16
    bytes; P1 follows AREION_RC7P1 unless library is set."""
    c = json.load(open(BUILD / "consts.json"))
    p1 = [row[:] for row in c["P1"]]
    if RC7P1 == "pi" and not library:
        p1[7] = c["P1rc7pi"]
    return p1, c["P2pi"], c["P2shift"]

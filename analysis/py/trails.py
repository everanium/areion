#!/usr/bin/env python3
"""The trail models searched by bounds.py, with per-round S-box lists
(m.rounds[0 .. rounds-1]). run.py keys its cached tables of minima by a
digest of this file, model.py and linear.py: the models define the
numbers, the search code in bounds.py only finds them.

Kinds:
  linear         linear trails, shared S-box layer counted once      (linear.py)
  linear-double  the same, the shared layer counted once per branch  (linear.py --double)
  single         differential trails of one permutation             (model.py, zero Delta)
  related        related-constant differential trails P1(u) vs P2(u ^ delta),
                 Delta_r nonzero in every byte (model.py, coarse model)
Width: aes (plain AES rounds; linear and single only), 256 or 512.
"""
import linear
import model


def build(kind, width, rounds):
    """Model with per-round S-box lists (m.rounds[0 .. rounds-1])."""
    if kind in ("linear", "linear-double"):
        m, _ = linear.build(width, rounds, kind == "linear-double")
    elif kind == "single":
        if width == "aes":
            m, _ = model.build_aes(rounds)
        else:
            m, rec = model.build(width, rounds, [0] * 15)
            first = rec[0]
            words = [first["A"], first["B"]] if width == 256 else [first[w] for w in "abcd"]
            m.cl.append(sum(words, []))       # nonzero input difference
    elif kind == "related":
        if width == "aes":
            raise SystemExit("related needs WIDTH 256 or 512")
        m, _ = model.build(width, rounds, [0xFFFF] * 15)
    else:
        raise SystemExit(f"unknown kind {kind!r}")
    rounds_lits = [r for r in m.rounds if r][:rounds]
    assert len(rounds_lits) == rounds, (len(rounds_lits), rounds)
    m.rounds = rounds_lits
    return m

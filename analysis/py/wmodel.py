#!/usr/bin/env python3
"""The weighted trail models of Areion-512 searched by weighted.py: the
models of trails.py with each round's S-box list replaced by a list in
which every literal appears once per bit it is charged, and the weights
taken from the Go subcommand chain. run.py keys the cached weighted
tables by a digest of this file, the trail models and the weights; the
search and the report in weighted.py can change without discarding them.
"""
import math

from trails import build


def chain_source(i):
    """Model.sr(w)[i] = w[chain_source(i)]: the byte of the first S-box layer
    that reaches byte i of the second."""
    return (i + 4 * (i % 4)) % 16


def bits(count):
    """-log2(count / 256) rounded down."""
    return math.floor(8 - math.log2(count))


def weights(chain):
    w = {"linear": {"a": 8 - int(math.log2(chain["sbox_walsh"])),
                    "single": 8 - int(math.log2(chain["sbox_walsh"])),
                    "pair": bits(chain["chain_walsh"])},
         "single": {"a": bits(chain["sbox_diff"]), "chain": bits(chain["chain_diff_one_table"])},
         "related": {"a": bits(chain["sbox_diff"]),
                     "chain": min(bits(chain["sbox_diff"]), bits(chain["chain_diff_two_tables"]))}}
    assert 2 ** (8 - w["linear"]["a"]) == chain["sbox_walsh"]
    assert w["linear"]["pair"] <= w["linear"]["single"]
    return w


def weighted_model(kind, rounds, w):
    """The model of trails.py with each round's S-box list replaced by a
    list in which every literal appears once per bit it is charged."""
    m = build(kind, 512, rounds)
    plain = [list(r) for r in m.rounds]
    lists = []
    for r in plain:
        a, c, second = r[:16], r[16:32], r[32:48]
        assert len(r) == 48
        lits = a * w[kind]["a"]
        for i in range(16):
            x, y = c[chain_source(i)], second[i]
            if kind == "linear":
                # q: some S-box of the chain active; e: exactly one active
                q, e = m.new(2)
                m.cl += [[-x, q], [-y, q], [-x, y, e], [x, -y, e]]
                lits += [q] * w[kind]["pair"] + [e] * (w[kind]["single"] - w[kind]["pair"])
            elif kind == "single":
                assert x == y                 # one permutation: the second S-box is active with the first
                lits += [x] * w[kind]["chain"]
            else:
                q = m.new(1)[0]
                m.cl += [[-x, q], [-y, q]]
                lits += [q] * w[kind]["chain"]
        lists.append(lits)
    m.rounds = lists
    m.sboxes = sum(lists, [])
    return m, sum(plain, [])

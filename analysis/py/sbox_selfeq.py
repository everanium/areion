#!/usr/bin/env python3
"""GF(2)-linear byte maps M with S(M x) = M S(x) for the AES S-box.

Every linear M for which some linear N gives N o inv = inv o M has the form
x -> a*x^(2^i)
(the 2040 linear self-equivalences of inversion); a map commuting with S
must be of that form, so testing those 2040 candidates is exhaustive for
GF(2)-linear M. Also counts the linear structures of the component
functions of S."""

def gmul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a = ((a << 1) ^ 0x11b) if a & 0x80 else a << 1
        b >>= 1
    return r

def gpow(a, e):
    r = 1
    while e:
        if e & 1: r = gmul(r, a)
        a = gmul(a, a); e >>= 1
    return r

def inv(x): return gpow(x, 254) if x else 0

def aff(x):
    r = 0x63
    for i in range(8):
        b = 0
        for k in (0, 4, 5, 6, 7):
            b ^= (x >> ((i + k) % 8)) & 1
        r ^= b << i
    return r

S = [aff(inv(x)) for x in range(256)]
assert S[0] == 0x63 and S[1] == 0x7c and S[0x53] == 0xed, "S-box mismatch"


def search():
    """Every linear map commuting with S has the form x -> a*x^(2^i)."""
    sols = []
    for a in range(1, 256):
        for i in range(8):
            M = [gmul(a, gpow(x, 1 << i)) if x else 0 for x in range(256)]
            if all(S[M[x]] == M[S[x]] for x in range(256)):
                sols.append((a, i))
    print("linear maps commuting with S (a, i) for x -> a*x^(2^i):", sols)


def linear_structures():
    """Pairs (u, a), u and a nonzero, with u.S(x) ^ u.S(x ^ a) constant."""
    count = 0
    for u in range(1, 256):
        f = [bin(u & S[x]).count("1") & 1 for x in range(256)]
        for a in range(1, 256):
            if len({f[x] ^ f[x ^ a] for x in range(256)}) == 1:
                count += 1
    print("linear structures (u, a) of the S-box component functions:", count)


if __name__ == "__main__":
    search()
    linear_structures()

package main

// Section D: empirical side. Lambda-sets of order 1..maxorder (default
// 3: 2^8, 2^16, 2^24 texts; active bytes in diagonal 0 or 3 of each
// block, the bytes ShiftRows gathers into one column) through reduced
// rounds, for P1 alone and for the
// SoEM22 core T(u) = P1(u) ^ P2(u ^ delta) with a random delta. Counts
// output bytes whose XOR over the set is zero (balanced); a random
// function balances about one output byte in 256 by chance.

import (
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
)

func integralMain() {
	width, _ := strconv.Atoi(os.Args[2])
	maxR, _ := strconv.Atoi(os.Args[3])
	maxOrder := 3
	if len(os.Args) > 4 {
		maxOrder, _ = strconv.Atoi(os.Args[4])
	}
	t2, suffix := formArg(5)
	nb := width / 8
	rng := rand.New(rand.NewPCG(31, 41))
	run := func(order, blk, diag, rounds int) (int, int) {
		base := make([]byte, nb)
		delta := make([]byte, nb)
		for i := range base {
			base[i] = byte(rng.Uint32())
			delta[i] = byte(rng.Uint32())
		}
		pos := make([]int, order)
		for k := range pos {
			pos[k] = 16*blk + (4*diag+5*k)%16
		}
		sumP := make([]byte, nb)
		sumT := make([]byte, nb)
		a := make([]byte, nb)
		b := make([]byte, nb)
		for v := 0; v < 1<<(8*order); v++ {
			copy(a, base)
			for k, p := range pos {
				a[p] = byte(v >> (8 * k))
			}
			for i := range b {
				b[i] = a[i] ^ delta[i]
			}
			if width == 256 {
				p256r((*State256)(a), &roundConstantsP1, rounds)
				p256r((*State256)(b), t2, rounds)
			} else {
				p512r((*State512)(a), &roundConstantsP1, rounds)
				p512r((*State512)(b), t2, rounds)
			}
			for i := range a {
				sumP[i] ^= a[i]
				sumT[i] ^= a[i] ^ b[i]
			}
		}
		zp, zt := 0, 0
		for i := range sumP {
			if sumP[i] == 0 {
				zp++
			}
			if sumT[i] == 0 {
				zt++
			}
		}
		return zp, zt
	}
	for rounds := 1; rounds <= maxR; rounds++ {
		for order := 1; order <= maxOrder; order++ {
			bestP, bestT := 0, 0
			for blk := 0; blk < nb/16; blk++ {
				for diag := 0; diag < 4; diag += 3 {
					zp, zt := run(order, blk, diag, rounds)
					bestP, bestT = max(bestP, zp), max(bestT, zt)
				}
			}
			fmt.Printf("Areion-%d r%d order %d%s: balanced bytes (max over sets) P1 %d / %d, P1(u)^P2(u^delta) %d / %d\n",
				width, rounds, order, suffix, bestP, nb, bestT, nb)
		}
	}
}

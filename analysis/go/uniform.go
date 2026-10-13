package main

// Section C: value level. For the SoEM22 core on reduced rounds, per
// output byte of T(x) = P1_r(x) ^ P2_r(x ^ delta), a 256-bin histogram
// over 2^24 random x, for a random delta and for delta = 0. Reports the
// largest chi-square over the bytes (255 degrees of freedom: mean 255,
// sd about 22.6) and the number of byte values never seen (an impossible
// value would stay at zero; a uniform byte misses a given value with
// probability about e^-65536 here).

import (
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
)

func uniformMain() {
	width, _ := strconv.Atoi(os.Args[2])
	maxR, _ := strconv.Atoi(os.Args[3])
	t2, suffix := formArg(4)
	nb := width / 8
	const n = 1 << 24
	for _, dz := range []bool{false, true} {
		for rounds := 1; rounds <= maxR; rounds++ {
			rng := rand.New(rand.NewPCG(uint64(rounds), 5))
			delta := make([]byte, nb)
			if !dz {
				for i := range delta {
					delta[i] = byte(rng.Uint32())
				}
			}
			hist := make([][256]int, nb)
			a := make([]byte, nb)
			b := make([]byte, nb)
			for t := 0; t < n; t++ {
				for i := 0; i < nb; i += 8 {
					v := rng.Uint64()
					for k := 0; k < 8; k++ {
						a[i+k] = byte(v >> (8 * k))
					}
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
					hist[i][a[i]^b[i]]++
				}
			}
			maxChi, missing := 0.0, 0
			exp := float64(n) / 256
			for i := range hist {
				chi := 0.0
				for _, c := range hist[i] {
					d := float64(c) - exp
					chi += d * d / exp
					if c == 0 {
						missing++
					}
				}
				maxChi = max(maxChi, chi)
			}
			label := "random delta"
			if dz {
				label = "delta = 0"
			}
			fmt.Printf("Areion-%d r%d %s%s: max chi-square over %d bytes %.1f; byte values never seen: %d\n", width, rounds, label, suffix, nb, maxChi, missing)
		}
	}
}

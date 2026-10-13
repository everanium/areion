package main

// Section C: empirical side. Frequency of zero bytes in
// P1_r(x) ^ P2_r(x ^ delta) for reduced and full rounds, random x and a
// random delta with every byte nonzero (odd); each byte should be zero
// about 1/256 of the time.

import (
	"fmt"
	"math/rand/v2"
)

func p256r(s *State256, rcs *[15][16]byte, rounds int) {
	x0 := (*Block)(s[0:16])
	x1 := (*Block)(s[16:32])
	for r := 0; r < rounds; r++ {
		var temp Block
		if r%2 == 0 {
			temp = *x0
			roundNoKey(&temp)
			xorBlock(&temp, &temp, &rcs[r])
			roundNoKey(&temp)
			xorBlock(&temp, &temp, x1)
			finalRoundNoKey(x0)
			*x1 = temp
		} else {
			temp = *x1
			roundNoKey(&temp)
			xorBlock(&temp, &temp, &rcs[r])
			roundNoKey(&temp)
			xorBlock(&temp, &temp, x0)
			finalRoundNoKey(x1)
			*x0 = temp
		}
	}
}

func p512r(s *State512, rcs *[15][16]byte, rounds int) {
	x := [4]*Block{(*Block)(s[0:16]), (*Block)(s[16:32]), (*Block)(s[32:48]), (*Block)(s[48:64])}
	for r := 0; r < rounds; r++ {
		o := r % 4
		areion512Round(x[o], x[(o+1)%4], x[(o+2)%4], x[(o+3)%4], &rcs[r])
	}
}

func zeroMain() {
	t2, suffix := formArg(2)
	rng := rand.New(rand.NewPCG(9, 10))
	const n = 1 << 20
	check := func() {
		for _, rounds := range []int{2, 3, 10} {
			var cnt [32]int
			var delta State256
			for i := range delta {
				delta[i] = byte(rng.Uint32()) | 1
			}
			for t := 0; t < n; t++ {
				var a State256
				for i := range a {
					a[i] = byte(rng.Uint32())
				}
				b := a
				for i := range b {
					b[i] ^= delta[i]
				}
				p256r(&a, &roundConstantsP1, rounds)
				p256r(&b, t2, rounds)
				for i := range a {
					if a[i] == b[i] {
						cnt[i]++
					}
				}
			}
			mn, mx := n, 0
			for _, c := range cnt {
				mn, mx = min(mn, c), max(mx, c)
			}
			fmt.Printf("Areion-256 r%d%s: zero count per byte min %d max %d (expected %d)\n", rounds, suffix, mn, mx, n/256)
		}
		for _, rounds := range []int{2, 3, 15} {
			var cnt [64]int
			var delta State512
			for i := range delta {
				delta[i] = byte(rng.Uint32()) | 1
			}
			for t := 0; t < n; t++ {
				var a State512
				for i := range a {
					a[i] = byte(rng.Uint32())
				}
				b := a
				for i := range b {
					b[i] ^= delta[i]
				}
				p512r(&a, &roundConstantsP1, rounds)
				p512r(&b, t2, rounds)
				for i := range a {
					if a[i] == b[i] {
						cnt[i]++
					}
				}
			}
			mn, mx := n, 0
			for _, c := range cnt {
				mn, mx = min(mn, c), max(mx, c)
			}
			fmt.Printf("Areion-512 r%d%s: zero count per byte min %d max %d (expected %d)\n", rounds, suffix, mn, mx, n/256)
		}
	}
	check()
}

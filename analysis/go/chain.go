package main

// The S-box chain of F3 in Areion-512: SR(SB(c)) ^ k_r is followed by
// SB, so every byte of c passes through two S-boxes in series, y = S(x)
// and z = S(y ^ k), with nothing between them but a round-constant byte
// k, while y also feeds F0 of the same word. Elsewhere in Areion a byte
// passes from one S-box to the next through MixColumns or through an XOR
// with another word of the state; a constant does not randomise the value
// in between. The product rule charges an active chain twice the single
// S-box; the exact correlations and probabilities of the chain, at their
// maximum over the constant bytes, are what the weighted bounds
// (weighted.py) charge instead.
//
// Linear: the correlation of a.x ^ b.y ^ g.z, summed over the mask on
// y ^ k (the hull of the chain, Frank Denis, ePrint 2026/1935, section 4.1),
// with a != 0 and g != 0 (both S-boxes active); b is the mask of the F0
// branch on y. Written over y, the Walsh coefficient is the transform at
// b of h(y) = (-1)^(a.S^-1(y) ^ g.S(y ^ k)).
//
// Differential, one table: the number of x with S(x) ^ S(x ^ a) = beta
// and z(x) ^ z(x ^ a) = gamma. Differential, two tables (P1 against P2,
// constants k1 != k2): the same with z(x) = S(S(x) ^ k1) and
// z'(x ^ a) = S(S(x ^ a) ^ k2).

import (
	"encoding/json"
	"math/bits"
	"os"
	"sync"
)

func parity8(v int) int { return bits.OnesCount8(uint8(v)) & 1 }

func fwht(h *[256]int32) {
	for l := 1; l < 256; l <<= 1 {
		for i := 0; i < 256; i += l << 1 {
			for j := i; j < i+l; j++ {
				u, v := h[j], h[j+l]
				h[j], h[j+l] = u+v, u-v
			}
		}
	}
}

// chainLinear returns the largest |W| over k, a != 0, g != 0 and b, and
// the largest over the same with b = 0 (the chain alone, S(S(x) ^ k)).
func chainLinear() (int32, int32) {
	var sgnInv, sgnS [256][256]int32 // [mask][y]
	for m := 0; m < 256; m++ {
		for y := 0; y < 256; y++ {
			sgnInv[m][y] = int32(1 - 2*parity8(m&int(invSbox[y])))
			sgnS[m][y] = int32(1 - 2*parity8(m&int(sbox[y])))
		}
	}
	var mu sync.Mutex
	var best, best0 int32
	var wg sync.WaitGroup
	for k := 0; k < 256; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			var h [256]int32
			var b1, b0 int32
			for a := 1; a < 256; a++ {
				for g := 1; g < 256; g++ {
					for y := 0; y < 256; y++ {
						h[y] = sgnInv[a][y] * sgnS[g][y^k]
					}
					fwht(&h)
					if v := abs32(h[0]); v > b0 {
						b0 = v
					}
					for _, v := range h {
						if v = abs32(v); v > b1 {
							b1 = v
						}
					}
				}
			}
			mu.Lock()
			best, best0 = max(best, b1), max(best0, b0)
			mu.Unlock()
		}(k)
	}
	wg.Wait()
	return best, best0
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

// chainDiff returns the largest joint count over a != 0, beta, gamma: for
// one table (k1 = k2 = k, every k) and for two tables (every k1 != k2).
func chainDiff() (int, int) {
	var mu sync.Mutex
	var one, two int
	var wg sync.WaitGroup
	for k1 := 0; k1 < 256; k1++ {
		wg.Add(1)
		go func(k1 int) {
			defer wg.Done()
			var cnt [1 << 16]uint16
			o, t := 0, 0
			for k2 := 0; k2 < 256; k2++ {
				for a := 1; a < 256; a++ {
					clear(cnt[:])
					for x := 0; x < 256; x++ {
						beta := int(sbox[x] ^ sbox[x^a])
						gamma := int(sbox[sbox[x]^byte(k1)] ^ sbox[sbox[x^a]^byte(k2)])
						cnt[beta<<8|gamma]++
					}
					m := 0
					for _, c := range cnt {
						m = max(m, int(c))
					}
					if k1 == k2 {
						o = max(o, m)
					} else {
						t = max(t, m)
					}
				}
			}
			mu.Lock()
			one, two = max(one, o), max(two, t)
			mu.Unlock()
		}(k1)
	}
	wg.Wait()
	return one, two
}

// sboxMax returns the largest |W| of the S-box over nonzero masks and its
// largest differential count over a nonzero input difference.
func sboxMax() (int32, int) {
	var w int32
	for a := 1; a < 256; a++ {
		var h [256]int32
		for y := 0; y < 256; y++ {
			h[y] = int32(1 - 2*parity8(a&int(invSbox[y])))
		}
		fwht(&h)
		for _, v := range h[1:] {
			w = max(w, abs32(v))
		}
	}
	d := 0
	for a := 1; a < 256; a++ {
		var cnt [256]int
		for x := 0; x < 256; x++ {
			cnt[sbox[x]^sbox[x^a]]++
		}
		for _, c := range cnt {
			d = max(d, c)
		}
	}
	return w, d
}

func chainMain() {
	sw, sd := sboxMax()
	lin, lin0 := chainLinear()
	one, two := chainDiff()
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"sbox_walsh": sw, "sbox_diff": sd,
		"chain_walsh": lin, "chain_walsh_no_branch": lin0,
		"chain_diff_one_table": one, "chain_diff_two_tables": two,
	})
}

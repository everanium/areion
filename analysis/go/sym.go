package main

// Section A: symmetries of the constant-free round. Searches byte
// permutations s of a 16-byte block (column permutation times per-column
// rotation, the permutations that can commute with MixColumns) that
// commute with SubBytes, ShiftRows and MixColumns, then verifies each
// survivor on the full permutations with an all-zero constant table, and
// compares s(RC1_r') with RC2_r for every pair of rounds (r, r').

import (
	"fmt"
	"math/rand/v2"
)

type perm [16]int

func (p perm) apply(b *Block) Block {
	var o Block
	for i := 0; i < 16; i++ {
		o[p[i]] = b[i]
	}
	return o
}

func randBlock(r *rand.Rand) Block {
	var b Block
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func permutations4() [][4]int {
	var out [][4]int
	var rec func(cur []int, used int)
	rec = func(cur []int, used int) {
		if len(cur) == 4 {
			out = append(out, [4]int{cur[0], cur[1], cur[2], cur[3]})
			return
		}
		for i := 0; i < 4; i++ {
			if used>>i&1 == 0 {
				rec(append(cur, i), used|1<<i)
			}
		}
	}
	rec(nil, 0)
	return out
}

func commutes(p perm, f func(*Block), rng *rand.Rand) bool {
	for t := 0; t < 64; t++ {
		x := randBlock(rng)
		a := p.apply(&x)
		f(&a)
		y := x
		f(&y)
		b := p.apply(&y)
		if a != b {
			return false
		}
	}
	return true
}

func symMain() {
	rng := rand.New(rand.NewPCG(7, 11))
	var cands []perm
	for _, cp := range permutations4() {
		for rot := 0; rot < 256; rot++ {
			var p perm
			for c := 0; c < 4; c++ {
				k := rot >> (2 * c) & 3
				for r := 0; r < 4; r++ {
					p[4*c+r] = 4*cp[c] + (r+k)%4
				}
			}
			cands = append(cands, p)
		}
	}
	var group []perm
	for _, p := range cands {
		if commutes(p, subBytes, rng) && commutes(p, shiftRows, rng) && commutes(p, mixColumns, rng) {
			group = append(group, p)
		}
	}
	fmt.Printf("byte permutations tested: %d; commuting with SB, SR, MC: %d\n", len(cands), len(group))

	// Maps that differ from round to round: a byte permutation p before an
	// S-box layer and ShiftRows reappears after them as T(p) = SR o p o SR^-1,
	// and MixColumns needs every map it meets to commute with it. Following
	// the round structure, the map on the F-function input must satisfy
	// T^3(p) = p in Areion-256 (x_A' = SR SB x_A and x_B ^= F(x_A) alternate),
	// and T(p) = p in Areion-512 (the roles of a, b, c, d rotate every round).
	mcOK := map[perm]bool{}
	for _, p := range cands {
		if commutes(p, mixColumns, rng) {
			mcOK[p] = true
		}
	}
	twist := func(p perm) perm {
		var b Block
		for i := range b {
			b[i] = byte(i)
		}
		invShiftRows(&b)
		y := p.apply(&b)
		shiftRows(&y)
		var q perm
		for j := 0; j < 16; j++ {
			q[y[j]] = j
		}
		return q
	}
	n256, n512 := 0, 0
	for p := range mcOK {
		t1 := twist(p)
		t2 := twist(t1)
		if mcOK[t1] && mcOK[t2] && twist(t2) == p {
			n256++
		}
		if t1 == p {
			n512++
		}
	}
	fmt.Printf("per-round maps: candidates commuting with MC %d; consistent with the Areion-256 round (T^3 = id) %d, with the Areion-512 round (T = id) %d\n",
		len(mcOK), n256, n512)
	for _, p := range group {
		fmt.Println("  ", p)
	}

	var zero [15][16]byte
	shift := *p2Table("shift")
	for _, p := range group {
		ok256, ok512 := true, true
		for t := 0; t < 256; t++ {
			var s State256
			for i := range s {
				s[i] = byte(rng.Uint32())
			}
			var ps State256
			for blk := 0; blk < 2; blk++ {
				b := (*Block)(s[16*blk:])
				o := p.apply(b)
				copy(ps[16*blk:], o[:])
			}
			areion256PermuteSoftwareRC(&s, &zero)
			areion256PermuteSoftwareRC(&ps, &zero)
			for blk := 0; blk < 2; blk++ {
				o := p.apply((*Block)(s[16*blk:]))
				if string(o[:]) != string(ps[16*blk:16*blk+16]) {
					ok256 = false
				}
			}
			var s5 State512
			for i := range s5 {
				s5[i] = byte(rng.Uint32())
			}
			var ps5 State512
			for blk := 0; blk < 4; blk++ {
				o := p.apply((*Block)(s5[16*blk:]))
				copy(ps5[16*blk:], o[:])
			}
			areion512PermuteSoftwareRC(&s5, &zero)
			areion512PermuteSoftwareRC(&ps5, &zero)
			for blk := 0; blk < 4; blk++ {
				o := p.apply((*Block)(s5[16*blk:]))
				if string(o[:]) != string(ps5[16*blk:16*blk+16]) {
					ok512 = false
				}
			}
		}
		// best byte agreement between s(RC1_r') and RC2_r over all (r, r')
		best := map[string]int{}
		exact := map[string]int{}
		for name, rc2 := range map[string][15][16]byte{"pi": roundConstantsP2, "shift": shift} {
			for r := 0; r < 15; r++ {
				for r2 := 0; r2 < 15; r2++ {
					img := p.apply(&roundConstantsP1[r2])
					m := 0
					for i := 0; i < 16; i++ {
						if img[i] == rc2[r][i] {
							m++
						}
					}
					if m > best[name] {
						best[name] = m
					}
					if m == 16 {
						exact[name]++
					}
				}
			}
		}
		fmt.Printf("  %v: zero-constant commute 256=%v 512=%v; s(RC1_r') == RC2_r exact pairs pi=%d shift=%d; best byte agreement pi=%d/16 shift=%d/16\n",
			p, ok256, ok512, exact["pi"], exact["shift"], best["pi"], best["shift"])
	}
}

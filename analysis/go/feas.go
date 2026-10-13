package main

// Column-level feasibility of T2 = MC(S) ^ Delta for one AES column:
// pair (s, t) of 4-bit activity masks is feasible iff some S column
// difference with support exactly s yields MC(S) ^ Delta with support
// exactly t. A pair is marked infeasible only after an exhaustive search
// finds nothing: over S for |s| <= 2, over T2 for |t| <= 3, and over S
// for the remaining corner |s| >= 3, |t| = 4, where the search stops at
// the first witness.

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

func mcCol(v [4]byte) [4]byte {
	return [4]byte{
		gfMul2(v[0]) ^ gfMul3(v[1]) ^ v[2] ^ v[3],
		v[0] ^ gfMul2(v[1]) ^ gfMul3(v[2]) ^ v[3],
		v[0] ^ v[1] ^ gfMul2(v[2]) ^ gfMul3(v[3]),
		gfMul3(v[0]) ^ v[1] ^ v[2] ^ gfMul2(v[3]),
	}
}

func invMcCol(v [4]byte) [4]byte {
	return [4]byte{
		gfMul14(v[0]) ^ gfMul11(v[1]) ^ gfMul13(v[2]) ^ gfMul9(v[3]),
		gfMul9(v[0]) ^ gfMul14(v[1]) ^ gfMul11(v[2]) ^ gfMul13(v[3]),
		gfMul13(v[0]) ^ gfMul9(v[1]) ^ gfMul14(v[2]) ^ gfMul11(v[3]),
		gfMul11(v[0]) ^ gfMul13(v[1]) ^ gfMul9(v[2]) ^ gfMul14(v[3]),
	}
}

func sup(v [4]byte) int {
	m := 0
	for i := 0; i < 4; i++ {
		if v[i] != 0 {
			m |= 1 << i
		}
	}
	return m
}

func popc(m int) int { return m&1 + m>>1&1 + m>>2&1 + m>>3&1 }

// forEach calls f for every column with support exactly mask.
func forEach(mask int, f func([4]byte)) {
	var pos []int
	for i := 0; i < 4; i++ {
		if mask>>i&1 == 1 {
			pos = append(pos, i)
		}
	}
	var v [4]byte
	var rec func(k int)
	rec = func(k int) {
		if k == len(pos) {
			f(v)
			return
		}
		for x := 1; x < 256; x++ {
			v[pos[k]] = byte(x)
			rec(k + 1)
		}
		v[pos[k]] = 0
	}
	rec(0)
}

// exists reports whether some column with support exactly mask satisfies
// pred, enumerating them in order and stopping at the first one.
func exists(mask int, pred func([4]byte) bool) bool {
	var pos []int
	for i := 0; i < 4; i++ {
		if mask>>i&1 == 1 {
			pos = append(pos, i)
		}
	}
	var v [4]byte
	var rec func(k int) bool
	rec = func(k int) bool {
		if k == len(pos) {
			return pred(v)
		}
		for x := 1; x < 256; x++ {
			v[pos[k]] = byte(x)
			if rec(k + 1) {
				return true
			}
		}
		v[pos[k]] = 0
		return false
	}
	return rec(0)
}

func colFeasible(delta [4]byte) (feas [16][16]bool) {
	// side 1: S support s with |s| <= 2, exhaustive over S
	for s := 0; s < 16; s++ {
		if popc(s) <= 2 {
			forEach(s, func(v [4]byte) {
				o := mcCol(v)
				for i := 0; i < 4; i++ {
					o[i] ^= delta[i]
				}
				feas[s][sup(o)] = true
			})
		}
	}
	// side 2: T2 support t with |t| <= 3, exhaustive over T2
	for t := 0; t < 16; t++ {
		if popc(t) <= 3 {
			forEach(t, func(v [4]byte) {
				for i := 0; i < 4; i++ {
					v[i] ^= delta[i]
				}
				feas[sup(invMcCol(v))][t] = true
			})
		}
	}
	// corner |s| >= 3, |t| = 4: exhaustive over S, stopping at the first witness
	for s := 0; s < 16; s++ {
		if popc(s) >= 3 {
			feas[s][15] = exists(s, func(v [4]byte) bool {
				o := mcCol(v)
				for i := 0; i < 4; i++ {
					o[i] ^= delta[i]
				}
				return sup(o) == 15
			})
		}
	}
	return
}

// feasTables writes, per RC7 form of P2 and round 0..14, the four column tables
// for Delta_r = RC1_r ^ RC2_r.
func feasTables() {
	out := map[string][][][16][16]bool{}
	for _, variant := range []string{"pi", "shift"} {
		t2 := p2Table(variant)
		rows := make([][][16][16]bool, 15)
		var wg sync.WaitGroup
		for r := 0; r < 15; r++ {
			rows[r] = make([][16][16]bool, 4)
			for c := 0; c < 4; c++ {
				wg.Add(1)
				go func(r, c int) {
					defer wg.Done()
					var d [4]byte
					for i := 0; i < 4; i++ {
						d[i] = roundConstantsP1[r][4*c+i] ^ t2[r][4*c+i]
					}
					rows[r][c] = colFeasible(d)
				}(r, c)
			}
		}
		wg.Wait()
		out[variant] = rows
	}
	json.NewEncoder(os.Stdout).Encode(out)
	for _, v := range []string{"pi", "shift"} {
		inf := 0
		for r := 0; r < 15; r++ {
			for c := 0; c < 4; c++ {
				for s := 0; s < 16; s++ {
					for t := 0; t < 16; t++ {
						if !out[v][r][c][s][t] {
							inf++
						}
					}
				}
			}
		}
		fmt.Fprintf(os.Stderr, "%s: %d infeasible (s,t) pairs over 15 rounds x 4 columns\n", v, inf)
	}
}

package main

// Section B1: every affine subspace U of F_2^8 with dim U >= 2 such that
// S(U) is affine (S = AES S-box), counted per dimension; plus the
// subspaces with S(U) = U (invariant cosets) and the cycle structure of S.

import (
	"fmt"
	"sort"
)

type set256 [4]uint64

func (s *set256) add(x int)     { s[x>>6] |= 1 << (x & 63) }
func (s set256) has(x int) bool { return s[x>>6]>>(x&63)&1 == 1 }

func members(s set256) []int {
	var m []int
	for x := 0; x < 256; x++ {
		if s.has(x) {
			m = append(m, x)
		}
	}
	return m
}

// isAffine reports whether the point set v (size a power of two) is an
// affine subspace: v + v[0] closed under XOR.
func isAffine(v []int) bool {
	var s set256
	for _, x := range v {
		s.add(x ^ v[0])
	}
	for _, a := range v {
		for _, b := range v {
			// (a ^ v0) ^ (b ^ v0) = a ^ b must lie in the linear part
			if !s.has(a ^ b) {
				return false
			}
		}
	}
	return true
}

func sboxSub() {
	// all linear subspaces of F_2^8, by closure from {0}
	seen := map[set256]int{}
	var zero set256
	zero.add(0)
	seen[zero] = 0
	frontier := []set256{zero}
	byDim := map[int][]set256{0: {zero}}
	for d := 1; d <= 7; d++ {
		next := map[set256]bool{}
		for _, s := range frontier {
			m := members(s)
			for v := 1; v < 256; v++ {
				if s.has(v) {
					continue
				}
				var t set256
				for _, x := range m {
					t.add(x)
					t.add(x ^ v)
				}
				next[t] = true
			}
		}
		frontier = frontier[:0]
		for t := range next {
			frontier = append(frontier, t)
		}
		// fixed order, so the printed examples repeat from run to run
		sort.Slice(frontier, func(i, j int) bool {
			for k := 3; k >= 0; k-- {
				if frontier[i][k] != frontier[j][k] {
					return frontier[i][k] < frontier[j][k]
				}
			}
			return false
		})
		byDim[d] = append(byDim[d], frontier...)
		fmt.Printf("dim %d: %d linear subspaces\n", d, len(byDim[d]))
	}
	sb := sbox
	for d := 2; d <= 7; d++ {
		affine, invariant, linearImg := 0, 0, 0
		var examples []string
		for _, lin := range byDim[d] {
			lm := members(lin)
			// coset representatives: smallest element of each coset
			done := set256{}
			for a := 0; a < 256; a++ {
				if done.has(a) {
					continue
				}
				coset := make([]int, len(lm))
				img := make([]int, len(lm))
				for i, x := range lm {
					coset[i] = x ^ a
					done.add(x ^ a)
					img[i] = int(sb[x^a])
				}
				if !isAffine(img) {
					continue
				}
				affine++
				sort.Ints(coset)
				si := append([]int(nil), img...)
				sort.Ints(si)
				same := true
				for i := range si {
					if si[i] != coset[i] {
						same = false
					}
				}
				if same {
					invariant++
				}
				if a == 0 {
					linearImg++
				}
				if len(examples) < 3 && d >= 3 {
					examples = append(examples, fmt.Sprintf("U=%02x.. (offset %02x) -> S(U) affine", lm[1:min(4, len(lm))], a))
				}
			}
		}
		fmt.Printf("dim %d: affine U with S(U) affine: %d (of which U linear: %d); S(U) = U: %d\n", d, affine, linearImg, invariant)
		for _, e := range examples {
			fmt.Println("   ", e)
		}
	}
	// cycle structure of S
	var vis [256]bool
	var cyc []int
	for x := 0; x < 256; x++ {
		if vis[x] {
			continue
		}
		n := 0
		for y := x; !vis[y]; y = int(sb[y]) {
			vis[y] = true
			n++
		}
		cyc = append(cyc, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(cyc)))
	fmt.Println("cycle lengths of S:", cyc)
}

package main

// Section A: control. A table built as s(RC1) does give
// P_fake = s o P1 o s^-1, so a matching table would be detected; and
// no non-identity s fixes every constant of a table (no self-symmetry).

import (
	"fmt"
	"math/rand/v2"
)

func symCtl() {
	rng := rand.New(rand.NewPCG(3, 5))
	s := perm{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3}
	var fake [15][16]byte
	for r := 0; r < 15; r++ {
		fake[r] = s.apply(&roundConstantsP1[r])
	}
	ok := true
	for t := 0; t < 256; t++ {
		var x State512
		for i := range x {
			x[i] = byte(rng.Uint32())
		}
		var sx State512
		for b := 0; b < 4; b++ {
			o := s.apply((*Block)(x[16*b:]))
			copy(sx[16*b:], o[:])
		}
		areion512PermuteSoftwareRC(&x, &roundConstantsP1)
		areion512PermuteSoftwareRC(&sx, &fake)
		for b := 0; b < 4; b++ {
			o := s.apply((*Block)(x[16*b:]))
			if o != *(*Block)(sx[16*b:]) {
				ok = false
			}
		}
	}
	fmt.Println("control: P_fake(s x) == s P1(x) for fake = s(RC1):", ok)
	pi, shift := *p2Table("pi"), *p2Table("shift")
	for _, rot := range []int{1, 2, 3} {
		var p perm
		for i := 0; i < 16; i++ {
			p[i] = (i + 4*rot) % 16
		}
		for _, nt := range []struct {
			name string
			t    [15][16]byte
		}{{"P1", roundConstantsP1}, {"P2 pi", pi}, {"P2 shift", shift}} {
			name, t := nt.name, nt.t
			fixed := 0
			for r := 0; r < 15; r++ {
				if p.apply(&t[r]) == t[r] {
					fixed++
				}
			}
			fmt.Printf("column rotation %d: constants of %s fixed: %d of 15\n", rot, name, fixed)
		}
	}
}

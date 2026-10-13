package main

// Weak-coset engine: cosets (base + span of basis states) of Areion-256 /
// Areion-512 pushed through one round at a time. The affine hull of the
// image is computed from all points when dim <= 16 and from random points
// otherwise, so a full hull is a proof and a smaller one holds with high
// probability. The hull is fed into the next round (a containment trail,
// as used by invariant-subspace distinguishers). coset2.go drives it.

import (
	"fmt"
	"math/bits"
	"math/rand/v2"
	"sort"
)

type vec [8]uint64 // up to 512 bits

func toVec(s []byte) vec {
	var v vec
	for i, b := range s {
		v[i/8] |= uint64(b) << (8 * (i % 8))
	}
	return v
}

func fromVec(v vec, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = byte(v[i/8] >> (8 * (i % 8)))
	}
	return s
}

func (a vec) xor(b vec) vec {
	for i := range a {
		a[i] ^= b[i]
	}
	return a
}

func (a vec) top() int {
	for i := 7; i >= 0; i-- {
		if a[i] != 0 {
			return 64*i + 63 - bits.LeadingZeros64(a[i])
		}
	}
	return -1
}

// basis in echelon form keyed by top bit
type echelon map[int]vec

func (e echelon) add(v vec) bool {
	for {
		t := v.top()
		if t < 0 {
			return false
		}
		b, ok := e[t]
		if !ok {
			e[t] = v
			return true
		}
		v = v.xor(b)
	}
}

type coset struct {
	base  vec
	basis []vec
}

func (c coset) point(sel uint64, rng *rand.Rand) vec {
	p := c.base
	if len(c.basis) <= 16 {
		for i, b := range c.basis {
			if sel>>i&1 == 1 {
				p = p.xor(b)
			}
		}
		return p
	}
	for _, b := range c.basis {
		if rng.Uint32()&1 == 1 {
			p = p.xor(b)
		}
	}
	return p
}

type roundFn func(s []byte, r int)

func mk256(t *[15][16]byte) roundFn {
	return func(s []byte, r int) {
		x0 := (*Block)(s[0:16])
		x1 := (*Block)(s[16:32])
		var temp Block
		if r%2 == 0 {
			temp = *x0
			roundNoKey(&temp)
			xorBlock(&temp, &temp, &t[r])
			roundNoKey(&temp)
			xorBlock(&temp, &temp, x1)
			finalRoundNoKey(x0)
			*x1 = temp
		} else {
			temp = *x1
			roundNoKey(&temp)
			xorBlock(&temp, &temp, &t[r])
			roundNoKey(&temp)
			xorBlock(&temp, &temp, x0)
			finalRoundNoKey(x1)
			*x0 = temp
		}
	}
}

func mk512(t *[15][16]byte) roundFn {
	return func(s []byte, r int) {
		x := [4]*Block{(*Block)(s[0:16]), (*Block)(s[16:32]), (*Block)(s[32:48]), (*Block)(s[48:64])}
		o := r % 4
		areion512Round(x[o], x[(o+1)%4], x[(o+2)%4], x[(o+3)%4], &t[r])
	}
}

// step maps the coset through round r and returns the hull of the image.
func step(c coset, f roundFn, r, nbytes int, rng *rand.Rand) (coset, bool) {
	d := len(c.basis)
	img := func(p vec) vec {
		s := fromVec(p, nbytes)
		f(s, r)
		return toVec(s)
	}
	b0 := img(c.base)
	e := echelon{}
	if d <= 16 {
		for sel := uint64(1); sel < 1<<d; sel++ {
			e.add(img(c.point(sel, rng)).xor(b0))
		}
	} else {
		idle := 0
		for idle < 96 && len(e) < 8*nbytes {
			if e.add(img(c.point(0, rng)).xor(b0)) {
				idle = 0
			} else {
				idle++
			}
		}
	}
	out := coset{base: b0}
	tops := make([]int, 0, len(e))
	for t := range e {
		tops = append(tops, t)
	}
	sort.Ints(tops) // fixed basis order, so later sampling does not depend on map iteration
	for _, t := range tops {
		out.basis = append(out.basis, e[t])
	}
	return out, len(e) == d
}

type seed struct {
	name string
	c    coset
	r0   int
}

func unitByte(pos int, v byte) vec {
	var u vec
	u[pos/8] |= uint64(v) << (8 * (pos % 8))
	return u
}

// seeds: (a) one full byte, (b) one byte over an F_4- or F_16-line,
// (c) 2..4 bytes of one column each over a 2-point set {p, p ^ alpha},
// at every block and every start round; base states given by baseFn.
func seeds(nbytes, rounds int, baseFn func(*rand.Rand) vec, rng *rand.Rand, lines [][]byte) []seed {
	var out []seed
	for r0 := 0; r0 < rounds; r0++ {
		for pos := 0; pos < nbytes; pos++ {
			base := baseFn(rng)
			var c coset
			c.base = base
			c.base[pos/8] &^= 0xff << (8 * (pos % 8))
			for k := 0; k < 8; k++ {
				c.basis = append(c.basis, unitByte(pos, 1<<k))
			}
			out = append(out, seed{fmt.Sprintf("full byte %d", pos), c, r0})
			for li, L := range lines {
				var cl coset
				cl.base = c.base // byte pos = 0, so the coset is the line itself
				for _, v := range L {
					cl.basis = append(cl.basis, unitByte(pos, v))
				}
				out = append(out, seed{fmt.Sprintf("line %d byte %d", li, pos), cl, r0})
			}
		}
		for blk := 0; blk < nbytes/16; blk++ {
			for col := 0; col < 4; col++ {
				for mask := 3; mask < 16; mask++ {
					if bits.OnesCount(uint(mask)) < 2 {
						continue
					}
					// kind 0: bytes of one column; kind 1: bytes of one
					// diagonal, which ShiftRows gathers into one column
					for kind, label := range []string{"col", "diag"} {
						var c coset
						c.base = baseFn(rng)
						for k := 0; k < 4; k++ {
							if mask>>k&1 == 1 {
								pos := 16*blk + 4*col + k
								if kind == 1 {
									pos = 16*blk + (4*col+5*k)%16
								}
								c.basis = append(c.basis, unitByte(pos, byte(rng.Uint32()|1)))
							}
						}
						out = append(out, seed{fmt.Sprintf("1-dim bytes mask %x blk %d %s %d", mask, blk, label, col), c, r0})
					}
				}
			}
		}
	}
	return out
}

func lineBases() [][]byte {
	// basis of each F_4- and F_16-line (B1): lambda * F
	gm := func(a, b byte) byte {
		var r byte
		for b != 0 {
			if b&1 == 1 {
				r ^= a
			}
			if a&0x80 != 0 {
				a = a<<1 ^ 0x1b
			} else {
				a <<= 1
			}
			b >>= 1
		}
		return r
	}
	pw := func(a byte, e int) byte {
		r := byte(1)
		for i := 0; i < e; i++ {
			r = gm(r, a)
		}
		return r
	}
	var out [][]byte
	for _, d := range []int{2, 4} {
		var F []byte
		for x := 0; x < 256; x++ {
			if pw(byte(x), 1<<d) == byte(x) {
				F = append(F, byte(x))
			}
		}
		seen := map[string]bool{}
		for l := 1; l < 256; l++ {
			var set []int
			for _, f := range F {
				set = append(set, int(gm(byte(l), f)))
			}
			sort.Ints(set)
			key := fmt.Sprint(set)
			if seen[key] {
				continue
			}
			seen[key] = true
			// echelon basis of the line
			var basis []byte
			var piv [8]byte
			for _, v := range set {
				x := byte(v)
				for b := 7; b >= 0 && x != 0; b-- {
					if x>>b&1 == 1 {
						if piv[b] == 0 {
							piv[b] = x
							basis = append(basis, x)
							x = 0
						} else {
							x ^= piv[b]
						}
					}
				}
			}
			out = append(out, basis)
		}
	}
	return out
}

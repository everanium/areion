package main

// Oracle for the related-constant byte-activity model: the reference
// rounds instrumented to record the activity pattern of every
// intermediate word of P1(u) versus P2(u ^ delta). check compares the
// instrumented permutations with the library; trace writes JSON lines
// that py/model.py --check requires to be satisfiable.

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"

	"github.com/everanium/areion"
)

func act(a, b *Block) uint16 {
	var m uint16
	for i := 0; i < 16; i++ {
		if a[i] != b[i] {
			m |= 1 << i
		}
	}
	return m
}

// --- instrumented Areion-256 (rounds as in areion256PermuteSoftwareRC) ---

type pair256 struct{ x, y [2]Block } // branch P1, branch P2

func r256(p *pair256, r int, rc1, rc2 *Block, rec map[string]uint16) {
	ai, bi := 0, 1
	if r%2 == 1 {
		ai, bi = 1, 0
	}
	rec["A"] = act(&p.x[ai], &p.y[ai])
	rec["B"] = act(&p.x[bi], &p.y[bi])
	step := func(s *[2]Block, rc *Block) (t1, t2, w Block) {
		t := s[ai]
		roundNoKey(&t)
		t1 = t
		xorBlock(&t, &t, rc)
		t2 = t
		roundNoKey(&t)
		w = t
		xorBlock(&t, &t, &s[bi])
		finalRoundNoKey(&s[ai])
		s[bi] = t
		return
	}
	xt1, xt2, xw := step(&p.x, rc1)
	yt1, yt2, yw := step(&p.y, rc2)
	rec["T1"] = act(&xt1, &yt1)
	rec["T2"] = act(&xt2, &yt2)
	rec["W"] = act(&xw, &yw)
}

func perm256Instr(st *State256, rcs *[15][16]byte) {
	var p pair256
	copy(p.x[0][:], st[0:16])
	copy(p.x[1][:], st[16:32])
	p.y = p.x
	rec := map[string]uint16{}
	for r := 0; r < 10; r++ {
		r256(&p, r, &rcs[r], &rcs[r], rec)
	}
	copy(st[0:16], p.x[0][:])
	copy(st[16:32], p.x[1][:])
}

// --- instrumented Areion-512 (rounds as in areion512PermuteSoftwareRC) ---

type pair512 struct{ x, y [4]Block }

func r512(p *pair512, r int, rc1, rc2 *Block, rec map[string]uint16) {
	o := r % 4 // role rotation: a=x[o], b=x[o+1], c=x[o+2], d=x[o+3]
	ia, ib, ic, id := o, (o+1)%4, (o+2)%4, (o+3)%4
	rec["a"] = act(&p.x[ia], &p.y[ia])
	rec["b"] = act(&p.x[ib], &p.y[ib])
	rec["c"] = act(&p.x[ic], &p.y[ic])
	rec["d"] = act(&p.x[id], &p.y[id])
	step := func(s *[4]Block, rc *Block) (t1, t2, c1, c2, cf Block) {
		a, b, c, d := &s[ia], &s[ib], &s[ic], &s[id]
		t1 = *a
		roundNoKey(&t1)
		xorBlock(b, b, &t1)
		t2 = *c
		roundNoKey(&t2)
		xorBlock(d, d, &t2)
		finalRoundNoKey(a)
		finalRoundNoKey(c)
		c1 = *c
		xorBlock(c, c, rc)
		c2 = *c
		roundNoKey(c)
		cf = *c
		return
	}
	xt1, xt2, xc1, xc2, xcf := step(&p.x, rc1)
	yt1, yt2, yc1, yc2, ycf := step(&p.y, rc2)
	rec["t1"] = act(&xt1, &yt1)
	rec["t2"] = act(&xt2, &yt2)
	rec["c1"] = act(&xc1, &yc1)
	rec["c2"] = act(&xc2, &yc2)
	rec["cf"] = act(&xcf, &ycf)
}

func perm512Instr(st *State512, rcs *[15][16]byte) {
	var p pair512
	for i := 0; i < 4; i++ {
		copy(p.x[i][:], st[16*i:16*i+16])
	}
	p.y = p.x
	rec := map[string]uint16{}
	for r := 0; r < 15; r++ {
		r512(&p, r, &rcs[r], &rcs[r], rec)
	}
	// final cyclic rotation: x0=x3, x1=x0, x2=x1, x3=x2
	x := p.x
	p.x = [4]Block{x[3], x[0], x[1], x[2]}
	for i := 0; i < 4; i++ {
		copy(st[16*i:16*i+16], p.x[i][:])
	}
}

// orng drives check and trace; trace reseeds it per width and RC7 form,
// so a failing trace can be reproduced.
var orng = rand.New(rand.NewPCG(1, 1))

func fill(b []byte) {
	for i := range b {
		b[i] = byte(orng.Uint32())
	}
}

func check() {
	bad := 0
	for n := 0; n < 2000; n++ {
		var s, a, b State256
		fill(s[:])
		a, b = s, s
		areion.Permute256(&a)
		perm256Instr(&b, &roundConstantsP1)
		if a != b {
			bad++
		}
		a, b = s, s
		areion.Permute256P2(&a)
		perm256Instr(&b, &roundConstantsP2)
		if a != b {
			bad++
		}
		var t, c, d State512
		fill(t[:])
		c, d = t, t
		areion.Permute512(&c)
		perm512Instr(&d, &roundConstantsP1)
		if c != d {
			bad++
		}
		c, d = t, t
		areion.Permute512P2(&c)
		perm512Instr(&d, &roundConstantsP2)
		if c != d {
			bad++
		}
	}
	fmt.Printf("instrumented vs library (2000 x {256 P1, 256 P2, 512 P1, 512 P2}): %d mismatches\n", bad)
	if bad != 0 {
		os.Exit(1)
	}
}

// randDelta returns a difference with nbytes nonzero bytes at random
// positions among the first width/8 bytes (positions may repeat).
func randDelta(nbytes, width int) (d [64]byte) {
	if nbytes == 0 {
		return
	}
	var idx [64]byte
	fill(idx[:])
	for i := 0; i < nbytes; i++ {
		var v [1]byte
		for v[0] == 0 {
			fill(v[:])
		}
		d[int(idx[i])%(width/8)] = v[0]
	}
	return
}

func trace(width int, variant string, rounds, n int) {
	seed := uint64(1)
	if variant == "shift" {
		seed = 2
	}
	orng = rand.New(rand.NewPCG(uint64(width), seed))
	t2 := p2Table(variant)
	enc := json.NewEncoder(os.Stdout)
	for k := 0; k < n; k++ {
		var nb [1]byte
		fill(nb[:])
		dbytes := []int{0, 1, 2, 4, 64}[int(nb[0])%5]
		delta := randDelta(dbytes, width)
		if dbytes == 64 {
			fill(delta[:])
		}
		var rounds_ []map[string]uint16
		if width == 256 {
			var p pair256
			var u [32]byte
			fill(u[:])
			copy(p.x[0][:], u[0:16])
			copy(p.x[1][:], u[16:32])
			p.y = p.x
			for i := 0; i < 32; i++ {
				p.y[i/16][i%16] ^= delta[i]
			}
			for r := 0; r < rounds; r++ {
				rec := map[string]uint16{}
				r256(&p, r, &roundConstantsP1[r], &t2[r], rec)
				rounds_ = append(rounds_, rec)
			}
			fin := map[string]uint16{"x0": act(&p.x[0], &p.y[0]), "x1": act(&p.x[1], &p.y[1])}
			rounds_ = append(rounds_, fin)
		} else {
			var p pair512
			var u [64]byte
			fill(u[:])
			for i := 0; i < 4; i++ {
				copy(p.x[i][:], u[16*i:16*i+16])
			}
			p.y = p.x
			for i := 0; i < 64; i++ {
				p.y[i/16][i%16] ^= delta[i]
			}
			for r := 0; r < rounds; r++ {
				rec := map[string]uint16{}
				r512(&p, r, &roundConstantsP1[r], &t2[r], rec)
				rounds_ = append(rounds_, rec)
			}
			fin := map[string]uint16{}
			for i := 0; i < 4; i++ {
				fin["x"+strconv.Itoa(i)] = act(&p.x[i], &p.y[i])
			}
			rounds_ = append(rounds_, fin)
		}
		enc.Encode(rounds_)
	}
}

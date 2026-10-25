package main

// Track 2: InversePermute (P1^-1, P2^-1) backward analysis and
// forward-backward cross-composition C_r(x) = P2_r^-1(P1_r(x))
// intermediate-state delta trajectory.

import (
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"math/rand/v2"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/everanium/areion"
)

// invP256r runs `rounds` inverse rounds of Areion-256 (from r = rounds-1 down to 0),
// the exact inverse of p256r(s, rcs, rounds).
func invP256r(s *State256, rcs *[15][16]byte, rounds int) {
	x := [2]*Block{(*Block)(s[0:16]), (*Block)(s[16:32])}
	for r := rounds - 1; r >= 0; r-- {
		ai, bi := 0, 1
		if r%2 == 1 {
			ai, bi = 1, 0
		}
		invFinalRoundNoKey(x[ai])
		temp := *x[ai]
		roundNoKey(&temp)
		xorBlock(&temp, &temp, &rcs[r])
		roundNoKey(&temp)
		xorBlock(x[bi], x[bi], &temp)
	}
}

// invRound512 applies one inverse round of Areion-512 on (a, b, c, d) with constant rc.
func invRound512(a, b, c, d *Block, rc *Block) {
	invFinalRoundNoKey(a)
	invMixColumns(c)
	invFinalRoundNoKey(c)
	xorBlock(c, c, rc)
	invFinalRoundNoKey(c)

	var temp1, temp2 Block
	temp1 = *a
	roundNoKey(&temp1)
	xorBlock(b, b, &temp1)

	temp2 = *c
	roundNoKey(&temp2)
	xorBlock(d, d, &temp2)
}

// invP512r runs `rounds` inverse rounds of Areion-512 (from r = rounds-1 down to 0),
// the exact inverse of p512r(s, rcs, rounds).
func invP512r(s *State512, rcs *[15][16]byte, rounds int) {
	x := [4]*Block{(*Block)(s[0:16]), (*Block)(s[16:32]), (*Block)(s[32:48]), (*Block)(s[48:64])}
	for r := rounds - 1; r >= 0; r-- {
		o := r % 4
		invRound512(x[o], x[(o+1)%4], x[(o+2)%4], x[(o+3)%4], &rcs[r])
	}
}

// --- Instrumented backward rounds for oracle trace verification ---

func invR256(p *pair256, r int, rc1, rc2 *Block, rec map[string]uint16) {
	ai, bi := 0, 1
	if r%2 == 1 {
		ai, bi = 1, 0
	}
	rec["S"] = act(&p.x[ai], &p.y[ai]) // S = A' (input to inverse round, equals SR(SB(A)))
	rec["Bp"] = act(&p.x[bi], &p.y[bi])
	step := func(s *[2]Block, rc *Block) (t1, t2, w Block) {
		invFinalRoundNoKey(&s[ai])
		t := s[ai]
		roundNoKey(&t)
		t1 = t
		xorBlock(&t, &t, rc)
		t2 = t
		roundNoKey(&t)
		w = t
		xorBlock(&s[bi], &s[bi], &t)
		return
	}
	xt1, xt2, xw := step(&p.x, rc1)
	yt1, yt2, yw := step(&p.y, rc2)
	rec["A"] = act(&p.x[ai], &p.y[ai])
	rec["B"] = act(&p.x[bi], &p.y[bi])
	rec["T1"] = act(&xt1, &yt1)
	rec["T2"] = act(&xt2, &yt2)
	rec["W"] = act(&xw, &yw)
}

func invR512(p *pair512, r int, rc1, rc2 *Block, rec map[string]uint16) {
	o := r % 4
	ia, ib, ic, id := o, (o+1)%4, (o+2)%4, (o+3)%4
	rec["ap"] = act(&p.x[ia], &p.y[ia])
	rec["bp"] = act(&p.x[ib], &p.y[ib])
	rec["cf"] = act(&p.x[ic], &p.y[ic])
	rec["dp"] = act(&p.x[id], &p.y[id])
	step := func(s *[4]Block, rc *Block) (t1, t2, cm, c2, c1 Block) {
		a, b, c, d := &s[ia], &s[ib], &s[ic], &s[id]
		invFinalRoundNoKey(a)
		invMixColumns(c)
		cm = *c
		invFinalRoundNoKey(c)
		c2 = *c
		xorBlock(c, c, rc)
		c1 = *c
		invFinalRoundNoKey(c)
		t1 = *a
		roundNoKey(&t1)
		xorBlock(b, b, &t1)
		t2 = *c
		roundNoKey(&t2)
		xorBlock(d, d, &t2)
		return
	}
	xt1, xt2, xcm, xc2, xc1 := step(&p.x, rc1)
	yt1, yt2, ycm, yc2, yc1 := step(&p.y, rc2)
	rec["a"] = act(&p.x[ia], &p.y[ia])
	rec["b"] = act(&p.x[ib], &p.y[ib])
	rec["c"] = act(&p.x[ic], &p.y[ic])
	rec["d"] = act(&p.x[id], &p.y[id])
	rec["t1"] = act(&xt1, &yt1)
	rec["t2"] = act(&xt2, &yt2)
	rec["cm"] = act(&xcm, &ycm)
	rec["c2"] = act(&xc2, &yc2)
	rec["c1"] = act(&xc1, &yc1)
}

func invPerm256Instr(st *State256, rcs *[15][16]byte) {
	var p pair256
	copy(p.x[0][:], st[0:16])
	copy(p.x[1][:], st[16:32])
	p.y = p.x
	rec := map[string]uint16{}
	for r := 9; r >= 0; r-- {
		invR256(&p, r, &rcs[r], &rcs[r], rec)
	}
	copy(st[0:16], p.x[0][:])
	copy(st[16:32], p.x[1][:])
}

func invPerm512Instr(st *State512, rcs *[15][16]byte) {
	var p pair512
	for i := 0; i < 4; i++ {
		copy(p.x[i][:], st[16*i:16*i+16])
	}
	// Reverse final rotation: x0=x1, x1=x2, x2=x3, x3=x0
	x := p.x
	p.x = [4]Block{x[1], x[2], x[3], x[0]}
	p.y = p.x
	rec := map[string]uint16{}
	for r := 14; r >= 0; r-- {
		invR512(&p, r, &rcs[r], &rcs[r], rec)
	}
	for i := 0; i < 4; i++ {
		copy(st[16*i:16*i+16], p.x[i][:])
	}
}

func checkInv() {
	rng := rand.New(rand.NewPCG(31, 32))
	badLib := 0
	badRoundTrip := 0
	for n := 0; n < 2000; n++ {
		var s, a, b State256
		for i := range s {
			s[i] = byte(rng.Uint32())
		}
		a, b = s, s
		areion.InversePermute256(&a)
		invPerm256Instr(&b, &roundConstantsP1)
		if a != b {
			badLib++
		}
		a, b = s, s
		areion.InversePermute256P2(&a)
		invPerm256Instr(&b, &roundConstantsP2)
		if a != b {
			badLib++
		}

		var t, c, d State512
		for i := range t {
			t[i] = byte(rng.Uint32())
		}
		c, d = t, t
		areion.InversePermute512(&c)
		invPerm512Instr(&d, &roundConstantsP1)
		if c != d {
			badLib++
		}
		c, d = t, t
		areion.InversePermute512P2(&c)
		invPerm512Instr(&d, &roundConstantsP2)
		if c != d {
			badLib++
		}
	}
	// Check reduced-round round-trip invP(p(x, r), r) == x for all r = 1..R
	for r := 1; r <= 10; r++ {
		for t := 0; t < 100; t++ {
			var s State256
			for i := range s {
				s[i] = byte(rng.Uint32())
			}
			orig := s
			p256r(&s, &roundConstantsP1, r)
			invP256r(&s, &roundConstantsP1, r)
			if s != orig {
				badRoundTrip++
			}
		}
	}
	for r := 1; r <= 15; r++ {
		for t := 0; t < 100; t++ {
			var s State512
			for i := range s {
				s[i] = byte(rng.Uint32())
			}
			orig := s
			p512r(&s, &roundConstantsP1, r)
			invP512r(&s, &roundConstantsP1, r)
			if s != orig {
				badRoundTrip++
			}
		}
	}
	fmt.Printf("instrumented InversePermute vs library (2000 x {256 P1, 256 P2, 512 P1, 512 P2}): %d mismatches\n", badLib)
	fmt.Printf("reduced-round P_r^-1(P_r(x)) == x (r=1..10 for 256, r=1..15 for 512): %d mismatches\n", badRoundTrip)
	if badLib != 0 || badRoundTrip != 0 {
		os.Exit(1)
	}
}

func traceInv(width int, variant string, rounds, n int) {
	seed := uint64(11)
	if variant == "shift" {
		seed = 12
	}
	rng := rand.New(rand.NewPCG(uint64(width), seed))
	rf := func(b []byte) {
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
	}
	t2 := p2Table(variant)
	enc := json.NewEncoder(os.Stdout)
	for k := 0; k < n; k++ {
		var nb [1]byte
		rf(nb[:])
		dbytes := []int{0, 1, 2, 4, 64}[int(nb[0])%5]
		if k < n/5 {
			dbytes = 0
		}
		var delta [64]byte
		if dbytes == 64 {
			rf(delta[:])
		} else if dbytes > 0 {
			var idx [64]byte
			rf(idx[:])
			for i := 0; i < dbytes; i++ {
				var v [1]byte
				for v[0] == 0 {
					rf(v[:])
				}
				delta[int(idx[i])%(width/8)] = v[0]
			}
		}
		var rounds_ []map[string]uint16
		if width == 256 {
			var p pair256
			var u [32]byte
			rf(u[:])
			copy(p.x[0][:], u[0:16])
			copy(p.x[1][:], u[16:32])
			p.y = p.x
			for i := 0; i < 32; i++ {
				p.y[i/16][i%16] ^= delta[i]
			}
			for r := rounds - 1; r >= 0; r-- {
				rec := map[string]uint16{}
				invR256(&p, r, &roundConstantsP1[r], &t2[r], rec)
				rounds_ = append(rounds_, rec)
			}
			fin := map[string]uint16{"x0": act(&p.x[0], &p.y[0]), "x1": act(&p.x[1], &p.y[1])}
			rounds_ = append(rounds_, fin)
		} else {
			var p pair512
			var u [64]byte
			rf(u[:])
			for i := 0; i < 4; i++ {
				copy(p.x[i][:], u[16*i:16*i+16])
			}
			p.y = p.x
			for i := 0; i < 64; i++ {
				p.y[i/16][i%16] ^= delta[i]
			}
			for r := rounds - 1; r >= 0; r-- {
				rec := map[string]uint16{}
				invR512(&p, r, &roundConstantsP1[r], &t2[r], rec)
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

// traceCross emits coupled 2r-round differential activity traces (JSON lines)
// for C_r(x) = P2_r^-1(P1_r(x)) on pairs (x, y) with x != y, mixing 1-byte
// input differences, multi-byte input differences, and turnaround-targeted
// pairs constructed at round boundaries r-1 and r-2.
func traceCross(width int, variant string, rounds, n int) {
	seed := uint64(21)
	if variant == "shift" {
		seed = 22
	}
	rng := rand.New(rand.NewPCG(uint64(width*100+rounds), seed))
	rf := func(b []byte) {
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
	}
	nzByte := func() byte {
		var v [1]byte
		for v[0] == 0 {
			rf(v[:])
		}
		return v[0]
	}
	t2 := p2Table(variant)
	enc := json.NewEncoder(os.Stdout)
	for k := 0; k < n; k++ {
		mode := k % 5
		var rounds_ []map[string]uint16
		if width == 256 {
			var sx, sy State256
			rf(sx[:])
			sy = sx
			switch mode {
			case 0: // 1-byte input difference
				pos := int(rng.Uint32()) % 32
				sy[pos] ^= nzByte()
			case 1: // 2-byte, 4-byte, or 32-byte input difference
				cnt := []int{2, 4, 32}[(k/5)%3]
				if cnt == 32 {
					for sy == sx {
						rf(sy[:])
					}
				} else {
					for i := 0; i < cnt; i++ {
						sy[(int(rng.Uint32())+i)%32] ^= nzByte()
					}
				}
			case 2, 3: // 1-byte difference at turnaround round r-1 (d=1) or r-2 (d=2)
				rTurn := rounds - 1
				if mode == 3 && rounds >= 2 {
					rTurn = rounds - 2
				}
				pos := int(rng.Uint32()) % 32
				sy[pos] ^= nzByte()
				invP256r(&sx, &roundConstantsP1, rTurn)
				invP256r(&sy, &roundConstantsP1, rTurn)
			case 4: // 1-byte T1 difference at turnaround round r-1 (wt(A)=4, wt(T1)=1)
				rTurn := rounds - 1
				ai := 0
				if rTurn%2 == 1 {
					ai = 1
				}
				var aBlk, sBlk, sBlkY Block
				copy(aBlk[:], sx[16*ai:16*ai+16])
				sBlk = aBlk
				finalRoundNoKey(&sBlk)
				sBlkY = sBlk
				var dT1 Block
				dT1[int(rng.Uint32())%16] = nzByte()
				invMixColumns(&dT1)
				xorBlock(&sBlkY, &sBlkY, &dT1)
				invFinalRoundNoKey(&sBlkY)
				copy(sy[16*ai:16*ai+16], sBlkY[:])
				invP256r(&sx, &roundConstantsP1, rTurn)
				invP256r(&sy, &roundConstantsP1, rTurn)
			}
			var p pair256
			copy(p.x[0][:], sx[0:16])
			copy(p.x[1][:], sx[16:32])
			copy(p.y[0][:], sy[0:16])
			copy(p.y[1][:], sy[16:32])
			for r := 0; r < rounds; r++ {
				rec := map[string]uint16{}
				r256(&p, r, &roundConstantsP1[r], &roundConstantsP1[r], rec)
				ai, bi := 0, 1
				if r%2 == 1 {
					ai, bi = 1, 0
				}
				rec["S"] = act(&p.x[ai], &p.y[ai])
				rec["nb"] = act(&p.x[bi], &p.y[bi])
				rounds_ = append(rounds_, rec)
			}
			for r := rounds - 1; r >= 0; r-- {
				rec := map[string]uint16{}
				invR256(&p, r, &t2[r], &t2[r], rec)
				rounds_ = append(rounds_, rec)
			}
			fin := map[string]uint16{"x0": act(&p.x[0], &p.y[0]), "x1": act(&p.x[1], &p.y[1])}
			rounds_ = append(rounds_, fin)
		} else {
			var sx, sy State512
			rf(sx[:])
			sy = sx
			switch mode {
			case 0: // 1-byte input difference
				pos := int(rng.Uint32()) % 64
				sy[pos] ^= nzByte()
			case 1: // 2-byte, 4-byte, or 64-byte input difference
				cnt := []int{2, 4, 64}[(k/5)%3]
				if cnt == 64 {
					for sy == sx {
						rf(sy[:])
					}
				} else {
					for i := 0; i < cnt; i++ {
						sy[(int(rng.Uint32())+i)%64] ^= nzByte()
					}
				}
			case 2, 3, 4: // 1-byte difference at turnaround round r-1, r-2, or r-3
				rTurn := rounds - 1
				if mode == 3 && rounds >= 2 {
					rTurn = rounds - 2
				} else if mode == 4 && rounds >= 3 {
					rTurn = rounds - 3
				}
				// Cycle across all 4 words a, b, c, d at rTurn
				word := (k / 5) % 4
				pos := 16*word + int(rng.Uint32())%16
				sy[pos] ^= nzByte()
				invP512r(&sx, &roundConstantsP1, rTurn)
				invP512r(&sy, &roundConstantsP1, rTurn)
			}
			var p pair512
			for i := 0; i < 4; i++ {
				copy(p.x[i][:], sx[16*i:16*i+16])
				copy(p.y[i][:], sy[16*i:16*i+16])
			}
			for r := 0; r < rounds; r++ {
				rec := map[string]uint16{}
				r512(&p, r, &roundConstantsP1[r], &roundConstantsP1[r], rec)
				o := r % 4
				ia, ib, id := o, (o+1)%4, (o+3)%4
				rec["na"] = act(&p.x[ia], &p.y[ia])
				rec["nb"] = act(&p.x[ib], &p.y[ib])
				rec["nd"] = act(&p.x[id], &p.y[id])
				rounds_ = append(rounds_, rec)
			}
			for r := rounds - 1; r >= 0; r-- {
				rec := map[string]uint16{}
				invR512(&p, r, &t2[r], &t2[r], rec)
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

// --- Cross-Composition Trajectory C_r(x) = P2_r^-1(P1_r(x)) ---

type crossStepStat struct {
	width        int
	totalRounds  int
	boundaryK    int // internal round boundary k in 0..r-1
	depthD       int // backward depth d = r - k in 1..r
	zeroBytes    int // bytes identically 0
	constNZBytes int // bytes constant != 0 independent of x
	halfBytes    int // bytes taking 2..128 distinct values out of 256
	fullBytes    int // bytes taking all 256 values
	missingVals  int // total (byte, value) pairs never seen
	maxChiAll    float64
	maxChiNonC   float64 // max chi-square over non-constant bytes
}

// runCrossTrajectory analyzes delta_{r,k}(x) = s_k^(1)(x) ^ s_k^(2)(x) for a given width,
// total round count r, and P2 table rc2 over nSamples random inputs x.
func runCrossTrajectory(width, totalR int, rc2 *[15][16]byte, nSamples int) (steps []crossStepStat, involFrac float64) {
	nb := width / 8
	// hists[k][byteIdx][val] for k = 0 .. totalR-1
	hists := make([][][256]int, totalR)
	for k := 0; k < totalR; k++ {
		hists[k] = make([][256]int, nb)
	}
	rng := rand.New(rand.NewPCG(uint64(width*1000+totalR), 99))
	involMatches := 0
	involTrials := min(nSamples, 4096)

	if width == 256 {
		fwdStates := make([]State256, totalR+1)
		for s := 0; s < nSamples; s++ {
			var x State256
			for i := 0; i < 32; i += 8 {
				v := rng.Uint64()
				for b := 0; b < 8; b++ {
					x[i+b] = byte(v >> (8 * b))
				}
			}
			fwdStates[0] = x
			cur := x
			for r := 0; r < totalR; r++ {
				x0 := (*Block)(cur[0:16])
				x1 := (*Block)(cur[16:32])
				var temp Block
				if r%2 == 0 {
					temp = *x0
					roundNoKey(&temp)
					xorBlock(&temp, &temp, &roundConstantsP1[r])
					roundNoKey(&temp)
					xorBlock(&temp, &temp, x1)
					finalRoundNoKey(x0)
					*x1 = temp
				} else {
					temp = *x1
					roundNoKey(&temp)
					xorBlock(&temp, &temp, &roundConstantsP1[r])
					roundNoKey(&temp)
					xorBlock(&temp, &temp, x0)
					finalRoundNoKey(x1)
					*x0 = temp
				}
				fwdStates[r+1] = cur
			}
			// Backward unroll under P2^-1 from k = totalR-1 down to 0
			bwd := fwdStates[totalR]
			for k := totalR - 1; k >= 0; k-- {
				x := [2]*Block{(*Block)(bwd[0:16]), (*Block)(bwd[16:32])}
				ai, bi := 0, 1
				if k%2 == 1 {
					ai, bi = 1, 0
				}
				invFinalRoundNoKey(x[ai])
				temp := *x[ai]
				roundNoKey(&temp)
				xorBlock(&temp, &temp, &rc2[k])
				roundNoKey(&temp)
				xorBlock(x[bi], x[bi], &temp)
				hk := hists[k]
				fk := &fwdStates[k]
				for i := 0; i < 32; i++ {
					hk[i][fk[i]^bwd[i]]++
				}
			}
			if s < involTrials {
				// Check whether C_r(C_r(x)) == x
				cx := bwd
				p256r(&cx, &roundConstantsP1, totalR)
				invP256r(&cx, rc2, totalR)
				if cx == x {
					involMatches++
				}
			}
		}
	} else {
		fwdStates := make([]State512, totalR+1)
		for s := 0; s < nSamples; s++ {
			var x State512
			for i := 0; i < 64; i += 8 {
				v := rng.Uint64()
				for b := 0; b < 8; b++ {
					x[i+b] = byte(v >> (8 * b))
				}
			}
			fwdStates[0] = x
			cur := x
			for r := 0; r < totalR; r++ {
				xb := [4]*Block{(*Block)(cur[0:16]), (*Block)(cur[16:32]), (*Block)(cur[32:48]), (*Block)(cur[48:64])}
				o := r % 4
				areion512Round(xb[o], xb[(o+1)%4], xb[(o+2)%4], xb[(o+3)%4], &roundConstantsP1[r])
				fwdStates[r+1] = cur
			}
			bwd := fwdStates[totalR]
			for k := totalR - 1; k >= 0; k-- {
				xb := [4]*Block{(*Block)(bwd[0:16]), (*Block)(bwd[16:32]), (*Block)(bwd[32:48]), (*Block)(bwd[48:64])}
				o := k % 4
				invRound512(xb[o], xb[(o+1)%4], xb[(o+2)%4], xb[(o+3)%4], &rc2[k])
				hk := hists[k]
				fk := &fwdStates[k]
				for i := 0; i < 64; i++ {
					hk[i][fk[i]^bwd[i]]++
				}
			}
			if s < involTrials {
				cx := bwd
				p512r(&cx, &roundConstantsP1, totalR)
				invP512r(&cx, rc2, totalR)
				if cx == x {
					involMatches++
				}
			}
		}
	}

	involFrac = float64(involMatches) / float64(involTrials)
	exp := float64(nSamples) / 256.0
	for k := totalR - 1; k >= 0; k-- {
		st := crossStepStat{
			width:       width,
			totalRounds: totalR,
			boundaryK:   k,
			depthD:      totalR - k,
		}
		hk := hists[k]
		for i := 0; i < nb; i++ {
			seen := 0
			chi := 0.0
			for v := 0; v < 256; v++ {
				c := hk[i][v]
				if c == 0 {
					st.missingVals++
				} else {
					seen++
				}
				d := float64(c) - exp
				chi += d * d / exp
			}
			st.maxChiAll = max(st.maxChiAll, chi)
			if seen == 1 {
				if hk[i][0] == nSamples {
					st.zeroBytes++
				} else {
					st.constNZBytes++
				}
			} else {
				st.maxChiNonC = max(st.maxChiNonC, chi)
				if seen <= 128 {
					st.halfBytes++
				} else if seen == 256 {
					st.fullBytes++
				}
			}
		}
		steps = append(steps, st)
	}
	return
}

// verifyAlgebraicCross256 checks the exact closed-form turnaround identities on Areion-256:
//  1. At d=1 (k=r-1): delta_{r,r-1}[A] == 0 (16 zero bytes) and
//     delta_{r,r-1}[B] == MC(SR(SB(T2_{r-1}^(1)) ^ SB(T2_{r-1}^(1) ^ Delta_{r-1}))),
//     plus differential-pair conservation Delta A_{r-1}^(2) == Delta A_{r-1}^(1) and
//     Delta T2_{r-1}^(2) == Delta T1_{r-1}^(1) == Delta T2_{r-1}^(1).
//  2. At d=2 (k=r-2):
//     delta_{r,r-2}[A] == A_{r-2}^(1) ^ SB^-1(SB(A_{r-2}^(1)) ^ SR^-1(delta_{r,r-1}[B])) and
//     delta_{r,r-2}[B] == W_{r-2}^(1) ^ W_{r-2}^(2).
func verifyAlgebraicCross256(rc2 *[15][16]byte) {
	rng := rand.New(rand.NewPCG(256, 1))
	badD1, badD2, badPair := 0, 0, 0
	for totalR := 1; totalR <= 10; totalR++ {
		r1 := totalR - 1
		ai1, bi1 := 0, 1
		if r1%2 == 1 {
			ai1, bi1 = 1, 0
		}
		var deltaR1 Block
		xorBlock(&deltaR1, &roundConstantsP1[r1], &rc2[r1])

		for t := 0; t < 500; t++ {
			var x, y State256
			for i := range x {
				x[i] = byte(rng.Uint32())
				y[i] = byte(rng.Uint32())
			}
			sR1, sTot := x, x
			p256r(&sR1, &roundConstantsP1, r1)
			p256r(&sTot, &roundConstantsP1, totalR)

			bwd1 := sTot
			xbBwd1 := [2]*Block{(*Block)(bwd1[0:16]), (*Block)(bwd1[16:32])}
			invFinalRoundNoKey(xbBwd1[ai1])
			t2Bwd1 := *xbBwd1[ai1]
			roundNoKey(&t2Bwd1)
			xorBlock(&t2Bwd1, &t2Bwd1, &rc2[r1])
			wBwd1 := t2Bwd1
			roundNoKey(&wBwd1)
			xorBlock(xbBwd1[bi1], xbBwd1[bi1], &wBwd1)

			aFwd1 := *(*Block)(sR1[16*ai1 : 16*ai1+16])
			bFwd1 := *(*Block)(sR1[16*bi1 : 16*bi1+16])
			t1Fwd1 := aFwd1
			roundNoKey(&t1Fwd1)
			var t2Fwd1 Block
			xorBlock(&t2Fwd1, &t1Fwd1, &roundConstantsP1[r1])
			wFwd1 := t2Fwd1
			roundNoKey(&wFwd1)

			var dA1, dB1, wantB1 Block
			xorBlock(&dA1, &aFwd1, xbBwd1[ai1])
			xorBlock(&dB1, &bFwd1, xbBwd1[bi1])
			xorBlock(&wantB1, &wFwd1, &wBwd1)
			if dA1 != (Block{}) || dB1 != wantB1 {
				badD1++
			}

			// Pair conservation at d=1 for (x, y)
			yR1, yTot := y, y
			p256r(&yR1, &roundConstantsP1, r1)
			p256r(&yTot, &roundConstantsP1, totalR)
			yBwd1 := yTot
			ybBwd1 := [2]*Block{(*Block)(yBwd1[0:16]), (*Block)(yBwd1[16:32])}
			invFinalRoundNoKey(ybBwd1[ai1])
			yt2Bwd1 := *ybBwd1[ai1]
			roundNoKey(&yt2Bwd1)
			xorBlock(&yt2Bwd1, &yt2Bwd1, &rc2[r1])

			yaFwd1 := *(*Block)(yR1[16*ai1 : 16*ai1+16])
			yt1Fwd1 := yaFwd1
			roundNoKey(&yt1Fwd1)
			var yt2Fwd1 Block
			xorBlock(&yt2Fwd1, &yt1Fwd1, &roundConstantsP1[r1])

			var delAFwd, delABwd, delT2Fwd, delT2Bwd Block
			xorBlock(&delAFwd, &aFwd1, &yaFwd1)
			xorBlock(&delABwd, xbBwd1[ai1], ybBwd1[ai1])
			xorBlock(&delT2Fwd, &t2Fwd1, &yt2Fwd1)
			xorBlock(&delT2Bwd, &t2Bwd1, &yt2Bwd1)
			if delAFwd != delABwd || delT2Fwd != delT2Bwd {
				badPair++
			}

			if totalR >= 2 {
				r2 := totalR - 2
				ai2, bi2 := 0, 1
				if r2%2 == 1 {
					ai2, bi2 = 1, 0
				}
				sR2 := x
				p256r(&sR2, &roundConstantsP1, r2)
				bwd2 := bwd1
				xbBwd2 := [2]*Block{(*Block)(bwd2[0:16]), (*Block)(bwd2[16:32])}
				invFinalRoundNoKey(xbBwd2[ai2])
				t2Bwd2 := *xbBwd2[ai2]
				roundNoKey(&t2Bwd2)
				xorBlock(&t2Bwd2, &t2Bwd2, &rc2[r2])
				wBwd2 := t2Bwd2
				roundNoKey(&wBwd2)
				xorBlock(xbBwd2[bi2], xbBwd2[bi2], &wBwd2)

				aFwd2 := *(*Block)(sR2[16*ai2 : 16*ai2+16])
				bFwd2 := *(*Block)(sR2[16*bi2 : 16*bi2+16])
				wFwd2 := aFwd2
				roundNoKey(&wFwd2)
				xorBlock(&wFwd2, &wFwd2, &roundConstantsP1[r2])
				roundNoKey(&wFwd2)

				isrDB1 := dB1
				invShiftRows(&isrDB1)
				var wantA2, wantB2, dA2, dB2 Block
				for j := 0; j < 16; j++ {
					wantA2[j] = aFwd2[j] ^ invSbox[sbox[aFwd2[j]]^isrDB1[j]]
				}
				xorBlock(&wantB2, &wFwd2, &wBwd2)
				xorBlock(&dA2, &aFwd2, xbBwd2[ai2])
				xorBlock(&dB2, &bFwd2, xbBwd2[bi2])
				if dA2 != wantA2 || dB2 != wantB2 {
					badD2++
				}
			}
		}
	}
	fmt.Printf("algebraic cross-composition check (Areion-256, 500 x r=1..10): d=1 mismatches=%d, d=2 mismatches=%d, pair-conservation mismatches=%d\n",
		badD1, badD2, badPair)
	if badD1 != 0 || badD2 != 0 || badPair != 0 {
		os.Exit(1)
	}
}

// verifyAlgebraicCross512 checks the exact closed-form identities on Areion-512:
//  1. At d=1 (k=r-1): delta_{r,r-1}[a] == 0, delta_{r,r-1}[b] == 0,
//     delta_{r,r-1}[d] == MC(Delta_{r-1}) (constant), and
//     delta_{r,r-1}[c] == c_{r-1} ^ SB^-1(SB(c_{r-1}) ^ SR^-1(Delta_{r-1})).
//  2. At d=2 (k=r-2):
//     delta_{r,r-2}[a] == a_{r-2} ^ SB^-1(SB(a_{r-2}) ^ SR^-1(MC(Delta_{r-1}))),
//     delta_{r,r-2}[b] == MC^2(Delta_{r-1}) (constant nonzero),
//     delta_{r,r-2}[c] == c_{r-2} ^ SB^-1(SB(c_{r-2}) ^ SR^-1(Delta_{r-2})), and
//     delta_{r,r-2}[d] == MC(Delta_{r-2}) ^ delta_{r,r-1}[c_{r-1}].
//  3. Differential-pair turnaround conservation laws across d=1, 2, 3:
//     at d=1: Delta a^(2) == Delta a^(1), Delta b^(2) == Delta b^(1), Delta d^(2) == Delta d^(1),
//     Delta c2^(2) == Delta c2^(1), supp(Delta c^(2)) == supp(Delta c^(1));
//     at d=2: Delta b^(2) == Delta b^(1), Delta c2^(2) == Delta c2^(1),
//     supp(Delta a^(2)) == supp(Delta a^(1)), supp(Delta c^(2)) == supp(Delta c^(1));
//     at d=3: supp(Delta c2^(2)) == supp(Delta c2^(1)).
func verifyAlgebraicCross512(rc2 *[15][16]byte) {
	rng := rand.New(rand.NewPCG(512, 1))
	badD1, badD2, badPair := 0, 0, 0
	for totalR := 1; totalR <= 15; totalR++ {
		r1 := totalR - 1
		o1 := r1 % 4
		ia1, ib1, ic1, id1 := o1, (o1+1)%4, (o1+2)%4, (o1+3)%4
		var deltaR1 Block
		xorBlock(&deltaR1, &roundConstantsP1[r1], &rc2[r1])
		mcDelta1 := deltaR1
		mixColumns(&mcDelta1)
		mc2Delta1 := mcDelta1
		mixColumns(&mc2Delta1)
		isrDelta1 := deltaR1
		invShiftRows(&isrDelta1)
		isrMcDelta1 := mcDelta1
		invShiftRows(&isrMcDelta1)

		for t := 0; t < 500; t++ {
			var x, y State512
			for i := range x {
				x[i] = byte(rng.Uint32())
				y[i] = byte(rng.Uint32())
			}
			// Forward to r1 and totalR
			sR1 := x
			p512r(&sR1, &roundConstantsP1, r1)
			sTot := sR1
			xb := [4]*Block{(*Block)(sTot[0:16]), (*Block)(sTot[16:32]), (*Block)(sTot[32:48]), (*Block)(sTot[48:64])}
			areion512Round(xb[ia1], xb[ib1], xb[ic1], xb[id1], &roundConstantsP1[r1])

			// 1 inverse round under P2^-1
			bwd1 := sTot
			xbBwd1 := [4]*Block{(*Block)(bwd1[0:16]), (*Block)(bwd1[16:32]), (*Block)(bwd1[32:48]), (*Block)(bwd1[48:64])}
			invRound512(xbBwd1[ia1], xbBwd1[ib1], xbBwd1[ic1], xbBwd1[id1], &rc2[r1])

			var dA, dB, dC, dD Block
			xorBlock(&dA, (*Block)(sR1[16*ia1:16*ia1+16]), xbBwd1[ia1])
			xorBlock(&dB, (*Block)(sR1[16*ib1:16*ib1+16]), xbBwd1[ib1])
			xorBlock(&dC, (*Block)(sR1[16*ic1:16*ic1+16]), xbBwd1[ic1])
			xorBlock(&dD, (*Block)(sR1[16*id1:16*id1+16]), xbBwd1[id1])

			var wantC Block
			cFwd := (*Block)(sR1[16*ic1 : 16*ic1+16])
			for j := 0; j < 16; j++ {
				wantC[j] = cFwd[j] ^ invSbox[sbox[cFwd[j]]^isrDelta1[j]]
			}
			if dA != (Block{}) || dB != (Block{}) || dD != mcDelta1 || dC != wantC {
				badD1++
			}

			// Pair conservation at d=1 for (x, y)
			yR1 := y
			p512r(&yR1, &roundConstantsP1, r1)
			yTot := yR1
			yb := [4]*Block{(*Block)(yTot[0:16]), (*Block)(yTot[16:32]), (*Block)(yTot[32:48]), (*Block)(yTot[48:64])}
			areion512Round(yb[ia1], yb[ib1], yb[ic1], yb[id1], &roundConstantsP1[r1])
			yBwd1 := yTot
			ybBwd1 := [4]*Block{(*Block)(yBwd1[0:16]), (*Block)(yBwd1[16:32]), (*Block)(yBwd1[32:48]), (*Block)(yBwd1[48:64])}
			invRound512(ybBwd1[ia1], ybBwd1[ib1], ybBwd1[ic1], ybBwd1[id1], &rc2[r1])
			if act((*Block)(sR1[16*ia1:16*ia1+16]), (*Block)(yR1[16*ia1:16*ia1+16])) != act(xbBwd1[ia1], ybBwd1[ia1]) ||
				act((*Block)(sR1[16*ib1:16*ib1+16]), (*Block)(yR1[16*ib1:16*ib1+16])) != act(xbBwd1[ib1], ybBwd1[ib1]) ||
				act((*Block)(sR1[16*ic1:16*ic1+16]), (*Block)(yR1[16*ic1:16*ic1+16])) != act(xbBwd1[ic1], ybBwd1[ic1]) ||
				act((*Block)(sR1[16*id1:16*id1+16]), (*Block)(yR1[16*id1:16*id1+16])) != act(xbBwd1[id1], ybBwd1[id1]) {
				badPair++
			}

			if totalR >= 2 {
				r2 := totalR - 2
				o2 := r2 % 4
				ia2, ib2, ic2, id2 := o2, (o2+1)%4, (o2+2)%4, (o2+3)%4
				var deltaR2 Block
				xorBlock(&deltaR2, &roundConstantsP1[r2], &rc2[r2])
				mcDelta2 := deltaR2
				mixColumns(&mcDelta2)
				isrDelta2 := deltaR2
				invShiftRows(&isrDelta2)

				sR2 := x
				p512r(&sR2, &roundConstantsP1, r2)
				bwd2 := bwd1
				xbBwd2 := [4]*Block{(*Block)(bwd2[0:16]), (*Block)(bwd2[16:32]), (*Block)(bwd2[32:48]), (*Block)(bwd2[48:64])}
				invRound512(xbBwd2[ia2], xbBwd2[ib2], xbBwd2[ic2], xbBwd2[id2], &rc2[r2])

				var dA2, dB2, dC2, dD2 Block
				xorBlock(&dA2, (*Block)(sR2[16*ia2:16*ia2+16]), xbBwd2[ia2])
				xorBlock(&dB2, (*Block)(sR2[16*ib2:16*ib2+16]), xbBwd2[ib2])
				xorBlock(&dC2, (*Block)(sR2[16*ic2:16*ic2+16]), xbBwd2[ic2])
				xorBlock(&dD2, (*Block)(sR2[16*id2:16*id2+16]), xbBwd2[id2])

				var wantA2, wantC2, wantD2 Block
				aFwd2 := (*Block)(sR2[16*ia2 : 16*ia2+16])
				cFwd2 := (*Block)(sR2[16*ic2 : 16*ic2+16])
				for j := 0; j < 16; j++ {
					wantA2[j] = aFwd2[j] ^ invSbox[sbox[aFwd2[j]]^isrMcDelta1[j]]
					wantC2[j] = cFwd2[j] ^ invSbox[sbox[cFwd2[j]]^isrDelta2[j]]
					wantD2[j] = mcDelta2[j] ^ wantC[j]
				}
				if dA2 != wantA2 || dB2 != mc2Delta1 || dC2 != wantC2 || dD2 != wantD2 {
					badD2++
				}

				yR2 := y
				p512r(&yR2, &roundConstantsP1, r2)
				yBwd2 := yBwd1
				ybBwd2 := [4]*Block{(*Block)(yBwd2[0:16]), (*Block)(yBwd2[16:32]), (*Block)(yBwd2[32:48]), (*Block)(yBwd2[48:64])}
				invRound512(ybBwd2[ia2], ybBwd2[ib2], ybBwd2[ic2], ybBwd2[id2], &rc2[r2])
				if act((*Block)(sR2[16*ia2:16*ia2+16]), (*Block)(yR2[16*ia2:16*ia2+16])) != act(xbBwd2[ia2], ybBwd2[ia2]) ||
					act((*Block)(sR2[16*ib2:16*ib2+16]), (*Block)(yR2[16*ib2:16*ib2+16])) != act(xbBwd2[ib2], ybBwd2[ib2]) ||
					act((*Block)(sR2[16*ic2:16*ic2+16]), (*Block)(yR2[16*ic2:16*ic2+16])) != act(xbBwd2[ic2], ybBwd2[ic2]) {
					badPair++
				}

				if totalR >= 3 {
					r3 := totalR - 3
					o3 := r3 % 4
					ic3 := (o3 + 2) % 4
					// At d=3, cf_{r-3}^(2) == b_{r-2}^(2) == b_{r-2}^(1) ^ MC^2(Delta_{r-1}),
					// so c2_{r-3}^(2) = SB^-1(ISR(IMC(cf_{r-3}^(2)))) has the same byte support as c2_{r-3}^(1).
					sR3 := x
					p512r(&sR3, &roundConstantsP1, r3)
					yR3 := y
					p512r(&yR3, &roundConstantsP1, r3)
					c1x := *(*Block)(sR3[16*ic3 : 16*ic3+16])
					c1y := *(*Block)(yR3[16*ic3 : 16*ic3+16])
					finalRoundNoKey(&c1x)
					finalRoundNoKey(&c1y)
					xorBlock(&c1x, &c1x, &roundConstantsP1[r3])
					xorBlock(&c1y, &c1y, &roundConstantsP1[r3])

					c2x := *xbBwd2[ic3]
					c2y := *ybBwd2[ic3]
					invMixColumns(&c2x)
					invMixColumns(&c2y)
					invFinalRoundNoKey(&c2x)
					invFinalRoundNoKey(&c2y)
					if act(&c1x, &c1y) != act(&c2x, &c2y) {
						badPair++
					}
				}
			}
		}
	}
	fmt.Printf("algebraic cross-composition check (Areion-512, 500 x r=1..15): d=1 closed-form mismatches=%d, d=2 constant MC^2(Delta_{r-1}) mismatches=%d, d=1..3 pair-conservation mismatches=%d\n",
		badD1, badD2, badPair)
	if badD1 != 0 || badD2 != 0 || badPair != 0 {
		os.Exit(1)
	}
}

type crossAvalRow struct {
	width     int
	levelID   string
	levelName string
	rounds    int
	idBits    int     // input bits i where C_r(x) ^ C_r(x ^ e_i) == e_i identically
	meanHW    float64 // mean wt(C_r(x) ^ C_r(x ^ e_i)) / n
	minHW     float64 // min_i mean wt(C_r(x) ^ C_r(x ^ e_i)) / n
	maxBias   float64 // max_{i,j} |Pr[bit_j(C_r(x) ^ C_r(x ^ e_i)) = 1] - 0.5|
}

func evalCross(width, rounds int, rc2 *[15][16]byte, in, out []byte) {
	if width == 256 {
		var s State256
		copy(s[:], in)
		p256r(&s, &roundConstantsP1, rounds)
		invP256r(&s, rc2, rounds)
		copy(out, s[:])
	} else {
		var s State512
		copy(s[:], in)
		p512r(&s, &roundConstantsP1, rounds)
		invP512r(&s, rc2, rounds)
		copy(out, s[:])
	}
}

func computeCrossAval(width, rounds int, lv p2Level, nAval int) crossAvalRow {
	nb := width / 8
	nbits := width
	rc2 := &lv.rc
	rng := rand.New(rand.NewPCG(uint64(width*500+rounds), 123))

	flips := make([][]int, nbits)
	for bi := range flips {
		flips[bi] = make([]int, nbits)
	}
	hwSum := make([]int, nbits)
	nonIdCount := make([]int, nbits)

	x := make([]byte, nb)
	x2 := make([]byte, nb)
	baseOut := make([]byte, nb)
	flipOut := make([]byte, nb)

	for s := 0; s < nAval; s++ {
		for i := 0; i < nb; i += 8 {
			v := rng.Uint64()
			for k := 0; k < 8; k++ {
				x[i+k] = byte(v >> (8 * k))
			}
		}
		evalCross(width, rounds, rc2, x, baseOut)
		copy(x2, x)
		for bi := 0; bi < nbits; bi++ {
			x2[bi/8] ^= 1 << (bi % 8)
			evalCross(width, rounds, rc2, x2, flipOut)
			x2[bi/8] ^= 1 << (bi % 8)
			hw := 0
			isId := true
			rowFlips := flips[bi]
			for B := 0; B < nb; B++ {
				diff := baseOut[B] ^ flipOut[B]
				expected := byte(0)
				if B == bi/8 {
					expected = 1 << (bi % 8)
				}
				if diff != expected {
					isId = false
				}
				if diff != 0 {
					hw += bits.OnesCount8(diff)
					for bit := 0; bit < 8; bit++ {
						if diff>>bit&1 == 1 {
							rowFlips[8*B+bit]++
						}
					}
				}
			}
			if !isId {
				nonIdCount[bi]++
			}
			hwSum[bi] += hw
		}
	}

	row := crossAvalRow{
		width:     width,
		levelID:   lv.id,
		levelName: lv.name,
		rounds:    rounds,
		minHW:     1.0,
	}
	totalHW := 0
	for bi := 0; bi < nbits; bi++ {
		if nonIdCount[bi] == 0 {
			row.idBits++
		}
		totalHW += hwSum[bi]
		avg := float64(hwSum[bi]) / float64(nAval*nbits)
		if avg < row.minHW {
			row.minHW = avg
		}
		for bj := 0; bj < nbits; bj++ {
			p := float64(flips[bi][bj]) / float64(nAval)
			b := math.Abs(p - 0.5)
			if b > row.maxBias {
				row.maxBias = b
			}
		}
	}
	row.meanHW = float64(totalHW) / float64(nAval*nbits*nbits)
	return row
}

// --- Backward Direct Pair P1_r^-1(y) ^ P2_r^-1(y ^ delta) Empirical Checks ---

func evalInvPair(width, rounds int, rc2 *[15][16]byte, y, delta, out []byte) {
	if width == 256 {
		var a, b State256
		copy(a[:], y)
		for i := 0; i < 32; i++ {
			b[i] = y[i] ^ delta[i]
		}
		invP256r(&a, &roundConstantsP1, rounds)
		invP256r(&b, rc2, rounds)
		for i := 0; i < 32; i++ {
			out[i] = a[i] ^ b[i]
		}
	} else {
		var a, b State512
		copy(a[:], y)
		for i := 0; i < 64; i++ {
			b[i] = y[i] ^ delta[i]
		}
		invP512r(&a, &roundConstantsP1, rounds)
		invP512r(&b, rc2, rounds)
		for i := 0; i < 64; i++ {
			out[i] = a[i] ^ b[i]
		}
	}
}

func runBackwardPairValues(maxR256, maxR512, nSamples int, variant string) {
	rc2 := p2Table(variant)
	for _, wSpec := range []struct{ w, maxR int }{{256, maxR256}, {512, maxR512}} {
		nb := wSpec.w / 8
		for r := 1; r <= wSpec.maxR; r++ {
			rng := rand.New(rand.NewPCG(uint64(wSpec.w*10+r), 55))
			deltaR := make([]byte, nb)
			for i := range deltaR {
				deltaR[i] = byte(rng.Uint32()) | 1
			}
			delta0 := make([]byte, nb)
			fHist0 := make([][256]int, nb)
			fHistR := make([][256]int, nb)
			bHist0 := make([][256]int, nb)
			bHistR := make([][256]int, nb)

			u := make([]byte, nb)
			out := make([]byte, nb)
			for s := 0; s < nSamples; s++ {
				for i := 0; i < nb; i += 8 {
					v := rng.Uint64()
					for k := 0; k < 8; k++ {
						u[i+k] = byte(v >> (8 * k))
					}
				}
				evalPair(wSpec.w, r, rc2, u, delta0, out)
				for i := 0; i < nb; i++ {
					fHist0[i][out[i]]++
				}
				evalPair(wSpec.w, r, rc2, u, deltaR, out)
				for i := 0; i < nb; i++ {
					fHistR[i][out[i]]++
				}
				evalInvPair(wSpec.w, r, rc2, u, delta0, out)
				for i := 0; i < nb; i++ {
					bHist0[i][out[i]]++
				}
				evalInvPair(wSpec.w, r, rc2, u, deltaR, out)
				for i := 0; i < nb; i++ {
					bHistR[i][out[i]]++
				}
			}
			stat := func(h [][256]int) (constB, miss int, maxChi float64, zMin, zMax int) {
				exp := float64(nSamples) / 256.0
				zMin, zMax = nSamples, 0
				for i := 0; i < nb; i++ {
					z := h[i][0]
					zMin = min(zMin, z)
					zMax = max(zMax, z)
					seen := 0
					chi := 0.0
					for v := 0; v < 256; v++ {
						c := h[i][v]
						if c == 0 {
							miss++
						} else {
							seen++
						}
						d := float64(c) - exp
						chi += d * d / exp
					}
					if seen == 1 {
						constB++
					}
					maxChi = max(maxChi, chi)
				}
				return
			}
			fc0, fm0, fchi0, _, _ := stat(fHist0)
			fcr, fmr, fchir, fzmin, fzmax := stat(fHistR)
			bc0, bm0, bchi0, _, _ := stat(bHist0)
			bcr, bmr, bchir, bzmin, bzmax := stat(bHistR)
			fmt.Printf("Areion-%d r=%2d (%s) | FWD d=0: const=%2d miss=%5d chi2=%10.1f | BWD d=0: const=%2d miss=%5d chi2=%10.1f | FWD d=rand: const=%2d miss=%5d chi2=%8.1f z=[%d,%d] | BWD d=rand: const=%2d miss=%5d chi2=%8.1f z=[%d,%d]\n",
				wSpec.w, r, variant,
				fc0, fm0, fchi0, bc0, bm0, bchi0,
				fcr, fmr, fchir, fzmin, fzmax, bcr, bmr, bchir, bzmin, bzmax)
		}
	}
}

// --- Backward Weak-Coset Trails (InversePermute vs Permute) ---

func mkInv256(t *[15][16]byte) roundFn {
	return func(s []byte, r int) {
		// r = 0..9 indexes the inverse step from round 9-r
		rk := 9 - r
		x := [2]*Block{(*Block)(s[0:16]), (*Block)(s[16:32])}
		ai, bi := 0, 1
		if rk%2 == 1 {
			ai, bi = 1, 0
		}
		invFinalRoundNoKey(x[ai])
		temp := *x[ai]
		roundNoKey(&temp)
		xorBlock(&temp, &temp, &t[rk])
		roundNoKey(&temp)
		xorBlock(x[bi], x[bi], &temp)
	}
}

func mkInv512(t *[15][16]byte) roundFn {
	return func(s []byte, r int) {
		rk := 14 - r
		x := [4]*Block{(*Block)(s[0:16]), (*Block)(s[16:32]), (*Block)(s[32:48]), (*Block)(s[48:64])}
		o := rk % 4
		invRound512(x[o], x[(o+1)%4], x[(o+2)%4], x[(o+3)%4], &t[rk])
	}
}

func runBackwardCosets(quick bool) {
	lines := lineBases()
	shift := *p2Table("shift")
	sym1 := symTable(&roundConstantsP1, 1)
	tables := []struct {
		name string
		t    *[15][16]byte
	}{{"P1^-1", &roundConstantsP1}, {"P2^-1 shift", &shift}, {"control sym1^-1", &sym1}}

	widths := []struct {
		w      string
		nbytes int
		rounds int
	}{{"256", 32, 10}, {"512", 64, 15}}
	if quick {
		widths = widths[:1]
	}

	for _, wSpec := range widths {
		for _, tb := range tables {
			var f roundFn
			if wSpec.w == "256" {
				f = mkInv256(tb.t)
			} else {
				f = mkInv512(tb.t)
			}
			stats := map[string]*famStat{}
			var mu sync.Mutex
			type job struct {
				fam string
				sd  seed
			}
			var jobs []job
			rng := rand.New(rand.NewPCG(1, 2))
			baseFn := func(r *rand.Rand) vec { return vec{} }
			for _, sd := range seeds(wSpec.nbytes, wSpec.rounds, baseFn, rng, lines) {
				fam := "1-dim bytes in a column"
				switch {
				case strings.Contains(sd.name, " diag "):
					fam = "1-dim bytes in a diagonal"
				case strings.HasPrefix(sd.name, "full"):
					fam = "full byte"
				case strings.HasPrefix(sd.name, "line"):
					fam = "F4/F16 line in a byte"
				}
				jobs = append(jobs, job{fam, sd})
			}
			for r0 := 0; r0 < wSpec.rounds; r0++ {
				jobs = append(jobs, job{"column-rotation fixed space (period 1)", seed{"sym1", symSeed(wSpec.nbytes, 1), r0}})
				jobs = append(jobs, job{"column-rotation fixed space (period 2)", seed{"sym2", symSeed(wSpec.nbytes, 2), r0}})
			}
			ch := make(chan int, len(jobs))
			for i := range jobs {
				ch <- i
			}
			close(ch)
			var wg sync.WaitGroup
			for w := 0; w < runtime.NumCPU(); w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range ch {
						lr := rand.New(rand.NewPCG(uint64(i), 99))
						runFamily(stats, &mu, jobs[i].fam, jobs[i].sd, f, wSpec.rounds, wSpec.nbytes, lr, i)
					}
				}()
			}
			wg.Wait()
			var fams []string
			for k := range stats {
				fams = append(fams, k)
			}
			sort.Strings(fams)
			for _, k := range fams {
				s := stats[k]
				fmt.Printf("Areion-%s | %-15s | %-40s | seeds %5d | exact max %2d (cut: %d, longest %d) [%s] | below generic bound max %2d (cut: %d, longest %d) [%s]\n",
					wSpec.w, tb.name, k, s.seeds, s.exactMax, s.cutExact, s.cutExactMax, s.exactArg, s.structMax, s.cutStruct, s.cutStructMax, s.structArg)
			}
		}
	}
}

func crossMain() {
	// Usage: go run ./analysis/go cross [maxR256 maxR512 [quick]]
	maxR256, maxR512 := 10, 15
	quick := false
	if len(os.Args) >= 4 {
		maxR256, _ = strconv.Atoi(os.Args[2])
		maxR512, _ = strconv.Atoi(os.Args[3])
	}
	if len(os.Args) >= 5 && os.Args[4] == "quick" {
		quick = true
	}
	nSamples := 1 << 18
	nAval := 1024
	if quick {
		nSamples = 1 << 14
		nAval = 256
	}

	checkInv()
	sh := p2Table("shift")
	verifyAlgebraicCross256(sh)
	verifyAlgebraicCross512(sh)

	// 1. Step-by-step intermediate state delta trajectory delta_{r,k}(x) = s_k^(1)(x) ^ s_k^(2)(x)
	// for both reduced rounds (k=0 end-to-end C_r(x) ^ x for r=1..R) and full internal trajectory (r=R, k=R-1..0).
	fmt.Printf("\n== Track 2.1: Cross-Composition C_r(x) = P2_r^-1(P1_r(x)) Intermediate-State & End-to-End Deltas (samples=%d)\n", nSamples)
	for _, wSpec := range []struct{ w, maxR int }{{256, maxR256}, {512, maxR512}} {
		nb := wSpec.w / 8
		for r := 1; r <= wSpec.maxR; r++ {
			steps, invol := runCrossTrajectory(wSpec.w, r, sh, nSamples)
			// End-to-end displacement delta_{r,0}(x) = C_r(x) ^ x is the last step (k=0, d=r)
			end := steps[len(steps)-1]
			fmt.Printf("Areion-%d C_%-2d end-to-end (k=0, d=%2d) | invol(C_r^2=id)=%.3f | zeroB=%2d/%2d constNZ=%2d/%2d halfB(<=128)=%2d/%2d fullB(256)=%2d/%2d miss=%5d maxChi(nonConst)=%10.1f\n",
				wSpec.w, r, end.depthD, invol,
				end.zeroBytes, nb, end.constNZBytes, nb, end.halfBytes, nb, end.fullBytes, nb,
				end.missingVals, end.maxChiNonC)
			if r == wSpec.maxR {
				fmt.Printf("  -- Internal boundary trajectory delta_{%d, k}(x) = s_k^(1)(x) ^ s_k^(2)(x) for k = %d..0:\n", r, r-1)
				for _, st := range steps {
					fmt.Printf("     k=%2d (bwd depth d=%2d): zeroB=%2d/%2d constNZ=%2d/%2d halfB(<=128)=%2d/%2d fullB(256)=%2d/%2d miss=%5d maxChi(nonConst)=%10.1f\n",
						st.boundaryK, st.depthD,
						st.zeroBytes, nb, st.constNZBytes, nb, st.halfBytes, nb, st.fullBytes, nb,
						st.missingVals, st.maxChiNonC)
				}
			}
		}
	}

	// 2. End-to-end differential avalanche of C_r(x) ^ C_r(x ^ e_i) across L0..L4p and r=1..R
	fmt.Printf("\n== Track 2.2: Cross-Composition Differential Avalanche C_r(x) ^ C_r(x ^ e_i) Across Ladder Levels (pairs=%d)\n", nAval)
	ladder := buildLadder()
	// Evaluate cross-composition avalanche across all 11 ladder levels L0..L4p:
	type avalJob struct {
		idx    int
		width  int
		rounds int
		lv     p2Level
	}
	var aJobs []avalJob
	for _, wSpec := range []struct{ w, maxR int }{{256, maxR256}, {512, maxR512}} {
		for _, lv := range ladder {
			for r := 1; r <= wSpec.maxR; r++ {
				aJobs = append(aJobs, avalJob{len(aJobs), wSpec.w, r, lv})
			}
		}
	}
	aRes := make([]crossAvalRow, len(aJobs))
	aCh := make(chan avalJob, len(aJobs))
	for _, jb := range aJobs {
		aCh <- jb
	}
	close(aCh)
	var wg sync.WaitGroup
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jb := range aCh {
				aRes[jb.idx] = computeCrossAval(jb.width, jb.rounds, jb.lv, nAval)
			}
		}()
	}
	wg.Wait()
	for _, ar := range aRes {
		fmt.Printf("Areion-%d | %-4s %-12s | C_%-2d | idBits=%3d/%3d meanHW=%.4f minHW=%.4f maxBias=%.4f\n",
			ar.width, ar.levelID, ar.levelName, ar.rounds,
			ar.idBits, ar.width, ar.meanHW, ar.minHW, ar.maxBias)
	}

	// 3. Forward vs Backward Direct Pair (P1_r vs P2_r and P1_r^-1 vs P2_r^-1) Values & ZeroBytes
	fmt.Printf("\n== Track 2.3: Forward vs Backward Direct Pair P1_r(u)^P2_r(u^d) vs P1_r^-1(y)^P2_r^-1(y^d) (samples=%d)\n", nSamples)
	runBackwardPairValues(maxR256, maxR512, nSamples, "shift")

	// 4. Backward Weak-Coset Trails on P1^-1 and P2^-1
	fmt.Printf("\n== Track 2.4: Backward Weak-Coset Containment Trails on P1^-1 and P2^-1\n")
	runBackwardCosets(quick)
}

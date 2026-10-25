package main

// Track 1: Parameterized P2^(k) dependence-dissolution spectrum across
// reduced and full rounds (r = 1..10 for Areion-256, r = 1..15 for
// Areion-512). Evaluates the 11-level perturbation ladder L0..L4p from
// identical tables (SoEM1) and column-rotated symmetry to single-byte /
// single-round local perturbations, even/odd round-cadence perturbations,
// sparse per-round column vs inverse-ShiftRows diagonal perturbations, and
// the full NUMS Table 2 (shift and pi forms).

import (
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"math/rand/v2"
	"os"
	"runtime"
	"strconv"
	"sync"
)

type p2Level struct {
	id   string
	name string
	desc string
	rc   [15][16]byte
}

// rot1Block applies a 1-column cyclic shift (col c -> col (c+1)%4) to a 16-byte block.
func rot1Block(b *Block) Block {
	var o Block
	for c := 0; c < 4; c++ {
		nc := (c + 1) % 4
		for row := 0; row < 4; row++ {
			o[4*nc+row] = b[4*c+row]
		}
	}
	return o
}

func rot1State256(s *State256) State256 {
	var o State256
	b0 := rot1Block((*Block)(s[0:16]))
	b1 := rot1Block((*Block)(s[16:32]))
	copy(o[0:16], b0[:])
	copy(o[16:32], b1[:])
	return o
}

func rot1State512(s *State512) State512 {
	var o State512
	for blk := 0; blk < 4; blk++ {
		b := rot1Block((*Block)(s[16*blk : 16*blk+16]))
		copy(o[16*blk:16*blk+16], b[:])
	}
	return o
}

// buildLadder constructs the 11 parameterized P2^(k) tables relative to current roundConstantsP1.
func buildLadder() []p2Level {
	p1 := roundConstantsP1
	sh := *p2Table("shift")
	pi := *p2Table("pi")

	// L0: identical (RC2 = RC1)
	l0 := p1

	// L1: 1-column cyclic rotation of RC1 in every round
	var l1 [15][16]byte
	for r := 0; r < 15; r++ {
		l1[r] = rot1Block(&p1[r])
	}

	// L2a: single byte in round 0 only (byte 0 from Table 2)
	l2a := p1
	l2a[0][0] = sh[0][0]

	// L2b: single round in round 0 only (all 16 bytes of round 0 from Table 2)
	l2b := p1
	l2b[0] = sh[0]

	// L2c: even rounds only (rounds 0, 2, 4, ..., 14 from Table 2; odd rounds from Table 1)
	l2c := p1
	for r := 0; r < 15; r += 2 {
		l2c[r] = sh[r]
	}

	// L2d: odd rounds only (rounds 1, 3, 5, ..., 13 from Table 2; even rounds from Table 1)
	l2d := p1
	for r := 1; r < 15; r += 2 {
		l2d[r] = sh[r]
	}

	// L3a: sparse 1 byte per round (byte 0 of every round from Table 2)
	l3a := p1
	for r := 0; r < 15; r++ {
		l3a[r][0] = sh[r][0]
	}

	// L3b: sparse 1 column (4 bytes) per round (col 0: bytes 0, 1, 2, 3 of every round from Table 2)
	l3b := p1
	for r := 0; r < 15; r++ {
		for row := 0; row < 4; row++ {
			l3b[r][row] = sh[r][row]
		}
	}

	// L3c: sparse 1 inverse-ShiftRows diagonal (4 bytes: 0, 5, 10, 15) per round from Table 2
	l3c := p1
	for r := 0; r < 15; r++ {
		for _, idx := range [4]int{0, 5, 10, 15} {
			l3c[r][idx] = sh[r][idx]
		}
	}

	return []p2Level{
		{"L0", "ident", "RC2 = RC1 (wt(Delta_r) = 0; SoEM1)", l0},
		{"L1", "rot1", "RC2 = sigma_1(RC1) (1-col rotation; commuting symmetry)", l1},
		{"L2a", "onebyte_r0", "RC2 differs in 1 byte of round 0 only (wt(Delta_0) = 1)", l2a},
		{"L2b", "oneround_r0", "RC2 differs in round 0 only (wt(Delta_0) = 16)", l2b},
		{"L2c", "even_rounds", "RC2 differs in even rounds only (wt(Delta_{2k}) = 16, wt(Delta_{2k+1}) = 0)", l2c},
		{"L2d", "odd_rounds", "RC2 differs in odd rounds only (wt(Delta_{2k}) = 0, wt(Delta_{2k+1}) = 16)", l2d},
		{"L3a", "sparse1", "RC2 differs in 1 byte/round (wt(Delta_r) = 1)", l3a},
		{"L3b", "sparse4_col", "RC2 differs in 1 col/round (bytes 0..3; wt(Delta_r) = 4)", l3b},
		{"L3c", "sparse4_diag", "RC2 differs on inv-SR diagonal (0,5,10,15)/round (wt(Delta_r) = 4)", l3c},
		{"L4", "table2_shift", "Library Table 2, shift form (wt(Delta_r) = 16)", sh},
		{"L4p", "table2_pi", "Plain pi Table 2, pi form (wt(Delta_r) = 16)", pi},
	}
}

// colFeasibleFast computes the exact 16x16 column feasibility table of
// T2 = MC(S) ^ delta without recursive closure overhead.
func colFeasibleFast(delta [4]byte) (feas [16][16]bool) {
	if delta == [4]byte{} {
		feas[0][0] = true
		for s := 1; s < 16; s++ {
			for t := 1; t < 16; t++ {
				if popc(s)+popc(t) >= 5 {
					feas[s][t] = true
				}
			}
		}
		return
	}
	// side 1: |s| <= 2
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
	// side 2: |t| <= 2 via forEach, and |t| == 3 via flat loops
	for t := 0; t < 16; t++ {
		if popc(t) <= 2 {
			forEach(t, func(v [4]byte) {
				for i := 0; i < 4; i++ {
					v[i] ^= delta[i]
				}
				feas[sup(invMcCol(v))][t] = true
			})
		} else if popc(t) == 3 {
			var p0, p1, p2 int
			k := 0
			for i := 0; i < 4; i++ {
				if t>>i&1 == 1 {
					switch k {
					case 0:
						p0 = i
					case 1:
						p1 = i
					case 2:
						p2 = i
					}
					k++
				}
			}
			for x0 := 1; x0 < 256; x0++ {
				for x1 := 1; x1 < 256; x1++ {
					for x2 := 1; x2 < 256; x2++ {
						v := delta
						v[p0] ^= byte(x0)
						v[p1] ^= byte(x1)
						v[p2] ^= byte(x2)
						feas[sup(invMcCol(v))][t] = true
					}
				}
			}
		}
	}
	// corner |s| >= 3, t = 15
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

type levelSpecJSON struct {
	ID    string              `json:"id"`
	Name  string              `json:"name"`
	Desc  string              `json:"desc"`
	RC    [15][16]byte        `json:"rc"`
	Masks [15]uint16          `json:"masks"`
	Feas  [15][4][16][16]bool `json:"feas"`
}

// feasDissolve writes the ladder definitions, byte-activity masks, and
// column feasibility tables for all 11 levels L0..L4p as JSON.
func feasDissolve() {
	ladder := buildLadder()
	// Collect unique 4-byte column differences across all levels.
	uniq := map[[4]byte]bool{}
	for _, lv := range ladder {
		for r := 0; r < 15; r++ {
			for c := 0; c < 4; c++ {
				var d [4]byte
				for i := 0; i < 4; i++ {
					d[i] = roundConstantsP1[r][4*c+i] ^ lv.rc[r][4*c+i]
				}
				uniq[d] = true
			}
		}
	}
	keys := make([][4]byte, 0, len(uniq))
	for d := range uniq {
		keys = append(keys, d)
	}
	cache := make(map[[4]byte][16][16]bool, len(keys))
	var mu sync.Mutex
	ch := make(chan [4]byte, len(keys))
	for _, d := range keys {
		ch <- d
	}
	close(ch)
	var wg sync.WaitGroup
	workers := runtime.NumCPU()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range ch {
				f := colFeasibleFast(d)
				mu.Lock()
				cache[d] = f
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	out := map[string]levelSpecJSON{}
	order := make([]string, 0, len(ladder))
	for _, lv := range ladder {
		var spec levelSpecJSON
		spec.ID = lv.id
		spec.Name = lv.name
		spec.Desc = lv.desc
		spec.RC = lv.rc
		for r := 0; r < 15; r++ {
			spec.Masks[r] = act(&roundConstantsP1[r], &lv.rc[r])
			for c := 0; c < 4; c++ {
				var d [4]byte
				for i := 0; i < 4; i++ {
					d[i] = roundConstantsP1[r][4*c+i] ^ lv.rc[r][4*c+i]
				}
				spec.Feas[r][c] = cache[d]
			}
		}
		out[lv.id] = spec
		order = append(order, lv.id)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"order":  order,
		"levels": out,
	})
}

// traceDissolve emits oracle activity traces (JSON lines) for a given width,
// ladder level ID, round count, and sample count n, including both delta=0 and
// nonzero delta inputs.
func traceDissolve(width int, levelID string, rounds, n int) {
	ladder := buildLadder()
	var t2 *[15][16]byte
	var seed uint64 = 10
	for i := range ladder {
		if ladder[i].id == levelID || ladder[i].name == levelID {
			t2 = &ladder[i].rc
			seed = uint64(10 + i)
			break
		}
	}
	if t2 == nil {
		panic("unknown ladder level: " + levelID)
	}
	rng := rand.New(rand.NewPCG(uint64(width), seed))
	rf := func(b []byte) {
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
	}
	enc := json.NewEncoder(os.Stdout)
	for k := 0; k < n; k++ {
		var nb [1]byte
		rf(nb[:])
		dbytes := []int{0, 1, 2, 4, 64}[int(nb[0])%5]
		if k < n/5 {
			dbytes = 0 // guarantee at least n/5 traces have delta = 0
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
			rf(u[:])
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

type dissolveRow struct {
	width     int
	levelID   string
	levelName string
	rounds    int
	// delta = 0 distribution
	d0ConstB  int
	d0Missing int
	d0MaxChi  float64
	d0ZeroMin int
	d0ZeroMax int
	// random delta distribution
	drConstB  int
	drMissing int
	drMaxChi  float64
	drZeroMin int
	drZeroMax int
	// bitwise avalanche (random delta and delta = 0)
	d0DeadIn  int
	d0MinHW   float64
	d0MaxBias float64
	drDeadIn  int
	drMinHW   float64
	drMaxBias float64
	// SoEM shift probe F_r(m) ^ F_r(m ^ delta)
	shZeroFrac float64
	shConstB   int
	shMaxChi   float64
	// Column-rotation commute & fixed-space probes
	rotCommZero int
	fixRot1Zero int
	// Coset hull dimension of u -> P1_r(u) ^ P2_r(u) on 1-byte (dim 8) and Fix(sigma_1) (dim n/4)
	hullByteD0 int
	hullByteDR int
	hullFixD0  int
}

func evalPair(width, rounds int, rc2 *[15][16]byte, u, delta, out []byte) {
	if width == 256 {
		var a, b State256
		copy(a[:], u)
		for i := 0; i < 32; i++ {
			b[i] = u[i] ^ delta[i]
		}
		p256r(&a, &roundConstantsP1, rounds)
		p256r(&b, rc2, rounds)
		for i := 0; i < 32; i++ {
			out[i] = a[i] ^ b[i]
		}
	} else {
		var a, b State512
		copy(a[:], u)
		for i := 0; i < 64; i++ {
			b[i] = u[i] ^ delta[i]
		}
		p512r(&a, &roundConstantsP1, rounds)
		p512r(&b, rc2, rounds)
		for i := 0; i < 64; i++ {
			out[i] = a[i] ^ b[i]
		}
	}
}

func pairHullDim(width, rounds int, rc2 *[15][16]byte, c coset, delta []byte, rng *rand.Rand) int {
	nbytes := width / 8
	d := len(c.basis)
	img := func(p vec) vec {
		u := fromVec(p, nbytes)
		out := make([]byte, nbytes)
		evalPair(width, rounds, rc2, u, delta, out)
		return toVec(out)
	}
	b0 := img(c.base)
	e := echelon{}
	if d <= 12 {
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
	return len(e)
}

func computeDissolveCell(width, rounds int, lv p2Level, nSamples, nAval int) dissolveRow {
	nb := width / 8
	nbits := width
	rc2 := &lv.rc
	row := dissolveRow{
		width:     width,
		levelID:   lv.id,
		levelName: lv.name,
		rounds:    rounds,
	}

	// Deterministic per-cell PRNG for delta
	rngD := rand.New(rand.NewPCG(uint64(width*100+rounds), 77))
	deltaR := make([]byte, nb)
	for i := range deltaR {
		deltaR[i] = byte(rngD.Uint32()) | 1
	}
	delta0 := make([]byte, nb)

	// 1. Histogram & Shift/Symmetry probes across nSamples (parallelized over chunks if large,
	// or caller parallelizes across cells; since there are ~160 cells, cell-level parallelism
	// across runtime.NumCPU() already saturates all 16 cores!).
	hist0 := make([][256]int, nb)
	histR := make([][256]int, nb)
	histSh := make([][256]int, nb)
	shAllZero := 0
	var rotCommOr [64]byte
	var fixRot1Or [64]byte

	u := make([]byte, nb)
	uShift := make([]byte, nb)
	out0 := make([]byte, nb)
	outR := make([]byte, nb)
	outR2 := make([]byte, nb)

	for s := 0; s < nSamples; s++ {
		for i := 0; i < nb; i += 8 {
			v := rngD.Uint64()
			for k := 0; k < 8; k++ {
				u[i+k] = byte(v >> (8 * k))
			}
		}
		evalPair(width, rounds, rc2, u, delta0, out0)
		evalPair(width, rounds, rc2, u, deltaR, outR)
		for i := 0; i < nb; i++ {
			hist0[i][out0[i]]++
			histR[i][outR[i]]++
		}
		// Shift probe: S_r(u, deltaR) = (P1(u)^P2(u^deltaR)) ^ (P1(u^deltaR)^P2(u))
		for i := 0; i < nb; i++ {
			uShift[i] = u[i] ^ deltaR[i]
		}
		evalPair(width, rounds, rc2, uShift, deltaR, outR2)
		allZ := true
		for i := 0; i < nb; i++ {
			sv := outR[i] ^ outR2[i]
			histSh[i][sv]++
			if sv != 0 {
				allZ = false
			}
		}
		if allZ {
			shAllZero++
		}
		// Symmetry probes on first 4096 samples
		if s < 4096 {
			if width == 256 {
				var st1, st2 State256
				copy(st1[:], u)
				st2 = rot1State256(&st1)
				p256r(&st1, &roundConstantsP1, rounds)
				p256r(&st2, rc2, rounds)
				st1Rot := rot1State256(&st1)
				for i := 0; i < 32; i++ {
					rotCommOr[i] |= st1Rot[i] ^ st2[i]
				}
				// Fixed-space probe: column 0 repeated in cols 1..3
				var fx1, fx2 State256
				for blk := 0; blk < 2; blk++ {
					for c := 0; c < 4; c++ {
						copy(fx1[16*blk+4*c:16*blk+4*c+4], u[16*blk:16*blk+4])
					}
				}
				fx2 = fx1
				p256r(&fx1, &roundConstantsP1, rounds)
				p256r(&fx2, rc2, rounds)
				for blk := 0; blk < 2; blk++ {
					for row := 0; row < 4; row++ {
						var colSum byte
						for c := 0; c < 4; c++ {
							idx := 16*blk + 4*c + row
							colSum ^= fx1[idx] ^ fx2[idx]
						}
						fixRot1Or[4*blk+row] |= colSum
					}
				}
			} else {
				var st1, st2 State512
				copy(st1[:], u)
				st2 = rot1State512(&st1)
				p512r(&st1, &roundConstantsP1, rounds)
				p512r(&st2, rc2, rounds)
				st1Rot := rot1State512(&st1)
				for i := 0; i < 64; i++ {
					rotCommOr[i] |= st1Rot[i] ^ st2[i]
				}
				var fx1, fx2 State512
				for blk := 0; blk < 4; blk++ {
					for c := 0; c < 4; c++ {
						copy(fx1[16*blk+4*c:16*blk+4*c+4], u[16*blk:16*blk+4])
					}
				}
				fx2 = fx1
				p512r(&fx1, &roundConstantsP1, rounds)
				p512r(&fx2, rc2, rounds)
				for blk := 0; blk < 4; blk++ {
					for row := 0; row < 4; row++ {
						var colSum byte
						for c := 0; c < 4; c++ {
							idx := 16*blk + 4*c + row
							colSum ^= fx1[idx] ^ fx2[idx]
						}
						fixRot1Or[4*blk+row] |= colSum
					}
				}
			}
		}
	}

	summarizeHist := func(h [][256]int) (constB, missing int, maxChi float64, zMin, zMax int) {
		exp := float64(nSamples) / 256.0
		zMin, zMax = nSamples, 0
		for i := 0; i < nb; i++ {
			z := h[i][0]
			zMin = min(zMin, z)
			zMax = max(zMax, z)
			chi := 0.0
			seen := 0
			for v := 0; v < 256; v++ {
				c := h[i][v]
				if c == 0 {
					missing++
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

	row.d0ConstB, row.d0Missing, row.d0MaxChi, row.d0ZeroMin, row.d0ZeroMax = summarizeHist(hist0)
	row.drConstB, row.drMissing, row.drMaxChi, row.drZeroMin, row.drZeroMax = summarizeHist(histR)
	row.shConstB, _, row.shMaxChi, _, _ = summarizeHist(histSh)
	row.shZeroFrac = float64(shAllZero) / float64(nSamples)

	for i := 0; i < nb; i++ {
		if rotCommOr[i] == 0 {
			row.rotCommZero++
		}
	}
	for i := 0; i < nb/4; i++ {
		if fixRot1Or[i] == 0 {
			row.fixRot1Zero++
		}
	}

	// 2. Bitwise input-to-output avalanche for delta = 0 and random delta
	aval := func(delta []byte) (deadIn int, minHW, maxBias float64) {
		flips := make([][]int, nbits)
		for bi := range flips {
			flips[bi] = make([]int, nbits)
		}
		hwSum := make([]int, nbits)
		baseOut := make([]byte, nb)
		flipOut := make([]byte, nb)
		u2 := make([]byte, nb)
		for s := 0; s < nAval; s++ {
			for i := 0; i < nb; i += 8 {
				v := rngD.Uint64()
				for k := 0; k < 8; k++ {
					u[i+k] = byte(v >> (8 * k))
				}
			}
			evalPair(width, rounds, rc2, u, delta, baseOut)
			copy(u2, u)
			for bi := 0; bi < nbits; bi++ {
				u2[bi/8] ^= 1 << (bi % 8)
				evalPair(width, rounds, rc2, u2, delta, flipOut)
				u2[bi/8] ^= 1 << (bi % 8)
				hw := 0
				rowFlips := flips[bi]
				for B := 0; B < nb; B++ {
					diff := baseOut[B] ^ flipOut[B]
					if diff != 0 {
						hw += bits.OnesCount8(diff)
						for bit := 0; bit < 8; bit++ {
							if diff>>bit&1 == 1 {
								rowFlips[8*B+bit]++
							}
						}
					}
				}
				hwSum[bi] += hw
			}
		}
		minHW = 1.0
		for bi := 0; bi < nbits; bi++ {
			if hwSum[bi] == 0 {
				deadIn++
			}
			avg := float64(hwSum[bi]) / float64(nAval*nbits)
			if avg < minHW {
				minHW = avg
			}
			for bj := 0; bj < nbits; bj++ {
				p := float64(flips[bi][bj]) / float64(nAval)
				b := math.Abs(p - 0.5)
				if b > maxBias {
					maxBias = b
				}
			}
		}
		return
	}

	row.d0DeadIn, row.d0MinHW, row.d0MaxBias = aval(delta0)
	row.drDeadIn, row.drMinHW, row.drMaxBias = aval(deltaR)

	// 3. Coset hull dimension of u -> P1_r(u) ^ P2_r(u ^ delta)
	var cByte coset
	for k := 0; k < 8; k++ {
		cByte.basis = append(cByte.basis, unitByte(0, 1<<k))
	}
	cFix := symSeed(nb, 1)
	row.hullByteD0 = pairHullDim(width, rounds, rc2, cByte, delta0, rngD)
	row.hullByteDR = pairHullDim(width, rounds, rc2, cByte, deltaR, rngD)
	row.hullFixD0 = pairHullDim(width, rounds, rc2, cFix, delta0, rngD)

	return row
}

func dissolveMain() {
	// Usage: go run ./analysis/go dissolve [maxR256 maxR512 [quick]]
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

	ladder := buildLadder()
	fmt.Printf("== Track 1: Parameterized P2^(k) Perturbation Ladder (%d levels, samples=%d, aval_pairs=%d)\n",
		len(ladder), nSamples, nAval)
	for _, lv := range ladder {
		w10, w15 := 0, 0
		for r := 0; r < 15; r++ {
			w := bits.OnesCount16(act(&roundConstantsP1[r], &lv.rc[r]))
			if r < 10 {
				w10 += w
			}
			w15 += w
		}
		fmt.Printf("  %-4s %-13s | active constant bytes: 10r=%3d/160, 15r=%3d/240 | %s\n",
			lv.id, lv.name, w10, w15, lv.desc)
	}

	type job struct {
		idx    int
		width  int
		rounds int
		lv     p2Level
	}
	var jobs []job
	for _, wSpec := range []struct{ w, maxR int }{{256, maxR256}, {512, maxR512}} {
		for _, lv := range ladder {
			for r := 1; r <= wSpec.maxR; r++ {
				jobs = append(jobs, job{len(jobs), wSpec.w, r, lv})
			}
		}
	}

	results := make([]dissolveRow, len(jobs))
	ch := make(chan job, len(jobs))
	for _, jb := range jobs {
		ch <- jb
	}
	close(ch)

	var wg sync.WaitGroup
	workers := runtime.NumCPU()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jb := range ch {
				results[jb.idx] = computeDissolveCell(jb.width, jb.rounds, jb.lv, nSamples, nAval)
			}
		}()
	}
	wg.Wait()

	for _, r := range results {
		nb := r.width / 8
		fmt.Printf("Areion-%d | %-4s %-12s | r=%2d | d=0: const=%2d/%2d miss=%5d chi2=%10.1f z=[%4d,%4d] deadIn=%3d minHW=%.3f bias=%.3f | d=rand: const=%2d/%2d miss=%5d chi2=%10.1f z=[%4d,%4d] deadIn=%3d minHW=%.3f bias=%.3f | shift: zero=%.3f const=%2d | sym: rotComm=%2d fixRot1=%2d | hull(1B d0/dr, fix d0)=%3d/%3d/%3d\n",
			r.width, r.levelID, r.levelName, r.rounds,
			r.d0ConstB, nb, r.d0Missing, r.d0MaxChi, r.d0ZeroMin, r.d0ZeroMax, r.d0DeadIn, r.d0MinHW, r.d0MaxBias,
			r.drConstB, nb, r.drMissing, r.drMaxChi, r.drZeroMin, r.drZeroMax, r.drDeadIn, r.drMinHW, r.drMaxBias,
			r.shZeroFrac, r.shConstB, r.rotCommZero, r.fixRot1Zero,
			r.hullByteD0, r.hullByteDR, r.hullFixD0)
	}
}

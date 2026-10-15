package main

// Section B4: coset trails. Per seed family, the longest run of
// rounds (from the start round) in which the coset maps exactly onto a
// coset of the same dimension, and the longest run in which the hull
// stays below the generic bound min(n, 2^d - 1) that any permutation
// meets for a d-dimensional input; runs cut off by the last round are
// reported separately. Adds the fixed spaces of the column rotations
// (states whose columns repeat with period 1 or 2) as seeds, and two
// crafted tables whose constants are invariant under those rotations,
// as positive controls: there the fixed space must stay invariant for
// every round.

import (
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
	"sync"
)

// fixed space of the rotation by `per` columns: column c equals column
// c mod per in every block.
func symSeed(nbytes, per int) coset {
	var c coset
	for blk := 0; blk < nbytes/16; blk++ {
		for col := 0; col < per; col++ {
			for row := 0; row < 4; row++ {
				for bit := 0; bit < 8; bit++ {
					var v vec
					for cc := col; cc < 4; cc += per {
						pos := 16*blk + 4*cc + row
						v = v.xor(unitByte(pos, 1<<bit))
					}
					c.basis = append(c.basis, v)
				}
			}
		}
	}
	return c
}

func symTable(src *[15][16]byte, per int) [15][16]byte {
	var t [15][16]byte
	for r := 0; r < 15; r++ {
		for c := 0; c < 4; c++ {
			for row := 0; row < 4; row++ {
				t[r][4*c+row] = src[r][4*(c%per)+row]
			}
		}
	}
	return t
}

type famStat struct {
	seeds, exactMax, structMax, cutExact, cutStruct int
	cutExactMax, cutStructMax                       int // longest runs cut by the last round
	exactArg, structArg                             string
	exactIdx, structIdx                             int // job index of the reported seed; ties go to the lowest
}

func runFamily(stats map[string]*famStat, mu *sync.Mutex, fam string, sd seed, f roundFn, rounds, nbytes int, rng *rand.Rand, idx int) {
	c := sd.c
	n := 8 * nbytes
	exact, strct := 0, 0
	exOn, stOn := true, true
	var dims []int
	cutE, cutS := false, false
	for r := sd.r0; r < rounds; r++ {
		din := len(c.basis)
		bound := n
		if din < 63 && (1<<din)-1 < n {
			bound = (1 << din) - 1
		}
		var ok bool
		c, ok = step(c, f, r, nbytes, rng)
		d := len(c.basis)
		dims = append(dims, d)
		if exOn {
			if ok {
				exact++
				if r == rounds-1 {
					cutE = true
				}
			} else {
				exOn = false
			}
		}
		if stOn {
			if d < bound {
				strct++
				if r == rounds-1 {
					cutS = true
				}
			} else {
				stOn = false
			}
		}
		if !exOn && !stOn {
			break
		}
		if d == n {
			break
		}
	}
	mu.Lock()
	defer mu.Unlock()
	st := stats[fam]
	if st == nil {
		st = &famStat{}
		stats[fam] = st
	}
	st.seeds++
	arg := fmt.Sprintf("%s r0=%d dims=%v", sd.name, sd.r0, dims)
	if cutE {
		st.cutExact++
		st.cutExactMax = max(st.cutExactMax, exact)
	} else if exact > st.exactMax || (exact == st.exactMax && exact > 0 && idx < st.exactIdx) {
		st.exactMax, st.exactArg, st.exactIdx = exact, arg, idx
	}
	if cutS {
		st.cutStruct++
		st.cutStructMax = max(st.cutStructMax, strct)
	} else if strct > st.structMax || (strct == st.structMax && strct > 0 && idx < st.structIdx) {
		st.structMax, st.structArg, st.structIdx = strct, arg, idx
	}
}

func coset2Main() {
	width := os.Args[2]
	nbytes, rounds := 32, 10
	if width == "512" {
		nbytes, rounds = 64, 15
	}
	rngT := rand.New(rand.NewPCG(100, 200))
	var zero, rand1 [15][16]byte
	for r := 0; r < 15; r++ {
		for i := 0; i < 16; i++ {
			rand1[r][i] = byte(rngT.Uint32())
		}
	}
	pi, shift := *p2Table("pi"), *p2Table("shift")
	sym1 := symTable(&roundConstantsP1, 1)
	sym2 := symTable(&roundConstantsP1, 2)
	tables := []struct {
		name string
		t    *[15][16]byte
	}{{"P1", &roundConstantsP1}, {"P2 pi", &pi}, {"P2 shift", &shift}, {"random", &rand1},
		{"zero", &zero}, {"control sym1", &sym1}, {"control sym2", &sym2}}
	bases := []int{0, 1}
	if len(os.Args) > 3 && os.Args[3] == "quick" {
		// quick: the two real tables against the symmetric control, zero base only
		tables = []struct {
			name string
			t    *[15][16]byte
		}{{"P1", &roundConstantsP1}, {"P2 pi", &pi}, {"control sym1", &sym1}}
		bases = []int{0}
	}
	lines := lineBases()
	for _, tb := range tables {
		var f roundFn
		if width == "256" {
			f = mk256(tb.t)
		} else {
			f = mk512(tb.t)
		}
		stats := map[string]*famStat{}
		var mu sync.Mutex
		type job struct {
			fam string
			sd  seed
		}
		var jobs []job
		for _, bs := range bases {
			rng := rand.New(rand.NewPCG(1, uint64(2+bs)))
			baseFn := func(r *rand.Rand) vec { return vec{} }
			if bs == 1 {
				baseFn = func(r *rand.Rand) vec {
					var v vec
					for i := 0; i < nbytes/8; i++ {
						v[i] = r.Uint64()
					}
					return v
				}
			}
			for _, sd := range seeds(nbytes, rounds, baseFn, rng, lines) {
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
		}
		for r0 := 0; r0 < rounds; r0++ {
			jobs = append(jobs, job{"column-rotation fixed space (period 1)", seed{"sym1", symSeed(nbytes, 1), r0}})
			jobs = append(jobs, job{"column-rotation fixed space (period 2)", seed{"sym2", symSeed(nbytes, 2), r0}})
		}
		// one generator per job, seeded by its index, so sampled hulls do not
		// depend on how the workers are scheduled
		ch := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < 6; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range ch {
					lr := rand.New(rand.NewPCG(uint64(i), 99))
					runFamily(stats, &mu, jobs[i].fam, jobs[i].sd, f, rounds, nbytes, lr, i)
				}
			}()
		}
		for i := range jobs {
			ch <- i
		}
		close(ch)
		wg.Wait()
		var fams []string
		for k := range stats {
			fams = append(fams, k)
		}
		sort.Strings(fams)
		for _, k := range fams {
			s := stats[k]
			fmt.Printf("Areion-%s | %-12s | %-40s | seeds %6d | exact max %2d (cut by last round: %d, longest %d) [%s] | below generic bound max %2d (cut: %d, longest %d) [%s]\n",
				width, tb.name, k, s.seeds, s.exactMax, s.cutExact, s.cutExactMax, s.exactArg, s.structMax, s.cutStruct, s.cutStructMax, s.structArg)
		}
	}
}

// Command analysis runs the Go side of the P1 / P2 analysis of Areion
// under its two round-constant tables. analysis/run.py drives it; each
// subcommand prints its result to stdout.
//
//	go run ./analysis/go <subcommand> [args]
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

var usage = `subcommands:
  check                          instrumented rounds == library (the test covers
                                 the reference rounds)
  consts                         round-constant tables as JSON (library P1, P2 in both
                                 RC7 forms, and P1 word 7 in the pi form)
  kat                            random input / output lines of the library permutations
  trace <256|512> <shift|pi> <rounds> <n>
                                 oracle activity traces (JSON lines)
  feas                           column feasibility tables of MC(S) ^ Delta (JSON)
  sym | symctl                   symmetries of the constant-free round, and control
  sboxsub                        affine subspaces the S-box maps affinely, cycles
  diag                           exhaustive MixColumns direction check (weak cosets)
  coset2 <256|512> [quick]       weak-coset trails from byte-structured seeds
  zero [shift|pi]                zero-byte frequency of P1_r(x) ^ P2_r(x ^ delta)
  uniform <256|512> <maxrounds> [shift|pi]
                                 per-byte value histograms of the same
  integral <256|512> <maxrounds> [maxorder [shift|pi]]
                                 Lambda-set sums of order 1..maxorder (default 3)
  chain                          exact correlations and probabilities of the S-box
                                 chain of F3 in Areion-512, over every constant byte
  feas-dissolve                  ladder definitions and column feasibility tables (JSON)
  trace-dissolve <256|512> <level> <rounds> <n>
                                 oracle activity traces for ladder level (JSON lines)
  dissolve [r256 r512 [quick]]   parameterized P2^(k) dependence-dissolution spectrum
  check-inv                      instrumented InversePermute == library and round-trip
  trace-inv <256|512> <shift|pi> <rounds> <n>
                                 backward oracle activity traces (JSON lines)
  trace-cross <256|512> <shift|pi> <rounds> <n>
                                 coupled 2r-round cross-composition oracle traces (JSON lines)
  cross [r256 r512 [quick]]      InversePermute & cross-composition C_r(x) delta analysis
The optional shift|pi selects the RC7 form of P2 (default shift, the library's).

AREION_RC7P1=pi switches P1 to the pi form of RC7 for every subcommand
except check, check-inv, kat and consts.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check", "check-inv", "kat", "consts":
	default:
		applyRC7P1()
	}
	switch os.Args[1] {
	case "check":
		check()
	case "consts":
		json.NewEncoder(os.Stdout).Encode(map[string]any{
			"P1": &roundConstantsP1, "P2pi": p2Table("pi"), "P2shift": p2Table("shift"), "P1rc7pi": &rc7P1Pi,
		})
	case "kat":
		katMain()
	case "trace":
		w, _ := strconv.Atoi(os.Args[2])
		r, _ := strconv.Atoi(os.Args[4])
		n, _ := strconv.Atoi(os.Args[5])
		trace(w, os.Args[3], r, n)
	case "feas":
		feasTables()
	case "sym":
		symMain()
	case "symctl":
		symCtl()
	case "sboxsub":
		sboxSub()
	case "diag":
		diagMain()
	case "coset2":
		coset2Main()
	case "zero":
		zeroMain()
	case "uniform":
		uniformMain()
	case "integral":
		integralMain()
	case "chain":
		chainMain()
	case "feas-dissolve":
		feasDissolve()
	case "trace-dissolve":
		w, _ := strconv.Atoi(os.Args[2])
		r, _ := strconv.Atoi(os.Args[4])
		n, _ := strconv.Atoi(os.Args[5])
		traceDissolve(w, os.Args[3], r, n)
	case "dissolve":
		dissolveMain()
	case "check-inv":
		checkInv()
	case "trace-inv":
		w, _ := strconv.Atoi(os.Args[2])
		r, _ := strconv.Atoi(os.Args[4])
		n, _ := strconv.Atoi(os.Args[5])
		traceInv(w, os.Args[3], r, n)
	case "trace-cross":
		w, _ := strconv.Atoi(os.Args[2])
		r, _ := strconv.Atoi(os.Args[4])
		n, _ := strconv.Atoi(os.Args[5])
		traceCross(w, os.Args[3], r, n)
	case "cross":
		crossMain()
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

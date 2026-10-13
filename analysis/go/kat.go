package main

// Prints input / output pairs of the library permutations (P1 and P2,
// through the exported API) as hex, so the Python layer decomposition and
// the AES-NI program can be checked against them.

import (
	"encoding/hex"
	"fmt"
	"math/rand/v2"

	"github.com/everanium/areion"
)

func katMain() {
	rng := rand.New(rand.NewPCG(21, 22))
	for t := 0; t < 4; t++ {
		var s State256
		for i := range s {
			s[i] = byte(rng.Uint32())
		}
		in := s
		areion.Permute256(&s)
		q := in
		areion.Permute256P2(&q)
		fmt.Println("256", hex.EncodeToString(in[:]), hex.EncodeToString(s[:]), hex.EncodeToString(q[:]))
		var s5 State512
		for i := range s5 {
			s5[i] = byte(rng.Uint32())
		}
		in5 := s5
		areion.Permute512(&s5)
		q5 := in5
		areion.Permute512P2(&q5)
		fmt.Println("512", hex.EncodeToString(in5[:]), hex.EncodeToString(s5[:]), hex.EncodeToString(q5[:]))
	}
}

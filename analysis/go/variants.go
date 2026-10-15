package main

import "os"

// RC7 forms. "pi" is the plain pi word; "shift" applies Table 1's
// one-nibble shift. The library uses "shift" for both P1 (as published)
// and P2; the two values below are the only definitions of the
// alternatives.

// rc7P2Pi is P2 word 7 in the pi form (pi word 22 without the shift),
// 0x0f6d6ff383f442392e0b4482a4842004, in little-endian byte order.
var rc7P2Pi = [16]byte{0x04, 0x20, 0x84, 0xa4, 0x82, 0x44, 0x0b, 0x2e, 0x39, 0x42, 0xf4, 0x83, 0xf3, 0x6f, 0x6d, 0x0f}

// p2Table returns the P2 constant table in the given RC7 form: "shift"
// (the library's table) or "pi".
func p2Table(variant string) *[15][16]byte {
	t := roundConstantsP2
	switch variant {
	case "shift":
	case "pi":
		t[7] = rc7P2Pi
	default:
		panic("unknown RC7 form " + variant)
	}
	return &t
}

// rc7P1Pi is P1 word 7 in the pi form (pi word 7 without the published
// shift), 0x0801f2e2858efc16636920d871574e69, in little-endian byte order.
var rc7P1Pi = [16]byte{0x69, 0x4e, 0x57, 0x71, 0xd8, 0x20, 0x69, 0x63, 0x16, 0xfc, 0x8e, 0x85, 0xe2, 0xf2, 0x01, 0x08}

// applyRC7P1 switches P1 to the pi form of RC7 when AREION_RC7P1=pi.
// Subcommands that compare with the library never call it.
func applyRC7P1() {
	switch os.Getenv("AREION_RC7P1") {
	case "", "shift":
	case "pi":
		roundConstantsP1[7] = rc7P1Pi
	default:
		panic("unknown RC7 form for P1: " + os.Getenv("AREION_RC7P1"))
	}
}

// formArg reads an optional RC7 form ("shift" or "pi") from os.Args[i],
// defaulting to "shift". The suffix marks the non-default forms of P2 and
// of P1 (AREION_RC7P1=pi), so output for the library tables keeps one
// format.
func formArg(i int) (t *[15][16]byte, suffix string) {
	form := "shift"
	if len(os.Args) > i {
		form = os.Args[i]
	}
	if form == "pi" {
		suffix = " (P2 pi)"
	}
	if roundConstantsP1[7] == rc7P1Pi {
		suffix += " (P1 pi)"
	}
	return p2Table(form), suffix
}

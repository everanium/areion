package main

import (
	"math/rand/v2"
	"testing"

	"github.com/everanium/areion"
)

// TestReferenceMatchesLibrary pins the copied reference rounds and
// constant tables to the library's exported permutations.
func TestReferenceMatchesLibrary(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for n := 0; n < 200; n++ {
		var s State256
		for i := range s {
			s[i] = byte(rng.Uint32())
		}
		for _, c := range []struct {
			lib func(*State256)
			rc  *[15][16]byte
		}{{areion.Permute256, &roundConstantsP1}, {areion.Permute256P2, &roundConstantsP2}} {
			a, b := s, s
			c.lib(&a)
			areion256PermuteSoftwareRC(&b, c.rc)
			if a != b {
				t.Fatalf("Areion-256 reference differs from the library")
			}
		}
		for _, c := range []struct {
			lib func(*State256)
			rc  *[15][16]byte
		}{{areion.InversePermute256, &roundConstantsP1}, {areion.InversePermute256P2, &roundConstantsP2}} {
			a, b := s, s
			c.lib(&a)
			areion256InversePermuteSoftwareRC(&b, c.rc)
			if a != b {
				t.Fatalf("Areion-256 inverse reference differs from the library")
			}
		}
		var u State512
		for i := range u {
			u[i] = byte(rng.Uint32())
		}
		for _, c := range []struct {
			lib func(*State512)
			rc  *[15][16]byte
		}{{areion.Permute512, &roundConstantsP1}, {areion.Permute512P2, &roundConstantsP2}} {
			a, b := u, u
			c.lib(&a)
			areion512PermuteSoftwareRC(&b, c.rc)
			if a != b {
				t.Fatalf("Areion-512 reference differs from the library")
			}
		}
		for _, c := range []struct {
			lib func(*State512)
			rc  *[15][16]byte
		}{{areion.InversePermute512, &roundConstantsP1}, {areion.InversePermute512P2, &roundConstantsP2}} {
			a, b := u, u
			c.lib(&a)
			areion512InversePermuteSoftwareRC(&b, c.rc)
			if a != b {
				t.Fatalf("Areion-512 inverse reference differs from the library")
			}
		}
	}
}

// TestPiVariant checks that the alternative RC7 form differs from the
// library table in word 7 only.
func TestPiVariant(t *testing.T) {
	pi, sh := p2Table("pi"), p2Table("shift")
	for r := 0; r < 15; r++ {
		if (pi[r] != sh[r]) != (r == 7) {
			t.Fatalf("round %d: unexpected table difference", r)
		}
	}
}

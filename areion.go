// Package areion implements the Areion-256 and Areion-512 cryptographic
// permutations, Davies-Meyer compression, and the SoEM22 PRF construction.
//
// References:
//   - Takanori Isobe, Ryoma Ito, Fukang Liu, Kazuhiko Minematsu, Motoki Nakahashi, Kosei Sakamoto, Rentaro Shiba:
//     "Areion: Highly-Efficient Permutations and Its Applications to Hash Functions for Short Input",
//     IACR Transactions on Cryptographic Hardware and Embedded Systems (TCHES), Volume 2023, Issue 2, pp. 115–154,
//     doi:10.46586/tches.v2023.i2.115-154.
//     Extended version: "Areion: Highly-Efficient Permutations and Its Applications (Extended Version)",
//     IACR ePrint 2023/794. Section, table and appendix numbers in this package refer to the extended version.
//   - Yu Long Chen, Eran Lambooij, Bart Mennink:
//     "How to Build Pseudorandom Functions from Public Random Permutations",
//     CRYPTO 2019, Part I, LNCS vol. 11692, pp. 266–293, doi:10.1007/978-3-030-26948-7_10 / IACR ePrint 2019/554.
//
// The second permutation P2 used by the SoEM22 PRFs is the Areion permutation under a second
// round-constant table (Table 2), proposed by Andrey Kuvshinov and derived by scripts/verify_p2_table.py.
// The SoEM22 bound of Chen, Lambooij and Mennink holds for two independent random permutations;
// treating P1 and P2 as independent is an assumption about this instantiation, not a proven property.
package areion

// State256 represents a 256-bit (32-byte) state for the Areion-256 permutation.
type State256 = [32]byte

// State512 represents a 512-bit (64-byte) state for the Areion-512 permutation.
type State512 = [64]byte

// Block represents a 128-bit (16-byte) AES block.
type Block = [16]byte

// Block4 represents four 128-bit AES blocks (64 bytes total), matching a 512-bit vector register.
type Block4 = [64]byte

// Permute256 applies the 10-round Areion-256 permutation P1 in place.
// Automatically leverages hardware acceleration (AES-NI or ARMv8 Cryptographic
// Extension) when available, or falls back to portable pure Go software.
func Permute256(state *State256) {
	areion256Permute(state)
}

// Permute256P2 applies the 10-round Areion-256 permutation P2 in place using roundConstantsP2.
func Permute256P2(state *State256) {
	areion256PermuteP2(state)
}

// InversePermute256 applies the 10-round inverse Areion-256 permutation P1^{-1} in place.
func InversePermute256(state *State256) {
	areion256InversePermute(state)
}

// Permute512 applies the 15-round Areion-512 permutation P1 in place.
func Permute512(state *State512) {
	areion512Permute(state)
}

// Permute512P2 applies the 15-round Areion-512 permutation P2 in place using roundConstantsP2.
func Permute512P2(state *State512) {
	areion512PermuteP2(state)
}

// InversePermute512 applies the 15-round inverse Areion-512 permutation P1^{-1} in place.
func InversePermute512(state *State512) {
	areion512InversePermute(state)
}

// DM256 computes the Davies-Meyer fixed-input compression/hash of a 32-byte input:
//
//	h = P1(m) ⊕ m
//
// Returns a 32-byte digest: Areion256-DM, Section 4.1.1 of Isobe et al. (ePrint 2023/794),
// Eq. (1) with Areion-256 in place of the Haraka v2 permutation.
func DM256(m *[32]byte) [32]byte {
	state := *m
	Permute256(&state)
	for i := range state {
		state[i] ^= m[i]
	}
	return state
}

// DM512 computes the Davies-Meyer fixed-input compression/hash of a 64-byte input:
//
//	h = Truncate256(P1(m) ⊕ m)
//
// Areion512-DM, Section 4.1.1 of Isobe et al. (ePrint 2023/794), Eqs. (2)–(3) with Areion-512: it applies P1(m) ⊕ m
// and keeps the 32-bit words x2‖x3‖x6‖x7‖x8‖x9‖x12‖x13, that is the four 8-byte slices
// state[8:16] || state[24:32] || state[32:40] || state[48:56].
func DM512(m *[64]byte) [32]byte {
	state := *m
	Permute512(&state)
	for i := range state {
		state[i] ^= m[i]
	}
	var out [32]byte
	copy(out[0:8], state[8:16])
	copy(out[8:16], state[24:32])
	copy(out[16:24], state[32:40])
	copy(out[24:32], state[48:56])
	return out
}

// SoEM256 evaluates the Sum of Even-Mansour (SoEM22) PRF on a 32-byte input with a 64-byte key
// (composed of two secret 32-byte subkeys k1 || k2):
//
//	F(k1, k2, m) = P1(m ⊕ k1) ⊕ P2(m ⊕ k2) ⊕ k1 ⊕ k2
//
// For two independent random permutations, SoEM22 (Chen, Lambooij, Mennink, CRYPTO 2019, Theorem 1)
// provides beyond-birthday-bound (BBB) security up to ~2^(2n/3) queries (≈2^170 for n = 256);
// P1 and P2 are taken to be independent (see the package documentation).
// Two distinct permutations remove the shift symmetry of single-permutation SoEM
// (SoEM1, Section 4.1 of Chen, Lambooij, Mennink).
func SoEM256(key *[64]byte, m *[32]byte) [32]byte {
	return areionSoEM256(key, m)
}

// SoEM512 evaluates the Sum of Even-Mansour (SoEM22) PRF on a 64-byte input with a 128-byte key
// (composed of two secret 64-byte subkeys k1 || k2):
//
//	F(k1, k2, m) = P1(m ⊕ k1) ⊕ P2(m ⊕ k2) ⊕ k1 ⊕ k2
//
// For two independent random permutations, SoEM22 provides beyond-birthday-bound (BBB) security
// up to ~2^(2n/3) queries (≈2^341 for n = 512); P1 and P2 are taken to be independent.
func SoEM512(key *[128]byte, m *[64]byte) [64]byte {
	return areionSoEM512(key, m)
}

// SoEM256x4 evaluates SoEM256 on four independent (key, input) tuples simultaneously.
func SoEM256x4(keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte {
	return areionSoEM256x4(keys, inputs)
}

// SoEM512x4 evaluates SoEM512 on four independent (key, input) tuples simultaneously.
func SoEM512x4(keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte {
	return areionSoEM512x4(keys, inputs)
}

// Permute256x4 evaluates permutation P1 on four 256-bit states in parallel.
func Permute256x4(states *[4][32]byte) {
	areion256Permutex4(states)
}

// Permute512x4 evaluates permutation P1 on four 512-bit states in parallel.
func Permute512x4(states *[4][64]byte) {
	areion512Permutex4(states)
}

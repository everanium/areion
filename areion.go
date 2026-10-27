// Package areion implements the Areion-256 and Areion-512 cryptographic
// permutations, Davies-Meyer compression, the SoEM22 PRF construction, and
// 1-round and 2-round Even-Mansour (`EM`, `EM2`) and Tweakable Even-Mansour
// (`TEM`, `TEM2`) wide-block ciphers.
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
//   - Shimon Even, Yishay Mansour:
//     "A Construction of a Cipher From a Single Pseudorandom Permutation",
//     ASIACRYPT 1991, LNCS vol. 739, pp. 210–224; Journal of Cryptology, 10(3), pp. 151–162 (1997).
//   - Andrey Bogdanov, Lars R. Knudsen, Gregor Leander, Francois-Xavier Standaert, John Steinberger, Elmar Tischhauser:
//     "Key-Alternating Ciphers in a Provable Setting: Encryption Using a Small Number of Public Permutations",
//     EUROCRYPT 2012, LNCS vol. 7237, pp. 45–62.
//   - Benoît Cogliati, Rodolphe Lampe, Yannick Seurin:
//     "Tweaking Even-Mansour Ciphers",
//     CRYPTO 2015, Part I, LNCS vol. 9215, pp. 189–208.
//
// The second permutation P2 used by the SoEM22 PRFs and the EM2, TEM, and TEM2 ciphers is the Areion
// permutation under a second round-constant table (Table 2), proposed by Andrey Kuvshinov and derived
// by scripts/verify_p2_table.py. The ideal-permutation security bounds of SoEM22, EM2, TEM, and TEM2 hold
// for two independent random permutations; treating P1 and P2 as independent is an assumption about this
// instantiation, not a proven property.
package areion

import (
	"errors"
	"runtime"
)

// State256 represents a 256-bit (32-byte) state for the Areion-256 permutation.
type State256 = [32]byte

// State512 represents a 512-bit (64-byte) state for the Areion-512 permutation.
type State512 = [64]byte

// Block represents a 128-bit (16-byte) AES block.
type Block = [16]byte

// Block4 represents four 128-bit AES blocks (64 bytes total), matching a 512-bit vector register.
type Block4 = [64]byte

// Key4 represents four 128-bit AES round keys (64 bytes total) for 4-way parallel round operations.
type Key4 = [64]byte

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

// InversePermute256P2 applies the 10-round inverse Areion-256 permutation P2^{-1} in place.
func InversePermute256P2(state *State256) {
	areion256InversePermuteP2(state)
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

// InversePermute512P2 applies the 15-round inverse Areion-512 permutation P2^{-1} in place.
func InversePermute512P2(state *State512) {
	areion512InversePermuteP2(state)
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
	var out [32]byte
	for i := range state {
		out[i] = state[i] ^ m[i]
	}
	clear(state[:])
	runtime.KeepAlive(&state)
	clobberScratchGPRs()
	return out
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
	clear(state[:])
	runtime.KeepAlive(&state)
	clobberScratchGPRs()
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

// Permute256P2x4 evaluates permutation P2 on four 256-bit states in parallel.
func Permute256P2x4(states *[4][32]byte) {
	areion256PermuteP2x4(states)
}

// Permute512P2x4 evaluates permutation P2 on four 512-bit states in parallel.
func Permute512P2x4(states *[4][64]byte) {
	areion512PermuteP2x4(states)
}

// InversePermute256x4 evaluates inverse permutation P1^{-1} on four 256-bit states in parallel.
func InversePermute256x4(states *[4][32]byte) {
	areion256InversePermutex4(states)
}

// InversePermute512x4 evaluates inverse permutation P1^{-1} on four 512-bit states in parallel.
func InversePermute512x4(states *[4][64]byte) {
	areion512InversePermutex4(states)
}

// InversePermute256P2x4 evaluates inverse permutation P2^{-1} on four 256-bit states in parallel.
func InversePermute256P2x4(states *[4][32]byte) {
	areion256InversePermuteP2x4(states)
}

// InversePermute512P2x4 evaluates inverse permutation P2^{-1} on four 512-bit states in parallel.
func InversePermute512P2x4(states *[4][64]byte) {
	areion512InversePermuteP2x4(states)
}

// Round performs one standard AES encryption round (SubBytes, ShiftRows, MixColumns, AddRoundKey)
// in portable pure Go software.
func Round(block, roundKey *Block) {
	rk := *roundKey
	roundNoKey(block)
	xorBlock(block, block, &rk)
	clear(rk[:])
	runtime.KeepAlive(&rk)
	clobberScratchGPRs()
}

// FinalRound performs one final AES encryption round (SubBytes, ShiftRows, AddRoundKey, no MixColumns)
// in portable pure Go software.
func FinalRound(block, roundKey *Block) {
	rk := *roundKey
	finalRoundNoKey(block)
	xorBlock(block, block, &rk)
	clear(rk[:])
	runtime.KeepAlive(&rk)
	clobberScratchGPRs()
}

// RoundHW performs one standard AES encryption round (SubBytes, ShiftRows, MixColumns, AddRoundKey),
// using hardware acceleration (AES-NI, VEX, or ARMv8 Cryptographic Extension) when available and enabled.
func RoundHW(block, roundKey *Block) {
	aesRoundHW(block, roundKey)
}

// FinalRoundHW performs one final AES encryption round (SubBytes, ShiftRows, AddRoundKey, no MixColumns),
// using hardware acceleration (AES-NI, VEX, or ARMv8 Cryptographic Extension) when available and enabled.
func FinalRoundHW(block, roundKey *Block) {
	aesFinalRoundHW(block, roundKey)
}

// AES128Round performs one standard AES encryption round (SubBytes, ShiftRows, MixColumns, AddRoundKey),
// using hardware acceleration when available and enabled.
func AES128Round(block, roundKey *Block) {
	aesRoundHW(block, roundKey)
}

// AES128FinalRound performs one final AES encryption round (SubBytes, ShiftRows, AddRoundKey, no MixColumns),
// using hardware acceleration when available and enabled.
func AES128FinalRound(block, roundKey *Block) {
	aesFinalRoundHW(block, roundKey)
}

// AES128Round4 performs one standard AES encryption round on four 16-byte blocks in parallel,
// each with its corresponding 16-byte round key in roundKeys, using hardware acceleration when available.
func AES128Round4(blocks, roundKeys *Block4) {
	aesRound4HW(blocks, roundKeys)
}

// AES128FinalRound4 performs one final AES encryption round (no MixColumns) on four 16-byte blocks in parallel,
// each with its corresponding 16-byte round key in roundKeys, using hardware acceleration when available.
func AES128FinalRound4(blocks, roundKeys *Block4) {
	aesFinalRound4HW(blocks, roundKeys)
}

// Round4HW is an alias for AES128Round4.
func Round4HW(blocks, roundKeys *Block4) {
	aesRound4HW(blocks, roundKeys)
}

// FinalRound4HW is an alias for AES128FinalRound4.
func FinalRound4HW(blocks, roundKeys *Block4) {
	aesFinalRound4HW(blocks, roundKeys)
}

// XorBlock sets dst = a ⊕ b on 16-byte blocks.
func XorBlock(dst, a, b *Block) {
	xorBlock(dst, a, b)
}

// XorBlock4 sets dst = a ⊕ b on 64-byte (4-block) vectors.
func XorBlock4(dst, a, b *Block4) {
	xorBlock4(dst, a, b)
}

// ExpandKey128 expands a 16-byte AES-128 key into 11 16-byte round keys (FIPS 197 §5.2).
// Uses the hardware AES S-box when hardware acceleration is enabled.
func ExpandKey128(key *[16]byte, rk *[11][16]byte) {
	expandKey128(key, rk)
}

// AES128EncryptBlock encrypts one 16-byte block under the 11 expanded AES-128 round keys rk.
// dst and src may alias.
func AES128EncryptBlock(rk *[11][16]byte, dst, src *[16]byte) {
	aes128EncryptBlock(rk, dst, src)
}

// AES128Encrypt4Blocks encrypts four 16-byte blocks in parallel under the shared 11 expanded
// AES-128 round keys rk. dst and src may alias.
func AES128Encrypt4Blocks(rk *[11][16]byte, dst, src *[64]byte) {
	aes128Encrypt4Blocks(rk, dst, src)
}

// EMEncrypt256 encrypts a 32-byte block under a 64-byte key = K1 || K2 (K1 = key[0:32], K2 = key[32:64])
// using the 1-round Even-Mansour wide-block cipher over P_{1,256}:
//
//	C = P_{1,256}(M ⊕ K1) ⊕ K2
func EMEncrypt256(key *[64]byte, m *[32]byte) (out [32]byte) {
	areionEMEncrypt256(&out, m, key)
	return out
}

// EMDecrypt256 decrypts a 32-byte ciphertext block under a 64-byte key = K1 || K2 (K1 = key[0:32], K2 = key[32:64])
// using the inverse 1-round Even-Mansour wide-block cipher over P_{1,256}^{-1}:
//
//	M = P_{1,256}^{-1}(C ⊕ K2) ⊕ K1
func EMDecrypt256(key *[64]byte, c *[32]byte) (out [32]byte) {
	areionEMDecrypt256(&out, c, key)
	return out
}

// EMEncrypt512 encrypts a 64-byte block under a 128-byte key = K1 || K2 (K1 = key[0:64], K2 = key[64:128])
// using the 1-round Even-Mansour wide-block cipher over P_{1,512}:
//
//	C = P_{1,512}(M ⊕ K1) ⊕ K2
func EMEncrypt512(key *[128]byte, m *[64]byte) (out [64]byte) {
	areionEMEncrypt512(&out, m, key)
	return out
}

// EMDecrypt512 decrypts a 64-byte ciphertext block under a 128-byte key = K1 || K2 (K1 = key[0:64], K2 = key[64:128])
// using the inverse 1-round Even-Mansour wide-block cipher over P_{1,512}^{-1}:
//
//	M = P_{1,512}^{-1}(C ⊕ K2) ⊕ K1
func EMDecrypt512(key *[128]byte, c *[64]byte) (out [64]byte) {
	areionEMDecrypt512(&out, c, key)
	return out
}

// EMEncrypt256x4 encrypts four independent 32-byte blocks under four 64-byte keys in parallel
// using EMEncrypt256.
func EMEncrypt256x4(keys *[4][64]byte, msgs *[4][32]byte) (out [4][32]byte) {
	areionEMEncrypt256x4(&out, msgs, keys)
	return out
}

// EMDecrypt256x4 decrypts four independent 32-byte ciphertexts under four 64-byte keys in parallel
// using EMDecrypt256.
func EMDecrypt256x4(keys *[4][64]byte, ct *[4][32]byte) (out [4][32]byte) {
	areionEMDecrypt256x4(&out, ct, keys)
	return out
}

// EMEncrypt512x4 encrypts four independent 64-byte blocks under four 128-byte keys in parallel
// using EMEncrypt512.
func EMEncrypt512x4(keys *[4][128]byte, msgs *[4][64]byte) (out [4][64]byte) {
	areionEMEncrypt512x4(&out, msgs, keys)
	return out
}

// EMDecrypt512x4 decrypts four independent 64-byte ciphertexts under four 128-byte keys in parallel
// using EMDecrypt512.
func EMDecrypt512x4(keys *[4][128]byte, ct *[4][64]byte) (out [4][64]byte) {
	areionEMDecrypt512x4(&out, ct, keys)
	return out
}

// EM2Encrypt256 encrypts a 32-byte block under a 64-byte key = K1 || K2 (K1 = key[0:32], K2 = key[32:64])
// using the 2-round independent-permutation Even-Mansour wide-block cipher over (P_{1,256}, P_{2,256})
// with pairwise-independent round keys (K1, K2, K1 ⊕ K2):
//
//	C = P_{2,256}(P_{1,256}(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2
func EM2Encrypt256(key *[64]byte, m *[32]byte) (out [32]byte) {
	areionEM2Encrypt256(&out, m, key)
	return out
}

// EM2Decrypt256 decrypts a 32-byte ciphertext block under a 64-byte key = K1 || K2 (K1 = key[0:32], K2 = key[32:64])
// using the inverse 2-round independent-permutation Even-Mansour wide-block cipher over (P_{2,256}^{-1}, P_{1,256}^{-1}):
//
//	M = P_{1,256}^{-1}(P_{2,256}^{-1}(C ⊕ K1 ⊕ K2) ⊕ K2) ⊕ K1
func EM2Decrypt256(key *[64]byte, c *[32]byte) (out [32]byte) {
	areionEM2Decrypt256(&out, c, key)
	return out
}

// EM2Encrypt512 encrypts a 64-byte block under a 128-byte key = K1 || K2 (K1 = key[0:64], K2 = key[64:128])
// using the 2-round independent-permutation Even-Mansour wide-block cipher over (P_{1,512}, P_{2,512})
// with pairwise-independent round keys (K1, K2, K1 ⊕ K2):
//
//	C = P_{2,512}(P_{1,512}(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2
func EM2Encrypt512(key *[128]byte, m *[64]byte) (out [64]byte) {
	areionEM2Encrypt512(&out, m, key)
	return out
}

// EM2Decrypt512 decrypts a 64-byte ciphertext block under a 128-byte key = K1 || K2 (K1 = key[0:64], K2 = key[64:128])
// using the inverse 2-round independent-permutation Even-Mansour wide-block cipher over (P_{2,512}^{-1}, P_{1,512}^{-1}):
//
//	M = P_{1,512}^{-1}(P_{2,512}^{-1}(C ⊕ K1 ⊕ K2) ⊕ K2) ⊕ K1
func EM2Decrypt512(key *[128]byte, c *[64]byte) (out [64]byte) {
	areionEM2Decrypt512(&out, c, key)
	return out
}

// EM2Encrypt256x4 encrypts four independent 32-byte blocks under four 64-byte keys in parallel
// using EM2Encrypt256.
func EM2Encrypt256x4(keys *[4][64]byte, msgs *[4][32]byte) (out [4][32]byte) {
	areionEM2Encrypt256x4(&out, msgs, keys)
	return out
}

// EM2Decrypt256x4 decrypts four independent 32-byte ciphertexts under four 64-byte keys in parallel
// using EM2Decrypt256.
func EM2Decrypt256x4(keys *[4][64]byte, ct *[4][32]byte) (out [4][32]byte) {
	areionEM2Decrypt256x4(&out, ct, keys)
	return out
}

// EM2Encrypt512x4 encrypts four independent 64-byte blocks under four 128-byte keys in parallel
// using EM2Encrypt512.
func EM2Encrypt512x4(keys *[4][128]byte, msgs *[4][64]byte) (out [4][64]byte) {
	areionEM2Encrypt512x4(&out, msgs, keys)
	return out
}

// EM2Decrypt512x4 decrypts four independent 64-byte ciphertexts under four 128-byte keys in parallel
// using EM2Decrypt512.
func EM2Decrypt512x4(keys *[4][128]byte, ct *[4][64]byte) (out [4][64]byte) {
	areionEM2Decrypt512x4(&out, ct, keys)
	return out
}

// TEMEncrypt256 encrypts a 32-byte block under a 64-byte key = K1 || K2 (K1 = key[0:32], K2 = key[32:64])
// and a 32-byte tweak using the 1-round nonlinear-tweakey Even-Mansour wide-block cipher:
//
//	W = P_{2,256}(T ⊕ K2) ⊕ K1
//	C = P_{1,256}(M ⊕ W) ⊕ W
func TEMEncrypt256(key *[64]byte, tweak *[32]byte, m *[32]byte) (out [32]byte) {
	areionTEMEncrypt256(&out, m, key, tweak)
	return out
}

// TEMDecrypt256 decrypts a 32-byte ciphertext block under a 64-byte key = K1 || K2 (K1 = key[0:32], K2 = key[32:64])
// and a 32-byte tweak using the inverse 1-round nonlinear-tweakey Even-Mansour wide-block cipher:
//
//	W = P_{2,256}(T ⊕ K2) ⊕ K1
//	M = P_{1,256}^{-1}(C ⊕ W) ⊕ W
func TEMDecrypt256(key *[64]byte, tweak *[32]byte, c *[32]byte) (out [32]byte) {
	areionTEMDecrypt256(&out, c, key, tweak)
	return out
}

// TEMEncrypt512 encrypts a 64-byte block under a 128-byte key = K1 || K2 (K1 = key[0:64], K2 = key[64:128])
// and a 64-byte tweak using the 1-round nonlinear-tweakey Even-Mansour wide-block cipher:
//
//	W = P_{2,512}(T ⊕ K2) ⊕ K1
//	C = P_{1,512}(M ⊕ W) ⊕ W
func TEMEncrypt512(key *[128]byte, tweak *[64]byte, m *[64]byte) (out [64]byte) {
	areionTEMEncrypt512(&out, m, key, tweak)
	return out
}

// TEMDecrypt512 decrypts a 64-byte ciphertext block under a 128-byte key = K1 || K2 (K1 = key[0:64], K2 = key[64:128])
// and a 64-byte tweak using the inverse 1-round nonlinear-tweakey Even-Mansour wide-block cipher:
//
//	W = P_{2,512}(T ⊕ K2) ⊕ K1
//	M = P_{1,512}^{-1}(C ⊕ W) ⊕ W
func TEMDecrypt512(key *[128]byte, tweak *[64]byte, c *[64]byte) (out [64]byte) {
	areionTEMDecrypt512(&out, c, key, tweak)
	return out
}

// TEMEncrypt256x4 encrypts four independent 32-byte blocks under four 64-byte keys and four 32-byte tweaks
// in parallel using TEMEncrypt256.
func TEMEncrypt256x4(keys *[4][64]byte, tweaks *[4][32]byte, msgs *[4][32]byte) (out [4][32]byte) {
	areionTEMEncrypt256x4(&out, msgs, keys, tweaks)
	return out
}

// TEMDecrypt256x4 decrypts four independent 32-byte ciphertexts under four 64-byte keys and four 32-byte tweaks
// in parallel using TEMDecrypt256.
func TEMDecrypt256x4(keys *[4][64]byte, tweaks *[4][32]byte, ct *[4][32]byte) (out [4][32]byte) {
	areionTEMDecrypt256x4(&out, ct, keys, tweaks)
	return out
}

// TEMEncrypt512x4 encrypts four independent 64-byte blocks under four 128-byte keys and four 64-byte tweaks
// in parallel using TEMEncrypt512.
func TEMEncrypt512x4(keys *[4][128]byte, tweaks *[4][64]byte, msgs *[4][64]byte) (out [4][64]byte) {
	areionTEMEncrypt512x4(&out, msgs, keys, tweaks)
	return out
}

// TEMDecrypt512x4 decrypts four independent 64-byte ciphertexts under four 128-byte keys and four 64-byte tweaks
// in parallel using TEMDecrypt512.
func TEMDecrypt512x4(keys *[4][128]byte, tweaks *[4][64]byte, ct *[4][64]byte) (out [4][64]byte) {
	areionTEMDecrypt512x4(&out, ct, keys, tweaks)
	return out
}

// TEM2Encrypt256 encrypts a 32-byte block under a 64-byte key = K1 || K2 (K1 = key[0:32], K2 = key[32:64])
// and a 32-byte tweak using the 2-round independent-permutation tweakable Even-Mansour wide-block cipher:
//
//	W1 = P_{1,256}(T ⊕ K1) ⊕ K1,  W2 = P_{2,256}(T ⊕ K2) ⊕ K2
//	C  = P_{2,256}(P_{1,256}(M ⊕ W1) ⊕ W2) ⊕ W1 ⊕ W2
func TEM2Encrypt256(key *[64]byte, tweak *[32]byte, m *[32]byte) (out [32]byte) {
	areionTEM2Encrypt256(&out, m, key, tweak)
	return out
}

// TEM2Decrypt256 decrypts a 32-byte ciphertext block under a 64-byte key = K1 || K2 (K1 = key[0:32], K2 = key[32:64])
// and a 32-byte tweak using the inverse 2-round independent-permutation tweakable Even-Mansour wide-block cipher:
//
//	W1 = P_{1,256}(T ⊕ K1) ⊕ K1,  W2 = P_{2,256}(T ⊕ K2) ⊕ K2
//	M  = P_{1,256}^{-1}(P_{2,256}^{-1}(C ⊕ W1 ⊕ W2) ⊕ W2) ⊕ W1
func TEM2Decrypt256(key *[64]byte, tweak *[32]byte, c *[32]byte) (out [32]byte) {
	areionTEM2Decrypt256(&out, c, key, tweak)
	return out
}

// TEM2Encrypt512 encrypts a 64-byte block under a 128-byte key = K1 || K2 (K1 = key[0:64], K2 = key[64:128])
// and a 64-byte tweak using the 2-round independent-permutation tweakable Even-Mansour wide-block cipher:
//
//	W1 = P_{1,512}(T ⊕ K1) ⊕ K1,  W2 = P_{2,512}(T ⊕ K2) ⊕ K2
//	C  = P_{2,512}(P_{1,512}(M ⊕ W1) ⊕ W2) ⊕ W1 ⊕ W2
func TEM2Encrypt512(key *[128]byte, tweak *[64]byte, m *[64]byte) (out [64]byte) {
	areionTEM2Encrypt512(&out, m, key, tweak)
	return out
}

// TEM2Decrypt512 decrypts a 64-byte ciphertext block under a 128-byte key = K1 || K2 (K1 = key[0:64], K2 = key[64:128])
// and a 64-byte tweak using the inverse 2-round independent-permutation tweakable Even-Mansour wide-block cipher:
//
//	W1 = P_{1,512}(T ⊕ K1) ⊕ K1,  W2 = P_{2,512}(T ⊕ K2) ⊕ K2
//	M  = P_{1,512}^{-1}(P_{2,512}^{-1}(C ⊕ W1 ⊕ W2) ⊕ W2) ⊕ W1
func TEM2Decrypt512(key *[128]byte, tweak *[64]byte, c *[64]byte) (out [64]byte) {
	areionTEM2Decrypt512(&out, c, key, tweak)
	return out
}

// TEM2Encrypt256x4 encrypts four independent 32-byte blocks under four 64-byte keys and four 32-byte tweaks
// in parallel using TEM2Encrypt256.
func TEM2Encrypt256x4(keys *[4][64]byte, tweaks *[4][32]byte, msgs *[4][32]byte) (out [4][32]byte) {
	areionTEM2Encrypt256x4(&out, msgs, keys, tweaks)
	return out
}

// TEM2Decrypt256x4 decrypts four independent 32-byte ciphertexts under four 64-byte keys and four 32-byte tweaks
// in parallel using TEM2Decrypt256.
func TEM2Decrypt256x4(keys *[4][64]byte, tweaks *[4][32]byte, ct *[4][32]byte) (out [4][32]byte) {
	areionTEM2Decrypt256x4(&out, ct, keys, tweaks)
	return out
}

// TEM2Encrypt512x4 encrypts four independent 64-byte blocks under four 128-byte keys and four 64-byte tweaks
// in parallel using TEM2Encrypt512.
func TEM2Encrypt512x4(keys *[4][128]byte, tweaks *[4][64]byte, msgs *[4][64]byte) (out [4][64]byte) {
	areionTEM2Encrypt512x4(&out, msgs, keys, tweaks)
	return out
}

// TEM2Decrypt512x4 decrypts four independent 64-byte ciphertexts under four 128-byte keys and four 64-byte tweaks
// in parallel using TEM2Decrypt512.
func TEM2Decrypt512x4(keys *[4][128]byte, tweaks *[4][64]byte, ct *[4][64]byte) (out [4][64]byte) {
	areionTEM2Decrypt512x4(&out, ct, keys, tweaks)
	return out
}

// Zeroize overwrites all bytes in b with zeros and prevents dead-store
// elimination via runtime.KeepAlive.
func Zeroize(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

var (
	selfTestWantP256 = [32]byte{
		0x28, 0x12, 0xa7, 0x24, 0x65, 0xb2, 0x6e, 0x9f,
		0xca, 0x75, 0x83, 0xf6, 0xe4, 0x12, 0x3a, 0xa1,
		0x49, 0x0e, 0x35, 0xe7, 0xd5, 0x20, 0x3e, 0x4b,
		0xa2, 0xe9, 0x27, 0xb0, 0x48, 0x2f, 0x4d, 0xb8,
	}
	selfTestWantP512 = [64]byte{
		0xb2, 0xad, 0xb0, 0x4f, 0xa9, 0x1f, 0x90, 0x15,
		0x59, 0x36, 0x71, 0x22, 0xcb, 0x3c, 0x96, 0xa9,
		0x78, 0xcf, 0x3e, 0xe4, 0xb7, 0x3c, 0x6a, 0x54,
		0x3f, 0xe6, 0xdc, 0x85, 0x77, 0x91, 0x02, 0xe7,
		0xe3, 0xf5, 0x50, 0x10, 0x16, 0xce, 0xed, 0x1d,
		0xd2, 0xc4, 0x8d, 0x0b, 0xc2, 0x12, 0xfb, 0x07,
		0xad, 0x16, 0x87, 0x94, 0xbd, 0x96, 0xcf, 0xf3,
		0x59, 0x09, 0xcd, 0xd8, 0xe2, 0x27, 0x49, 0x28,
	}
	selfTestWantP256P2 = [32]byte{
		0x94, 0x59, 0xad, 0x09, 0x73, 0x2a, 0x12, 0xdf,
		0x68, 0x63, 0x26, 0xcd, 0xb2, 0x91, 0xbd, 0x02,
		0x12, 0x39, 0xb6, 0xec, 0x01, 0xdf, 0x49, 0xd7,
		0x01, 0x89, 0x02, 0xea, 0x09, 0x47, 0x32, 0x84,
	}
	selfTestWantP512P2 = [64]byte{
		0xea, 0xb2, 0xb6, 0x7d, 0x13, 0xb2, 0x77, 0x25,
		0x1c, 0x1b, 0x37, 0xb2, 0x67, 0xf6, 0xe0, 0x95,
		0xed, 0xe5, 0x03, 0x16, 0xc3, 0x23, 0x46, 0xe2,
		0x7f, 0x92, 0x44, 0xdf, 0x53, 0x1f, 0x91, 0x54,
		0x1d, 0xfe, 0xcd, 0xf5, 0xc6, 0xe4, 0x52, 0x92,
		0xbd, 0x10, 0xb1, 0x2a, 0x07, 0x7e, 0x08, 0x13,
		0x0a, 0xe3, 0x72, 0x6f, 0x1e, 0x23, 0xfd, 0x48,
		0xeb, 0x87, 0xd3, 0x9d, 0xb3, 0x05, 0xee, 0xe8,
	}
	selfTestWantEM256 = [32]byte{
		0xb1, 0x59, 0x0d, 0xe6, 0xb0, 0xee, 0x58, 0x9c,
		0x39, 0xdc, 0x13, 0x01, 0x40, 0xc0, 0xb3, 0x8b,
		0x83, 0x20, 0x60, 0x51, 0x82, 0xe5, 0xf3, 0x7a,
		0x01, 0xe5, 0x10, 0x4c, 0x4a, 0x7b, 0xfe, 0xab,
	}
	selfTestWantEM512 = [64]byte{
		0x77, 0x65, 0x0f, 0xae, 0x67, 0x2e, 0x2b, 0x9d,
		0x12, 0xe5, 0xd4, 0x00, 0x43, 0x83, 0xa1, 0x62,
		0xe4, 0x69, 0x93, 0x48, 0x90, 0x94, 0xad, 0xc4,
		0xa4, 0xce, 0xa1, 0x5a, 0x65, 0x8d, 0x78, 0xa5,
		0x3b, 0x7c, 0xc4, 0x57, 0xf1, 0x08, 0xce, 0x51,
		0xfc, 0x2e, 0xb6, 0xf1, 0x23, 0x10, 0xcf, 0xc3,
		0x87, 0x41, 0xef, 0xb0, 0xb0, 0xda, 0xe5, 0x8f,
		0xe5, 0x4e, 0x96, 0x63, 0x79, 0x29, 0x97, 0xe7,
	}
	selfTestWantEM2256 = [32]byte{
		0x06, 0x1a, 0x5e, 0x87, 0x82, 0x64, 0x7a, 0x6b,
		0xae, 0xcc, 0x87, 0x72, 0x2d, 0xdf, 0xf3, 0xbe,
		0xab, 0x73, 0x1f, 0x41, 0xcc, 0x40, 0x09, 0x1b,
		0xaf, 0xa6, 0x83, 0xce, 0x5f, 0x80, 0xca, 0x78,
	}
	selfTestWantEM2512 = [64]byte{
		0x49, 0x65, 0xbb, 0x05, 0x38, 0x0e, 0x69, 0xa5,
		0xd7, 0x7e, 0x4e, 0xe5, 0xe1, 0xb1, 0x6e, 0xc5,
		0x9d, 0x4b, 0x38, 0xdb, 0xe4, 0x4b, 0xd5, 0xf8,
		0xf6, 0x57, 0xd4, 0x72, 0x3f, 0x0b, 0x0a, 0x0c,
		0xca, 0xe9, 0x21, 0xcf, 0x3a, 0xc6, 0x53, 0xca,
		0x95, 0xe8, 0xbd, 0x3d, 0xbb, 0xbf, 0x3d, 0x88,
		0x83, 0x5c, 0x86, 0x98, 0x37, 0x18, 0x0e, 0x3b,
		0xee, 0xcc, 0xc1, 0xf9, 0xf8, 0x1b, 0xa2, 0xf8,
	}
	selfTestWantTEM256 = [32]byte{
		0xde, 0x63, 0x2e, 0x74, 0x54, 0x19, 0xba, 0x1e,
		0xb0, 0xfb, 0x40, 0x00, 0x14, 0xe4, 0xba, 0x88,
		0x31, 0x48, 0x36, 0x53, 0x2f, 0xcb, 0xe6, 0x91,
		0x1a, 0x61, 0x89, 0x61, 0xd6, 0x19, 0x30, 0x5b,
	}
	selfTestWantTEM512 = [64]byte{
		0x90, 0x59, 0x5f, 0x2a, 0x0b, 0x87, 0xfd, 0xa6,
		0xcc, 0x75, 0x1c, 0x95, 0xdc, 0xed, 0xc8, 0xd6,
		0xf3, 0x9b, 0xc1, 0x83, 0x0b, 0xf2, 0x91, 0x8a,
		0x47, 0x0d, 0x70, 0x1f, 0xf8, 0x1b, 0x7d, 0x35,
		0xe8, 0x67, 0xd4, 0xd8, 0xba, 0x3c, 0x86, 0x36,
		0xb7, 0x4f, 0x82, 0xf3, 0x7f, 0x9b, 0x61, 0xac,
		0x8b, 0x34, 0xab, 0x43, 0x54, 0xd3, 0x49, 0x16,
		0x15, 0x99, 0xcb, 0x36, 0x9d, 0x2e, 0xdb, 0xc3,
	}
	selfTestWantTEM2256 = [32]byte{
		0x74, 0xde, 0xe4, 0x0d, 0x0a, 0xe8, 0x2e, 0x8f,
		0x0d, 0x62, 0x67, 0x5e, 0xad, 0x6c, 0x54, 0xf4,
		0x97, 0x6c, 0x53, 0x96, 0x29, 0xc2, 0x1a, 0xeb,
		0x29, 0xc2, 0xdb, 0x43, 0x16, 0x40, 0xf9, 0x54,
	}
	selfTestWantTEM2512 = [64]byte{
		0x6d, 0x6f, 0x7d, 0x5c, 0x0d, 0xe2, 0xfc, 0x65,
		0x77, 0x9f, 0xc4, 0x79, 0x4e, 0xb3, 0x20, 0x75,
		0x10, 0x7c, 0x70, 0xb4, 0x15, 0xb0, 0x09, 0x37,
		0x43, 0x99, 0x39, 0x25, 0x55, 0x9b, 0x54, 0x3c,
		0x83, 0x72, 0xcf, 0x00, 0x1d, 0x9a, 0xdc, 0x5f,
		0xf4, 0xf4, 0xad, 0x02, 0x67, 0x6c, 0xe6, 0xd3,
		0x90, 0x8e, 0x64, 0xfd, 0xff, 0xcb, 0x8a, 0xec,
		0xcd, 0x3f, 0x51, 0xac, 0x72, 0x9b, 0xb2, 0xe1,
	}
	selfTestWantAES128 = [16]byte{
		0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
		0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
	}
)

// SelfTest executes a FIPS 140-3 Power-On Known-Answer Self-Test (CAST) across the
// active backend tier covering AES-128, Permute256/512, InversePermute256/512, P2 variants,
// DM256/512, SoEM256/512, EM/EM2/TEM/TEM2 (256 and 512), and x4 batch functions.
// It returns nil on success or a non-nil error if any KAT check fails.
func SelfTest() error {
	aesKey := [16]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	aesPT := [16]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	var aesRK [11][16]byte
	var aesCT [16]byte
	ExpandKey128(&aesKey, &aesRK)
	AES128EncryptBlock(&aesRK, &aesCT, &aesPT)
	clear(aesRK[:])
	runtime.KeepAlive(&aesRK)
	Zeroize(aesKey[:])
	Zeroize(aesPT[:])
	if aesCT != selfTestWantAES128 {
		Zeroize(aesCT[:])
		return errors.New("areion: SelfTest AES128EncryptBlock KAT mismatch")
	}
	Zeroize(aesCT[:])

	var zero256, s256 [32]byte
	var zero512, s512 [64]byte

	Permute256(&s256)
	if s256 != selfTestWantP256 {
		return errors.New("areion: SelfTest Permute256 KAT mismatch")
	}
	InversePermute256(&s256)
	if s256 != zero256 {
		return errors.New("areion: SelfTest InversePermute256 KAT mismatch")
	}

	Permute512(&s512)
	if s512 != selfTestWantP512 {
		return errors.New("areion: SelfTest Permute512 KAT mismatch")
	}
	InversePermute512(&s512)
	if s512 != zero512 {
		return errors.New("areion: SelfTest InversePermute512 KAT mismatch")
	}

	Permute256P2(&s256)
	if s256 != selfTestWantP256P2 {
		return errors.New("areion: SelfTest Permute256P2 KAT mismatch")
	}
	InversePermute256P2(&s256)
	if s256 != zero256 {
		return errors.New("areion: SelfTest InversePermute256P2 KAT mismatch")
	}

	Permute512P2(&s512)
	if s512 != selfTestWantP512P2 {
		return errors.New("areion: SelfTest Permute512P2 KAT mismatch")
	}
	InversePermute512P2(&s512)
	if s512 != zero512 {
		return errors.New("areion: SelfTest InversePermute512P2 KAT mismatch")
	}

	if DM256(&zero256) != selfTestWantP256 {
		return errors.New("areion: SelfTest DM256 KAT mismatch")
	}
	var wantDM512 [32]byte
	copy(wantDM512[0:8], selfTestWantP512[8:16])
	copy(wantDM512[8:16], selfTestWantP512[24:32])
	copy(wantDM512[16:24], selfTestWantP512[32:40])
	copy(wantDM512[24:32], selfTestWantP512[48:56])
	if DM512(&zero512) != wantDM512 {
		return errors.New("areion: SelfTest DM512 KAT mismatch")
	}

	var zeroK256 [64]byte
	var zeroK512 [128]byte
	var wantSoEM256 [32]byte
	for i := range wantSoEM256 {
		wantSoEM256[i] = selfTestWantP256[i] ^ selfTestWantP256P2[i]
	}
	if SoEM256(&zeroK256, &zero256) != wantSoEM256 {
		return errors.New("areion: SelfTest SoEM256 KAT mismatch")
	}
	var wantSoEM512 [64]byte
	for i := range wantSoEM512 {
		wantSoEM512[i] = selfTestWantP512[i] ^ selfTestWantP512P2[i]
	}
	if SoEM512(&zeroK512, &zero512) != wantSoEM512 {
		return errors.New("areion: SelfTest SoEM512 KAT mismatch")
	}

	var k256 [64]byte
	var t256, m256 [32]byte
	var k512 [128]byte
	var t512, m512 [64]byte
	for i := range k256 {
		k256[i] = byte(i)
	}
	for i := range t256 {
		t256[i] = byte(0x80 + i)
		m256[i] = byte(0x40 + i)
	}
	for i := range k512 {
		k512[i] = byte(i)
	}
	for i := range t512 {
		t512[i] = byte(0x80 + i)
		m512[i] = byte(0x40 + i)
	}
	defer func() {
		Zeroize(k256[:])
		Zeroize(t256[:])
		Zeroize(m256[:])
		Zeroize(k512[:])
		Zeroize(t512[:])
		Zeroize(m512[:])
	}()

	c256 := EMEncrypt256(&k256, &m256)
	if c256 != selfTestWantEM256 || EMDecrypt256(&k256, &c256) != m256 {
		return errors.New("areion: SelfTest EM256 KAT mismatch")
	}
	c512 := EMEncrypt512(&k512, &m512)
	if c512 != selfTestWantEM512 || EMDecrypt512(&k512, &c512) != m512 {
		return errors.New("areion: SelfTest EM512 KAT mismatch")
	}

	c256 = EM2Encrypt256(&k256, &m256)
	if c256 != selfTestWantEM2256 || EM2Decrypt256(&k256, &c256) != m256 {
		return errors.New("areion: SelfTest EM2-256 KAT mismatch")
	}
	c512 = EM2Encrypt512(&k512, &m512)
	if c512 != selfTestWantEM2512 || EM2Decrypt512(&k512, &c512) != m512 {
		return errors.New("areion: SelfTest EM2-512 KAT mismatch")
	}

	c256 = TEMEncrypt256(&k256, &t256, &m256)
	if c256 != selfTestWantTEM256 || TEMDecrypt256(&k256, &t256, &c256) != m256 {
		return errors.New("areion: SelfTest TEM-256 KAT mismatch")
	}
	c512 = TEMEncrypt512(&k512, &t512, &m512)
	if c512 != selfTestWantTEM512 || TEMDecrypt512(&k512, &t512, &c512) != m512 {
		return errors.New("areion: SelfTest TEM-512 KAT mismatch")
	}

	c256 = TEM2Encrypt256(&k256, &t256, &m256)
	if c256 != selfTestWantTEM2256 || TEM2Decrypt256(&k256, &t256, &c256) != m256 {
		return errors.New("areion: SelfTest TEM2-256 KAT mismatch")
	}
	c512 = TEM2Encrypt512(&k512, &t512, &m512)
	if c512 != selfTestWantTEM2512 || TEM2Decrypt512(&k512, &t512, &c512) != m512 {
		return errors.New("areion: SelfTest TEM2-512 KAT mismatch")
	}

	var b256 [4][32]byte
	Permute256x4(&b256)
	for lane := 0; lane < 4; lane++ {
		if b256[lane] != selfTestWantP256 {
			return errors.New("areion: SelfTest Permute256x4 KAT mismatch")
		}
	}
	InversePermute256x4(&b256)
	for lane := 0; lane < 4; lane++ {
		if b256[lane] != zero256 {
			return errors.New("areion: SelfTest InversePermute256x4 KAT mismatch")
		}
	}

	Permute256P2x4(&b256)
	for lane := 0; lane < 4; lane++ {
		if b256[lane] != selfTestWantP256P2 {
			return errors.New("areion: SelfTest Permute256P2x4 KAT mismatch")
		}
	}
	InversePermute256P2x4(&b256)
	for lane := 0; lane < 4; lane++ {
		if b256[lane] != zero256 {
			return errors.New("areion: SelfTest InversePermute256P2x4 KAT mismatch")
		}
	}

	var b512 [4][64]byte
	Permute512x4(&b512)
	for lane := 0; lane < 4; lane++ {
		if b512[lane] != selfTestWantP512 {
			return errors.New("areion: SelfTest Permute512x4 KAT mismatch")
		}
	}
	InversePermute512x4(&b512)
	for lane := 0; lane < 4; lane++ {
		if b512[lane] != zero512 {
			return errors.New("areion: SelfTest InversePermute512x4 KAT mismatch")
		}
	}

	Permute512P2x4(&b512)
	for lane := 0; lane < 4; lane++ {
		if b512[lane] != selfTestWantP512P2 {
			return errors.New("areion: SelfTest Permute512P2x4 KAT mismatch")
		}
	}
	InversePermute512P2x4(&b512)
	for lane := 0; lane < 4; lane++ {
		if b512[lane] != zero512 {
			return errors.New("areion: SelfTest InversePermute512P2x4 KAT mismatch")
		}
	}

	var k256x4 [4][64]byte
	var t256x4, m256x4 [4][32]byte
	var k512x4 [4][128]byte
	var t512x4, m512x4 [4][64]byte
	soem256x4 := SoEM256x4(&k256x4, &m256x4)
	soem512x4 := SoEM512x4(&k512x4, &m512x4)
	for lane := 0; lane < 4; lane++ {
		if soem256x4[lane] != wantSoEM256 {
			return errors.New("areion: SelfTest SoEM256x4 KAT mismatch")
		}
		if soem512x4[lane] != wantSoEM512 {
			return errors.New("areion: SelfTest SoEM512x4 KAT mismatch")
		}
		k256x4[lane] = k256
		t256x4[lane] = t256
		m256x4[lane] = m256
		k512x4[lane] = k512
		t512x4[lane] = t512
		m512x4[lane] = m512
	}
	defer func() {
		for lane := 0; lane < 4; lane++ {
			Zeroize(k256x4[lane][:])
			Zeroize(t256x4[lane][:])
			Zeroize(m256x4[lane][:])
			Zeroize(k512x4[lane][:])
			Zeroize(t512x4[lane][:])
			Zeroize(m512x4[lane][:])
		}
	}()

	wantSoEM256Seq := SoEM256(&k256, &m256)
	wantSoEM512Seq := SoEM512(&k512, &m512)
	soem256x4 = SoEM256x4(&k256x4, &m256x4)
	soem512x4 = SoEM512x4(&k512x4, &m512x4)
	for lane := 0; lane < 4; lane++ {
		if soem256x4[lane] != wantSoEM256Seq {
			return errors.New("areion: SelfTest SoEM256x4 sequential KAT mismatch")
		}
		if soem512x4[lane] != wantSoEM512Seq {
			return errors.New("areion: SelfTest SoEM512x4 sequential KAT mismatch")
		}
	}

	ct256x4 := EMEncrypt256x4(&k256x4, &m256x4)
	pt256x4 := EMDecrypt256x4(&k256x4, &ct256x4)
	ct512x4 := EMEncrypt512x4(&k512x4, &m512x4)
	pt512x4 := EMDecrypt512x4(&k512x4, &ct512x4)
	for lane := 0; lane < 4; lane++ {
		if ct256x4[lane] != selfTestWantEM256 || pt256x4[lane] != m256 {
			return errors.New("areion: SelfTest EM256x4 KAT mismatch")
		}
		if ct512x4[lane] != selfTestWantEM512 || pt512x4[lane] != m512 {
			return errors.New("areion: SelfTest EM512x4 KAT mismatch")
		}
	}

	ct256x4 = EM2Encrypt256x4(&k256x4, &m256x4)
	pt256x4 = EM2Decrypt256x4(&k256x4, &ct256x4)
	ct512x4 = EM2Encrypt512x4(&k512x4, &m512x4)
	pt512x4 = EM2Decrypt512x4(&k512x4, &ct512x4)
	for lane := 0; lane < 4; lane++ {
		if ct256x4[lane] != selfTestWantEM2256 || pt256x4[lane] != m256 {
			return errors.New("areion: SelfTest EM2-256x4 KAT mismatch")
		}
		if ct512x4[lane] != selfTestWantEM2512 || pt512x4[lane] != m512 {
			return errors.New("areion: SelfTest EM2-512x4 KAT mismatch")
		}
	}

	ct256x4 = TEMEncrypt256x4(&k256x4, &t256x4, &m256x4)
	pt256x4 = TEMDecrypt256x4(&k256x4, &t256x4, &ct256x4)
	ct512x4 = TEMEncrypt512x4(&k512x4, &t512x4, &m512x4)
	pt512x4 = TEMDecrypt512x4(&k512x4, &t512x4, &ct512x4)
	for lane := 0; lane < 4; lane++ {
		if ct256x4[lane] != selfTestWantTEM256 || pt256x4[lane] != m256 {
			return errors.New("areion: SelfTest TEM-256x4 KAT mismatch")
		}
		if ct512x4[lane] != selfTestWantTEM512 || pt512x4[lane] != m512 {
			return errors.New("areion: SelfTest TEM-512x4 KAT mismatch")
		}
	}

	ct256x4 = TEM2Encrypt256x4(&k256x4, &t256x4, &m256x4)
	pt256x4 = TEM2Decrypt256x4(&k256x4, &t256x4, &ct256x4)
	ct512x4 = TEM2Encrypt512x4(&k512x4, &t512x4, &m512x4)
	pt512x4 = TEM2Decrypt512x4(&k512x4, &t512x4, &ct512x4)
	for lane := 0; lane < 4; lane++ {
		if ct256x4[lane] != selfTestWantTEM2256 || pt256x4[lane] != m256 {
			return errors.New("areion: SelfTest TEM2-256x4 KAT mismatch")
		}
		if ct512x4[lane] != selfTestWantTEM2512 || pt512x4[lane] != m512 {
			return errors.New("areion: SelfTest TEM2-512x4 KAT mismatch")
		}
	}

	return nil
}

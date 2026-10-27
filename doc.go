// Package areion implements the Areion-256 and Areion-512 cryptographic
// permutations, Davies-Meyer short-input compression (DM256, DM512),
// beyond-birthday-bound Sum of Even-Mansour pseudorandom functions (SoEM256,
// SoEM512), and 1-round / 2-round Even-Mansour (EM, EM2) and Tweakable
// Even-Mansour (TEM, TEM2) invertible wide-block ciphers.
//
// All primitives execute in constant time with respect to secret inputs and
// scrub temporary stack buffers, SIMD vector registers, and scratch
// general-purpose registers before returning.
//
// # Cryptographic Constructions
//
// Let P1 denote the standard Areion permutation (Table 1 round constants,
// fractional part of π words 0..14) and P2 denote the domain-separated second
// permutation (Table 2 round constants, fractional part of π words 15..29).
// For width n ∈ {256, 512} bits (32 or 64 bytes), a 2n-bit key is partitioned
// as K = K1 || K2 with |K1| = |K2| = n:
//
//	Permutations (10 rounds for n = 256, 15 rounds for n = 512):
//	  P1, P1⁻¹, P2, P2⁻¹  (single-block and 4-way *x4 batch)
//
//	Davies-Meyer Compression (DM256, DM512):
//	  DM256(M) = P1(M) ⊕ M
//	  DM512(M) = Trunc256(P1(M) ⊕ M)   (32-bit words x2 || x3 || x6 || x7 || x8 || x9 || x12 || x13, bytes [8:16] || [24:32] || [32:40] || [48:56])
//
//	Sum of Even-Mansour PRF (SoEM256, SoEM512, SoEM256x4, SoEM512x4):
//	  SoEM(K1 || K2, M) = P1(M ⊕ K1) ⊕ P2(M ⊕ K2) ⊕ K1 ⊕ K2
//
//	1-Round Even-Mansour Cipher (EMEncrypt256/512, EMDecrypt256/512, *x4):
//	  C = P1(M ⊕ K1) ⊕ K2
//	  M = P1⁻¹(C ⊕ K2) ⊕ K1
//
//	2-Round Even-Mansour Cipher (EM2Encrypt256/512, EM2Decrypt256/512, *x4):
//	  C = P2(P1(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2
//	  M = P1⁻¹(P2⁻¹(C ⊕ K1 ⊕ K2) ⊕ K2) ⊕ K1
//
//	1-Round Tweakable Even-Mansour Cipher (TEMEncrypt256/512, TEMDecrypt256/512, *x4):
//	  W = P2(T ⊕ K2) ⊕ K1
//	  C = P1(M ⊕ W) ⊕ W
//	  M = P1⁻¹(C ⊕ W) ⊕ W
//
//	2-Round Tweakable Even-Mansour Cipher (TEM2Encrypt256/512, TEM2Decrypt256/512, *x4):
//	  W1 = P1(T ⊕ K1) ⊕ K1,   W2 = P2(T ⊕ K2) ⊕ K2
//	  C  = P2(P1(M ⊕ W1) ⊕ W2) ⊕ W1 ⊕ W2
//	  M  = P1⁻¹(P2⁻¹(C ⊕ W1 ⊕ W2) ⊕ W2) ⊕ W1
//
// # Hardware Acceleration and Runtime Dispatch
//
// At package initialization, the highest supported instruction-set tier is
// selected automatically and verified with a FIPS 140-3 Known-Answer Self-Test
// ([SelfTest]):
//
//   - x86-64 (amd64): [TierAVX512] ("avx512"), [TierVAESAVX2] ("vaesavx2"),
//     [TierVEX] ("vex"), [TierAESNI] ("aesni"), or [TierPureGo] ("purego").
//   - ARM64 (arm64): [TierARMCrypto] ("arm64") or [TierPureGo] ("purego").
//   - Other architectures: constant-time 64-bit bitsliced [TierPureGo] ("purego").
//
// Use [Tier], [TierCode], [SetTier], or the AREION_FORCE_TIER environment
// variable to inspect or override the active tier at runtime.
//
// # References
//
//   - Takanori Isobe, Ryoma Ito, Fukang Liu, Kazuhiko Minematsu, Motoki Nakahashi,
//     Kosei Sakamoto, Rentaro Shiba: "Areion: Highly-Efficient Permutations and Its
//     Applications to Hash Functions for Short Input", IACR TCHES 2023(2), pp. 115–154,
//     doi:10.46586/tches.v2023.i2.115-154 (Extended version: IACR ePrint 2023/794).
//   - Yu Long Chen, Eran Lambooij, Bart Mennink: "How to Build Pseudorandom
//     Functions from Public Random Permutations", CRYPTO 2019, Part I, LNCS 11692,
//     pp. 266–293, doi:10.1007/978-3-030-26948-7_10 (IACR ePrint 2019/554).
//   - Shimon Even, Yishay Mansour: "A Construction of a Cipher From a Single
//     Pseudorandom Permutation", Journal of Cryptology 10(3), pp. 151–162 (1997).
//   - Andrey Bogdanov, Lars R. Knudsen, Gregor Leander, Francois-Xavier Standaert,
//     John Steinberger, Elmar Tischhauser: "Key-Alternating Ciphers in a Provable
//     Setting: Encryption Using a Small Number of Public Permutations", EUROCRYPT
//     2012, LNCS 7237, pp. 45–62.
//   - Benoît Cogliati, Rodolphe Lampe, Yannick Seurin: "Tweaking Even-Mansour
//     Ciphers", CRYPTO 2015, Part I, LNCS 9215, pp. 189–208.
package areion

//go:build amd64 && !purego

package areion

import "unsafe"

//go:noescape
func areion256PermuteRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion512PermuteRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areion256InversePermuteAsm(state *State256)

//go:noescape
func areion512InversePermuteAsm(state *State512)

//go:noescape
func areion256Permutex4RC(x0, x1 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4RC(x0, x1, x2, x3 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion256Permutex4Avx2RC(x0, x1 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4Avx2RC(x0, x1, x2, x3 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion256Permutex4AesNiRC(x0, x1 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4AesNiRC(x0, x1, x2, x3 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion256SoEMPermutex4Interleaved(s1b0, s1b1, s2b0, s2b1 *Block4)

//go:noescape
func areion512SoEMPermutex4Interleaved(a1, b1, c1, d1, a2, b2, c2, d2 *Block4)

//go:noescape
func areion256SoEMPermutex4AesNi(s1b0, s1b1, s2b0, s2b1 *Block4)

//go:noescape
func areion512SoEMPermutex4AesNi(a1, b1, c1, d1, a2, b2, c2, d2 *Block4)

func areion256Permute(state *State256) {
	if hasAESNI && TierCode() != TierPureGo {
		areion256PermuteRCAsm(state, &roundConstantsP1)
		return
	}
	areion256PermuteSoftwareRC(state, &roundConstantsP1)
}

func areion256PermuteP2(state *State256) {
	if hasAESNI && TierCode() != TierPureGo {
		areion256PermuteRCAsm(state, &roundConstantsP2)
		return
	}
	areion256PermuteSoftwareRC(state, &roundConstantsP2)
}

func areion256InversePermute(state *State256) {
	if hasAESNI && TierCode() != TierPureGo {
		areion256InversePermuteAsm(state)
		return
	}
	areion256InversePermuteSoftware(state)
}

func areion512Permute(state *State512) {
	if hasAESNI && TierCode() != TierPureGo {
		areion512PermuteRCAsm(state, &roundConstantsP1)
		return
	}
	areion512PermuteSoftwareRC(state, &roundConstantsP1)
}

func areion512PermuteP2(state *State512) {
	if hasAESNI && TierCode() != TierPureGo {
		areion512PermuteRCAsm(state, &roundConstantsP2)
		return
	}
	areion512PermuteSoftwareRC(state, &roundConstantsP2)
}

func areion512InversePermute(state *State512) {
	if hasAESNI && TierCode() != TierPureGo {
		areion512InversePermuteAsm(state)
		return
	}
	areion512InversePermuteSoftware(state)
}

func areionSoEM256(key *[64]byte, m *[32]byte) [32]byte {
	if !hasAESNI || TierCode() == TierPureGo {
		return soem256Software(key, m)
	}
	var state1, state2 State256
	for i := 0; i < 32; i++ {
		state1[i] = m[i] ^ key[i]
		state2[i] = m[i] ^ key[32+i]
	}
	areion256PermuteRCAsm(&state1, &roundConstantsP1)
	areion256PermuteRCAsm(&state2, &roundConstantsP2)
	for i := 0; i < 32; i++ {
		state1[i] ^= state2[i] ^ key[i] ^ key[32+i]
	}
	return state1
}

func areionSoEM512(key *[128]byte, m *[64]byte) [64]byte {
	if !hasAESNI || TierCode() == TierPureGo {
		return soem512Software(key, m)
	}
	var state1, state2 State512
	for i := 0; i < 64; i++ {
		state1[i] = m[i] ^ key[i]
		state2[i] = m[i] ^ key[64+i]
	}
	areion512PermuteRCAsm(&state1, &roundConstantsP1)
	areion512PermuteRCAsm(&state2, &roundConstantsP2)
	for i := 0; i < 64; i++ {
		state1[i] ^= state2[i] ^ key[i] ^ key[64+i]
	}
	return state1
}

func areion256Permutex4(states *[4][32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		for i := 0; i < 4; i++ {
			areion256PermuteSoftwareRC(&states[i], &roundConstantsP1)
		}
		return
	}
	b0, b1 := pack256x4SoA(states)
	if hasAVX512 && hasVAESAVX2 && tier >= TierAVX512 {
		areion256Permutex4RC(&b0, &b1, &areionRC4x)
	} else if hasVAESAVX2 && tier >= TierVAESAVX2 {
		areion256Permutex4Avx2RC(&b0, &b1, &areionRC4x)
	} else {
		areion256Permutex4AesNiRC(&b0, &b1, &areionRC4x)
	}
	unpack256x4SoA(&b0, &b1, states)
}

func areion512Permutex4(states *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		for i := 0; i < 4; i++ {
			areion512PermuteSoftwareRC(&states[i], &roundConstantsP1)
		}
		return
	}
	b0, b1, b2, b3 := pack512x4SoA(states)
	if hasAVX512 && hasVAESAVX2 && tier >= TierAVX512 {
		areion512Permutex4RC(&b0, &b1, &b2, &b3, &areionRC4x)
	} else if hasVAESAVX2 && tier >= TierVAESAVX2 {
		areion512Permutex4Avx2RC(&b0, &b1, &b2, &b3, &areionRC4x)
	} else {
		areion512Permutex4AesNiRC(&b0, &b1, &b2, &b3, &areionRC4x)
	}
	unpack512x4SoA(&b0, &b1, &b2, &b3, states)
}

func areionSoEM256x4(keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		var out [4][32]byte
		for i := 0; i < 4; i++ {
			out[i] = soem256Software(&keys[i], &inputs[i])
		}
		return out
	}

	keysU64 := (*[4][8]uint64)(unsafe.Pointer(keys))
	inputsU64 := (*[4][4]uint64)(unsafe.Pointer(inputs))

	var s1b0, s1b1, s2b0, s2b1 Block4
	for lane := 0; lane < 4; lane++ {
		s1b0U64 := (*[2]uint64)(unsafe.Pointer(&s1b0[lane*16]))
		s1b1U64 := (*[2]uint64)(unsafe.Pointer(&s1b1[lane*16]))
		s2b0U64 := (*[2]uint64)(unsafe.Pointer(&s2b0[lane*16]))
		s2b1U64 := (*[2]uint64)(unsafe.Pointer(&s2b1[lane*16]))

		s1b0U64[0] = inputsU64[lane][0] ^ keysU64[lane][0]
		s1b0U64[1] = inputsU64[lane][1] ^ keysU64[lane][1]
		s1b1U64[0] = inputsU64[lane][2] ^ keysU64[lane][2]
		s1b1U64[1] = inputsU64[lane][3] ^ keysU64[lane][3]

		s2b0U64[0] = inputsU64[lane][0] ^ keysU64[lane][4]
		s2b0U64[1] = inputsU64[lane][1] ^ keysU64[lane][5]
		s2b1U64[0] = inputsU64[lane][2] ^ keysU64[lane][6]
		s2b1U64[1] = inputsU64[lane][3] ^ keysU64[lane][7]
	}

	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256SoEMPermutex4Interleaved(&s1b0, &s1b1, &s2b0, &s2b1)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256Permutex4Avx2RC(&s1b0, &s1b1, &areionRC4x)
		areion256Permutex4Avx2RC(&s2b0, &s2b1, &areionRC4x2)
		for i := 0; i < 64; i++ {
			s1b0[i] ^= s2b0[i]
			s1b1[i] ^= s2b1[i]
		}
	default:
		areion256SoEMPermutex4AesNi(&s1b0, &s1b1, &s2b0, &s2b1)
	}

	var out [4][32]byte
	for lane := 0; lane < 4; lane++ {
		s1b0U64 := (*[2]uint64)(unsafe.Pointer(&s1b0[lane*16]))
		s1b1U64 := (*[2]uint64)(unsafe.Pointer(&s1b1[lane*16]))
		outU64 := (*[4]uint64)(unsafe.Pointer(&out[lane]))
		k := &keysU64[lane]

		outU64[0] = s1b0U64[0] ^ k[0] ^ k[4]
		outU64[1] = s1b0U64[1] ^ k[1] ^ k[5]
		outU64[2] = s1b1U64[0] ^ k[2] ^ k[6]
		outU64[3] = s1b1U64[1] ^ k[3] ^ k[7]
	}
	return out
}

func areionSoEM512x4(keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		var out [4][64]byte
		for i := 0; i < 4; i++ {
			out[i] = soem512Software(&keys[i], &inputs[i])
		}
		return out
	}

	keysU64 := (*[4][16]uint64)(unsafe.Pointer(keys))
	inputsU64 := (*[4][8]uint64)(unsafe.Pointer(inputs))

	var a1, b1, c1, d1, a2, b2, c2, d2 Block4
	for lane := 0; lane < 4; lane++ {
		a1U64 := (*[2]uint64)(unsafe.Pointer(&a1[lane*16]))
		b1U64 := (*[2]uint64)(unsafe.Pointer(&b1[lane*16]))
		c1U64 := (*[2]uint64)(unsafe.Pointer(&c1[lane*16]))
		d1U64 := (*[2]uint64)(unsafe.Pointer(&d1[lane*16]))

		a2U64 := (*[2]uint64)(unsafe.Pointer(&a2[lane*16]))
		b2U64 := (*[2]uint64)(unsafe.Pointer(&b2[lane*16]))
		c2U64 := (*[2]uint64)(unsafe.Pointer(&c2[lane*16]))
		d2U64 := (*[2]uint64)(unsafe.Pointer(&d2[lane*16]))

		a1U64[0] = inputsU64[lane][0] ^ keysU64[lane][0]
		a1U64[1] = inputsU64[lane][1] ^ keysU64[lane][1]
		b1U64[0] = inputsU64[lane][2] ^ keysU64[lane][2]
		b1U64[1] = inputsU64[lane][3] ^ keysU64[lane][3]
		c1U64[0] = inputsU64[lane][4] ^ keysU64[lane][4]
		c1U64[1] = inputsU64[lane][5] ^ keysU64[lane][5]
		d1U64[0] = inputsU64[lane][6] ^ keysU64[lane][6]
		d1U64[1] = inputsU64[lane][7] ^ keysU64[lane][7]

		a2U64[0] = inputsU64[lane][0] ^ keysU64[lane][8]
		a2U64[1] = inputsU64[lane][1] ^ keysU64[lane][9]
		b2U64[0] = inputsU64[lane][2] ^ keysU64[lane][10]
		b2U64[1] = inputsU64[lane][3] ^ keysU64[lane][11]
		c2U64[0] = inputsU64[lane][4] ^ keysU64[lane][12]
		c2U64[1] = inputsU64[lane][5] ^ keysU64[lane][13]
		d2U64[0] = inputsU64[lane][6] ^ keysU64[lane][14]
		d2U64[1] = inputsU64[lane][7] ^ keysU64[lane][15]
	}

	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512SoEMPermutex4Interleaved(&a1, &b1, &c1, &d1, &a2, &b2, &c2, &d2)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512Permutex4Avx2RC(&a1, &b1, &c1, &d1, &areionRC4x)
		areion512Permutex4Avx2RC(&a2, &b2, &c2, &d2, &areionRC4x2)
		for i := 0; i < 64; i++ {
			a1[i] ^= a2[i]
			b1[i] ^= b2[i]
			c1[i] ^= c2[i]
			d1[i] ^= d2[i]
		}
	default:
		areion512SoEMPermutex4AesNi(&a1, &b1, &c1, &d1, &a2, &b2, &c2, &d2)
	}

	var out [4][64]byte
	for lane := 0; lane < 4; lane++ {
		a1U64 := (*[2]uint64)(unsafe.Pointer(&a1[lane*16]))
		b1U64 := (*[2]uint64)(unsafe.Pointer(&b1[lane*16]))
		c1U64 := (*[2]uint64)(unsafe.Pointer(&c1[lane*16]))
		d1U64 := (*[2]uint64)(unsafe.Pointer(&d1[lane*16]))
		outU64 := (*[8]uint64)(unsafe.Pointer(&out[lane]))
		k := &keysU64[lane]

		outU64[0] = a1U64[0] ^ k[0] ^ k[8]
		outU64[1] = a1U64[1] ^ k[1] ^ k[9]
		outU64[2] = b1U64[0] ^ k[2] ^ k[10]
		outU64[3] = b1U64[1] ^ k[3] ^ k[11]
		outU64[4] = c1U64[0] ^ k[4] ^ k[12]
		outU64[5] = c1U64[1] ^ k[5] ^ k[13]
		outU64[6] = d1U64[0] ^ k[6] ^ k[14]
		outU64[7] = d1U64[1] ^ k[7] ^ k[15]
	}
	return out
}

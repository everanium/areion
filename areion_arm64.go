//go:build arm64 && !purego

package areion

//go:noescape
func areion256PermuteRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion512PermuteRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areion256InversePermuteRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion512InversePermuteRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areion256Permutex4RC(x0, x1 *Block4, rc *[15][16]byte)

//go:noescape
func areion512Permutex4RC(x0, x1, x2, x3 *Block4, rc *[15][16]byte)

func areion256Permute(state *State256) {
	if hasARMCrypto && TierCode() != TierPureGo {
		areion256PermuteRCAsm(state, &roundConstantsP1)
		return
	}
	areion256PermuteSoftwareRC(state, &roundConstantsP1)
}

func areion256PermuteP2(state *State256) {
	if hasARMCrypto && TierCode() != TierPureGo {
		areion256PermuteRCAsm(state, &roundConstantsP2)
		return
	}
	areion256PermuteSoftwareRC(state, &roundConstantsP2)
}

func areion256InversePermute(state *State256) {
	areion256InversePermuteRC(state, &roundConstantsP1)
}

func areion256InversePermuteP2(state *State256) {
	areion256InversePermuteRC(state, &roundConstantsP2)
}

func areion256InversePermuteRC(state *State256, rc *[15][16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		areion256InversePermuteRCAsm(state, rc)
		return
	}
	areion256InversePermuteSoftwareRC(state, rc)
}

func areion512Permute(state *State512) {
	if hasARMCrypto && TierCode() != TierPureGo {
		areion512PermuteRCAsm(state, &roundConstantsP1)
		return
	}
	areion512PermuteSoftwareRC(state, &roundConstantsP1)
}

func areion512PermuteP2(state *State512) {
	if hasARMCrypto && TierCode() != TierPureGo {
		areion512PermuteRCAsm(state, &roundConstantsP2)
		return
	}
	areion512PermuteSoftwareRC(state, &roundConstantsP2)
}

func areion512InversePermute(state *State512) {
	areion512InversePermuteRC(state, &roundConstantsP1)
}

func areion512InversePermuteP2(state *State512) {
	areion512InversePermuteRC(state, &roundConstantsP2)
}

func areion512InversePermuteRC(state *State512, rc *[15][16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		areion512InversePermuteRCAsm(state, rc)
		return
	}
	areion512InversePermuteSoftwareRC(state, rc)
}

func areionSoEM256(key *[64]byte, m *[32]byte) [32]byte {
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	areion256Permutex4Table(states, &roundConstantsP1)
}

func areion256PermuteP2x4(states *[4][32]byte) {
	areion256Permutex4Table(states, &roundConstantsP2)
}

// areion256Permutex4Table runs four Areion-256 permutations under one round-constant table.
func areion256Permutex4Table(states *[4][32]byte, rc *[15][16]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		for i := 0; i < 4; i++ {
			areion256PermuteSoftwareRC(&states[i], rc)
		}
		return
	}
	b0, b1 := pack256x4SoA(states)
	areion256Permutex4RC(&b0, &b1, rc)
	unpack256x4SoA(&b0, &b1, states)
}

func areion512Permutex4(states *[4][64]byte) {
	areion512Permutex4Table(states, &roundConstantsP1)
}

func areion512PermuteP2x4(states *[4][64]byte) {
	areion512Permutex4Table(states, &roundConstantsP2)
}

// areion512Permutex4Table runs four Areion-512 permutations under one round-constant table.
func areion512Permutex4Table(states *[4][64]byte, rc *[15][16]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		for i := 0; i < 4; i++ {
			areion512PermuteSoftwareRC(&states[i], rc)
		}
		return
	}
	b0, b1, b2, b3 := pack512x4SoA(states)
	areion512Permutex4RC(&b0, &b1, &b2, &b3, rc)
	unpack512x4SoA(&b0, &b1, &b2, &b3, states)
}

func areionSoEM256x4(keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte {
	if !hasARMCrypto || TierCode() == TierPureGo {
		var out [4][32]byte
		for i := 0; i < 4; i++ {
			out[i] = soem256Software(&keys[i], &inputs[i])
		}
		return out
	}
	var s1, s2 [4][32]byte
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i++ {
			s1[lane][i] = inputs[lane][i] ^ keys[lane][i]
			s2[lane][i] = inputs[lane][i] ^ keys[lane][32+i]
		}
	}
	b0, b1 := pack256x4SoA(&s1)
	b2, b3 := pack256x4SoA(&s2)
	areion256Permutex4RC(&b0, &b1, &roundConstantsP1)
	areion256Permutex4RC(&b2, &b3, &roundConstantsP2)
	unpack256x4SoA(&b0, &b1, &s1)
	unpack256x4SoA(&b2, &b3, &s2)
	var out [4][32]byte
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i++ {
			out[lane][i] = s1[lane][i] ^ s2[lane][i] ^ keys[lane][i] ^ keys[lane][32+i]
		}
	}
	return out
}

func areionSoEM512x4(keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte {
	if !hasARMCrypto || TierCode() == TierPureGo {
		var out [4][64]byte
		for i := 0; i < 4; i++ {
			out[i] = soem512Software(&keys[i], &inputs[i])
		}
		return out
	}
	var s1, s2 [4][64]byte
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i++ {
			s1[lane][i] = inputs[lane][i] ^ keys[lane][i]
			s2[lane][i] = inputs[lane][i] ^ keys[lane][64+i]
		}
	}
	a1, b1, c1, d1 := pack512x4SoA(&s1)
	a2, b2, c2, d2 := pack512x4SoA(&s2)
	areion512Permutex4RC(&a1, &b1, &c1, &d1, &roundConstantsP1)
	areion512Permutex4RC(&a2, &b2, &c2, &d2, &roundConstantsP2)
	unpack512x4SoA(&a1, &b1, &c1, &d1, &s1)
	unpack512x4SoA(&a2, &b2, &c2, &d2, &s2)
	var out [4][64]byte
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i++ {
			out[lane][i] = s1[lane][i] ^ s2[lane][i] ^ keys[lane][i] ^ keys[lane][64+i]
		}
	}
	return out
}

//go:build (!amd64 && !arm64) || purego

package areion

func areion256Permute(state *State256) {
	areion256PermuteSoftwareRC(state, &roundConstantsP1)
}

func areion256PermuteP2(state *State256) {
	areion256PermuteSoftwareRC(state, &roundConstantsP2)
}

func areion256InversePermute(state *State256) {
	areion256InversePermuteSoftwareRC(state, &roundConstantsP1)
}

func areion256InversePermuteP2(state *State256) {
	areion256InversePermuteSoftwareRC(state, &roundConstantsP2)
}

func areion512Permute(state *State512) {
	areion512PermuteSoftwareRC(state, &roundConstantsP1)
}

func areion512PermuteP2(state *State512) {
	areion512PermuteSoftwareRC(state, &roundConstantsP2)
}

func areion512InversePermute(state *State512) {
	areion512InversePermuteSoftwareRC(state, &roundConstantsP1)
}

func areion512InversePermuteP2(state *State512) {
	areion512InversePermuteSoftwareRC(state, &roundConstantsP2)
}

func areionSoEM256(key *[64]byte, m *[32]byte) [32]byte {
	return soem256Software(key, m)
}

func areionSoEM512(key *[128]byte, m *[64]byte) [64]byte {
	return soem512Software(key, m)
}

func areion256Permutex4(states *[4][32]byte) {
	for i := 0; i < 4; i++ {
		areion256PermuteSoftwareRC(&states[i], &roundConstantsP1)
	}
}

func areion256PermuteP2x4(states *[4][32]byte) {
	for i := 0; i < 4; i++ {
		areion256PermuteSoftwareRC(&states[i], &roundConstantsP2)
	}
}

func areion512Permutex4(states *[4][64]byte) {
	for i := 0; i < 4; i++ {
		areion512PermuteSoftwareRC(&states[i], &roundConstantsP1)
	}
}

func areion512PermuteP2x4(states *[4][64]byte) {
	for i := 0; i < 4; i++ {
		areion512PermuteSoftwareRC(&states[i], &roundConstantsP2)
	}
}

func areionSoEM256x4(keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte {
	var out [4][32]byte
	for i := 0; i < 4; i++ {
		out[i] = soem256Software(&keys[i], &inputs[i])
	}
	return out
}

func areionSoEM512x4(keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte {
	var out [4][64]byte
	for i := 0; i < 4; i++ {
		out[i] = soem512Software(&keys[i], &inputs[i])
	}
	return out
}

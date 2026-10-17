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
	areion256Permutex4SoftwareRC(states, &roundConstantsP1)
}

func areion256PermuteP2x4(states *[4][32]byte) {
	areion256Permutex4SoftwareRC(states, &roundConstantsP2)
}

func areion512Permutex4(states *[4][64]byte) {
	areion512Permutex4SoftwareRC(states, &roundConstantsP1)
}

func areion512PermuteP2x4(states *[4][64]byte) {
	areion512Permutex4SoftwareRC(states, &roundConstantsP2)
}

func areion256InversePermutex4(states *[4][32]byte) {
	areion256InversePermutex4SoftwareRC(states, &roundConstantsP1)
}

func areion256InversePermuteP2x4(states *[4][32]byte) {
	areion256InversePermutex4SoftwareRC(states, &roundConstantsP2)
}

func areion512InversePermutex4(states *[4][64]byte) {
	areion512InversePermutex4SoftwareRC(states, &roundConstantsP1)
}

func areion512InversePermuteP2x4(states *[4][64]byte) {
	areion512InversePermutex4SoftwareRC(states, &roundConstantsP2)
}

func areionSoEM256x4(keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte {
	return soem256x4Software(keys, inputs)
}

func areionSoEM512x4(keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte {
	return soem512x4Software(keys, inputs)
}

func aesRoundHW(block, roundKey *Block) {
	Round(block, roundKey)
}

func aesFinalRoundHW(block, roundKey *Block) {
	FinalRound(block, roundKey)
}

func aesRound4HW(blocks, roundKeys *Block4) {
	aesRound4Software(blocks, roundKeys)
}

func aesFinalRound4HW(blocks, roundKeys *Block4) {
	aesFinalRound4Software(blocks, roundKeys)
}

func aes128EncryptBlock(rk *[11][16]byte, dst, src *[16]byte) {
	aes128EncryptBlockSoftware(rk, dst, src)
}

func aes128Encrypt4Blocks(rk *[11][16]byte, dst, src *[64]byte) {
	aes128Encrypt4BlocksSoftware(rk, dst, src)
}

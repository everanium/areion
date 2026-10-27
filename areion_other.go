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

func areionEMEncrypt256(out, m *[32]byte, k *[64]byte) {
	emEncrypt256Software(out, m, k)
}

func areionEMDecrypt256(out, c *[32]byte, k *[64]byte) {
	emDecrypt256Software(out, c, k)
}

func areionEMEncrypt512(out, m *[64]byte, k *[128]byte) {
	emEncrypt512Software(out, m, k)
}

func areionEMDecrypt512(out, c *[64]byte, k *[128]byte) {
	emDecrypt512Software(out, c, k)
}

func areionEMEncrypt256x4(out, msgs *[4][32]byte, keys *[4][64]byte) {
	emEncrypt256x4Software(out, msgs, keys)
}

func areionEMDecrypt256x4(out, ct *[4][32]byte, keys *[4][64]byte) {
	emDecrypt256x4Software(out, ct, keys)
}

func areionEMEncrypt512x4(out, msgs *[4][64]byte, keys *[4][128]byte) {
	emEncrypt512x4Software(out, msgs, keys)
}

func areionEMDecrypt512x4(out, ct *[4][64]byte, keys *[4][128]byte) {
	emDecrypt512x4Software(out, ct, keys)
}

func areionEM2Encrypt256(out, m *[32]byte, k *[64]byte) {
	em2Encrypt256Software(out, m, k)
}

func areionEM2Decrypt256(out, c *[32]byte, k *[64]byte) {
	em2Decrypt256Software(out, c, k)
}

func areionEM2Encrypt512(out, m *[64]byte, k *[128]byte) {
	em2Encrypt512Software(out, m, k)
}

func areionEM2Decrypt512(out, c *[64]byte, k *[128]byte) {
	em2Decrypt512Software(out, c, k)
}

func areionEM2Encrypt256x4(out, msgs *[4][32]byte, keys *[4][64]byte) {
	em2Encrypt256x4Software(out, msgs, keys)
}

func areionEM2Decrypt256x4(out, ct *[4][32]byte, keys *[4][64]byte) {
	em2Decrypt256x4Software(out, ct, keys)
}

func areionEM2Encrypt512x4(out, msgs *[4][64]byte, keys *[4][128]byte) {
	em2Encrypt512x4Software(out, msgs, keys)
}

func areionEM2Decrypt512x4(out, ct *[4][64]byte, keys *[4][128]byte) {
	em2Decrypt512x4Software(out, ct, keys)
}

func areionTEMEncrypt256(out, m *[32]byte, k *[64]byte, t *[32]byte) {
	temEncrypt256Software(out, m, k, t)
}

func areionTEMDecrypt256(out, c *[32]byte, k *[64]byte, t *[32]byte) {
	temDecrypt256Software(out, c, k, t)
}

func areionTEMEncrypt512(out, m *[64]byte, k *[128]byte, t *[64]byte) {
	temEncrypt512Software(out, m, k, t)
}

func areionTEMDecrypt512(out, c *[64]byte, k *[128]byte, t *[64]byte) {
	temDecrypt512Software(out, c, k, t)
}

func areionTEMEncrypt256x4(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	temEncrypt256x4Software(out, msgs, keys, tweaks)
}

func areionTEMDecrypt256x4(out, ct *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	temDecrypt256x4Software(out, ct, keys, tweaks)
}

func areionTEMEncrypt512x4(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	temEncrypt512x4Software(out, msgs, keys, tweaks)
}

func areionTEMDecrypt512x4(out, ct *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	temDecrypt512x4Software(out, ct, keys, tweaks)
}

func areionTEM2Encrypt256(out, m *[32]byte, k *[64]byte, t *[32]byte) {
	tem2Encrypt256Software(out, m, k, t)
}

func areionTEM2Decrypt256(out, c *[32]byte, k *[64]byte, t *[32]byte) {
	tem2Decrypt256Software(out, c, k, t)
}

func areionTEM2Encrypt512(out, m *[64]byte, k *[128]byte, t *[64]byte) {
	tem2Encrypt512Software(out, m, k, t)
}

func areionTEM2Decrypt512(out, c *[64]byte, k *[128]byte, t *[64]byte) {
	tem2Decrypt512Software(out, c, k, t)
}

func areionTEM2Encrypt256x4(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	tem2Encrypt256x4Software(out, msgs, keys, tweaks)
}

func areionTEM2Decrypt256x4(out, ct *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	tem2Decrypt256x4Software(out, ct, keys, tweaks)
}

func areionTEM2Encrypt512x4(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	tem2Encrypt512x4Software(out, msgs, keys, tweaks)
}

func areionTEM2Decrypt512x4(out, ct *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	tem2Decrypt512x4Software(out, ct, keys, tweaks)
}

func clobberScratchGPRs() {}

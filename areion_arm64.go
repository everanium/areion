//go:build arm64 && !purego

package areion

//go:noescape
func aesRoundAsm(block, roundKey *Block)

//go:noescape
func aesFinalRoundAsm(block, roundKey *Block)

//go:noescape
func aesRound4Asm(blocks, roundKeys *Block4)

//go:noescape
func aesFinalRound4Asm(blocks, roundKeys *Block4)

//go:noescape
func aes128EncryptBlockAsm(rk *[11][16]byte, dst, src *[16]byte)

//go:noescape
func aes128Encrypt4BlocksAsm(rk *[11][16]byte, dst, src *[64]byte)

//go:noescape
func aes128ExpandKeyAsm(rk *[11][16]byte, key *[16]byte)

//go:noescape
func rijndael256EncryptBlockAsm(rk *[15][32]byte, dst, src *[32]byte)

//go:noescape
func rijndael256Encrypt4BlocksAsm(rk *[15][32]byte, dst, src *[4][32]byte)

//go:noescape
func vistrutah256EncryptBlockAsm(dst, src, key *[32]byte, rounds int)

//go:noescape
func vistrutah256Encrypt4BlocksAsm(dst, src *[4][32]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock256Asm(dst, src *[64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock512Asm(dst, src, key *[64]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks256Asm(dst, src *[4][64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks512Asm(dst, src *[4][64]byte, key *[64]byte, rounds int)

//go:noescape
func areion256PermuteRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion512PermuteRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areion256InversePermuteRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion512InversePermuteRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areionSoEM256Asm(out *[32]byte, key *[64]byte, m *[32]byte)

//go:noescape
func areionSoEM512Asm(out *[64]byte, key *[128]byte, m *[64]byte)

//go:noescape
func areion256DMAsm(out, m *[32]byte)

//go:noescape
func areion512DMAsm(out *[32]byte, m *[64]byte)

//go:noescape
func areion256Permutex4RC(b0, b1, b2, b3 *[32]byte, rc *[15][16]byte)

//go:noescape
func areion256InversePermutex4RC(b0, b1, b2, b3 *[32]byte, rc *[15][16]byte)

//go:noescape
func areion512Permutex4RC(b0, b1, b2, b3 *[64]byte, rc *[15][16]byte)

//go:noescape
func areion512InversePermutex4RC(b0, b1, b2, b3 *[64]byte, rc *[15][16]byte)

//go:noescape
func areion256SoEMPermutex4NEON(out, inputs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion512SoEMPermutex4NEON(out, inputs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion256EMEncryptx4Asm(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EMDecryptx4Asm(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion512EMEncryptx4Asm(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EMDecryptx4Asm(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion256EM2Encryptx4Asm(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EM2Decryptx4Asm(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion512EM2Encryptx4Asm(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EM2Decryptx4Asm(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion256TEMEncryptx4Asm(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEMDecryptx4Asm(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion512TEMEncryptx4Asm(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEMDecryptx4Asm(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion256TEM2Encryptx4Asm(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEM2Decryptx4Asm(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion512TEM2Encryptx4Asm(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEM2Decryptx4Asm(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion256EMEncryptAsm(out *[32]byte, m *[32]byte, k *[64]byte)

//go:noescape
func areion256EMDecryptAsm(out *[32]byte, c *[32]byte, k *[64]byte)

//go:noescape
func areion512EMEncryptAsm(out *[64]byte, m *[64]byte, k *[128]byte)

//go:noescape
func areion512EMDecryptAsm(out *[64]byte, c *[64]byte, k *[128]byte)

//go:noescape
func areion256EM2EncryptAsm(out *[32]byte, m *[32]byte, k *[64]byte)

//go:noescape
func areion256EM2DecryptAsm(out *[32]byte, c *[32]byte, k *[64]byte)

//go:noescape
func areion512EM2EncryptAsm(out *[64]byte, m *[64]byte, k *[128]byte)

//go:noescape
func areion512EM2DecryptAsm(out *[64]byte, c *[64]byte, k *[128]byte)

//go:noescape
func areion256TEMEncryptAsm(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEMDecryptAsm(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion512TEMEncryptAsm(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEMDecryptAsm(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion256TEM2EncryptAsm(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEM2DecryptAsm(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion512TEM2EncryptAsm(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEM2DecryptAsm(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte)

func aesRoundHW(block, roundKey *Block) {
	if hasARMCrypto && TierCode() != TierPureGo {
		aesRoundAsm(block, roundKey)
		return
	}
	Round(block, roundKey)
}

func aesFinalRoundHW(block, roundKey *Block) {
	if hasARMCrypto && TierCode() != TierPureGo {
		aesFinalRoundAsm(block, roundKey)
		return
	}
	FinalRound(block, roundKey)
}

func aesRound4HW(blocks, roundKeys *Block4) {
	if hasARMCrypto && TierCode() != TierPureGo {
		aesRound4Asm(blocks, roundKeys)
		return
	}
	aesRound4Software(blocks, roundKeys)
}

func aesFinalRound4HW(blocks, roundKeys *Block4) {
	if hasARMCrypto && TierCode() != TierPureGo {
		aesFinalRound4Asm(blocks, roundKeys)
		return
	}
	aesFinalRound4Software(blocks, roundKeys)
}

func aes128EncryptBlock(rk *[11][16]byte, dst, src *[16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		aes128EncryptBlockAsm(rk, dst, src)
		return
	}
	aes128EncryptBlockSoftware(rk, dst, src)
}

func aes128Encrypt4Blocks(rk *[11][16]byte, dst, src *[64]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		aes128Encrypt4BlocksAsm(rk, dst, src)
		return
	}
	aes128Encrypt4BlocksSoftware(rk, dst, src)
}

func expandKey128(key *[16]byte, rk *[11][16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		aes128ExpandKeyAsm(rk, key)
		return
	}
	expandKey128Software(key, rk)
}

func rijndael256EncryptBlockHW(rk *[15][32]byte, dst, src *[32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		rijndael256EncryptBlockAsm(rk, dst, src)
		return
	}
	rijndael256EncryptBlockSoftware(rk, dst, src)
}

func rijndael256Encrypt4BlocksHW(rk *[15][32]byte, dst, src *[4][32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		rijndael256Encrypt4BlocksAsm(rk, dst, src)
		return
	}
	rijndael256Encrypt4BlocksSoftware(rk, dst, src)
}

func vistrutah256EncryptBlockHW(dst, src, key *[32]byte, rounds int) {
	if (rounds == 10 || rounds == 14) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah256EncryptBlockAsm(dst, src, key, rounds)
		return
	}
	vistrutah256EncryptBlockSoft(dst, src, key, rounds)
}

func vistrutah256Encrypt4BlocksHW(dst, src *[4][32]byte, key *[32]byte, rounds int) {
	if (rounds == 10 || rounds == 14) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah256Encrypt4BlocksAsm(dst, src, key, rounds)
		return
	}
	vistrutah256Encrypt4BlocksSoft(dst, src, key, rounds)
}

func vistrutah512EncryptBlock256HW(dst, src *[64]byte, key *[32]byte, rounds int) {
	if (rounds == 10 || rounds == 12 || rounds == 14 || rounds == 18) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah512EncryptBlock256Asm(dst, src, key, rounds)
		return
	}
	vistrutah512EncryptBlock256Soft(dst, src, key, rounds)
}

func vistrutah512EncryptBlock512HW(dst, src, key *[64]byte, rounds int) {
	if (rounds == 10 || rounds == 12 || rounds == 14 || rounds == 18) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah512EncryptBlock512Asm(dst, src, key, rounds)
		return
	}
	vistrutah512EncryptBlock512Soft(dst, src, key, rounds)
}

func vistrutah512Encrypt4Blocks256HW(dst, src *[4][64]byte, key *[32]byte, rounds int) {
	if (rounds == 10 || rounds == 12 || rounds == 14 || rounds == 18) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah512Encrypt4Blocks256Asm(dst, src, key, rounds)
		return
	}
	vistrutah512Encrypt4Blocks256Soft(dst, src, key, rounds)
}

func vistrutah512Encrypt4Blocks512HW(dst, src *[4][64]byte, key *[64]byte, rounds int) {
	if (rounds == 10 || rounds == 12 || rounds == 14 || rounds == 18) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah512Encrypt4Blocks512Asm(dst, src, key, rounds)
		return
	}
	vistrutah512Encrypt4Blocks512Soft(dst, src, key, rounds)
}

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

//go:noescape
func clobberScratchGPRs()

func areionSoEM256(key *[64]byte, m *[32]byte) (out [32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		return soem256Software(key, m)
	}
	areionSoEM256Asm(&out, key, m)
	return out
}

func areionSoEM512(key *[128]byte, m *[64]byte) (out [64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		return soem512Software(key, m)
	}
	areionSoEM512Asm(&out, key, m)
	return out
}

func areionDM256(out, m *[32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		areion256DMAsm(out, m)
		return
	}
	dm256Software(out, m)
}

func areionDM512(out *[32]byte, m *[64]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		areion512DMAsm(out, m)
		return
	}
	dm512Software(out, m)
}

func areion256Permutex4(states *[4][32]byte) {
	areion256Permutex4Table(states, &roundConstantsP1)
}

func areion256PermuteP2x4(states *[4][32]byte) {
	areion256Permutex4Table(states, &roundConstantsP2)
}

func areion256Permutex4Table(states *[4][32]byte, rc *[15][16]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		areion256Permutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	areion256Permutex4RC(&states[0], &states[1], &states[2], &states[3], rc)
}

func areion256InversePermutex4(states *[4][32]byte) {
	areion256InversePermutex4Table(states, &roundConstantsP1)
}

func areion256InversePermuteP2x4(states *[4][32]byte) {
	areion256InversePermutex4Table(states, &roundConstantsP2)
}

func areion256InversePermutex4Table(states *[4][32]byte, rc *[15][16]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		areion256InversePermutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	areion256InversePermutex4RC(&states[0], &states[1], &states[2], &states[3], rc)
}

func areion512Permutex4(states *[4][64]byte) {
	areion512Permutex4Table(states, &roundConstantsP1)
}

func areion512PermuteP2x4(states *[4][64]byte) {
	areion512Permutex4Table(states, &roundConstantsP2)
}

func areion512Permutex4Table(states *[4][64]byte, rc *[15][16]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		areion512Permutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	areion512Permutex4RC(&states[0], &states[1], &states[2], &states[3], rc)
}

func areion512InversePermutex4(states *[4][64]byte) {
	areion512InversePermutex4Table(states, &roundConstantsP1)
}

func areion512InversePermuteP2x4(states *[4][64]byte) {
	areion512InversePermutex4Table(states, &roundConstantsP2)
}

func areion512InversePermutex4Table(states *[4][64]byte, rc *[15][16]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		areion512InversePermutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	areion512InversePermutex4RC(&states[0], &states[1], &states[2], &states[3], rc)
}

func areionSoEM256x4(keys *[4][64]byte, inputs *[4][32]byte) (out [4][32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		return soem256x4Software(keys, inputs)
	}
	areion256SoEMPermutex4NEON(&out, inputs, keys)
	return out
}

func areionSoEM512x4(keys *[4][128]byte, inputs *[4][64]byte) (out [4][64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		return soem512x4Software(keys, inputs)
	}
	areion512SoEMPermutex4NEON(&out, inputs, keys)
	return out
}

func areionEMEncrypt256(out *[32]byte, m *[32]byte, k *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emEncrypt256Software(out, m, k)
		return
	}
	areion256EMEncryptAsm(out, m, k)
}

func areionEMDecrypt256(out *[32]byte, c *[32]byte, k *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emDecrypt256Software(out, c, k)
		return
	}
	areion256EMDecryptAsm(out, c, k)
}

func areionEMEncrypt512(out *[64]byte, m *[64]byte, k *[128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emEncrypt512Software(out, m, k)
		return
	}
	areion512EMEncryptAsm(out, m, k)
}

func areionEMDecrypt512(out *[64]byte, c *[64]byte, k *[128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emDecrypt512Software(out, c, k)
		return
	}
	areion512EMDecryptAsm(out, c, k)
}

func areionEM2Encrypt256(out *[32]byte, m *[32]byte, k *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Encrypt256Software(out, m, k)
		return
	}
	areion256EM2EncryptAsm(out, m, k)
}

func areionEM2Decrypt256(out *[32]byte, c *[32]byte, k *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Decrypt256Software(out, c, k)
		return
	}
	areion256EM2DecryptAsm(out, c, k)
}

func areionEM2Encrypt512(out *[64]byte, m *[64]byte, k *[128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Encrypt512Software(out, m, k)
		return
	}
	areion512EM2EncryptAsm(out, m, k)
}

func areionEM2Decrypt512(out *[64]byte, c *[64]byte, k *[128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Decrypt512Software(out, c, k)
		return
	}
	areion512EM2DecryptAsm(out, c, k)
}

func areionTEMEncrypt256(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temEncrypt256Software(out, m, k, t)
		return
	}
	areion256TEMEncryptAsm(out, m, k, t)
}

func areionTEMDecrypt256(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temDecrypt256Software(out, c, k, t)
		return
	}
	areion256TEMDecryptAsm(out, c, k, t)
}

func areionTEMEncrypt512(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temEncrypt512Software(out, m, k, t)
		return
	}
	areion512TEMEncryptAsm(out, m, k, t)
}

func areionTEMDecrypt512(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temDecrypt512Software(out, c, k, t)
		return
	}
	areion512TEMDecryptAsm(out, c, k, t)
}

func areionTEM2Encrypt256(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Encrypt256Software(out, m, k, t)
		return
	}
	areion256TEM2EncryptAsm(out, m, k, t)
}

func areionTEM2Decrypt256(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Decrypt256Software(out, c, k, t)
		return
	}
	areion256TEM2DecryptAsm(out, c, k, t)
}

func areionTEM2Encrypt512(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Encrypt512Software(out, m, k, t)
		return
	}
	areion512TEM2EncryptAsm(out, m, k, t)
}

func areionTEM2Decrypt512(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Decrypt512Software(out, c, k, t)
		return
	}
	areion512TEM2DecryptAsm(out, c, k, t)
}

func areionEMEncrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emEncrypt256x4Software(out, msgs, keys)
		return
	}
	areion256EMEncryptx4Asm(out, msgs, keys)
}

func areionEMDecrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emDecrypt256x4Software(out, ct, keys)
		return
	}
	areion256EMDecryptx4Asm(out, ct, keys)
}

func areionEMEncrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emEncrypt512x4Software(out, msgs, keys)
		return
	}
	areion512EMEncryptx4Asm(out, msgs, keys)
}

func areionEMDecrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emDecrypt512x4Software(out, ct, keys)
		return
	}
	areion512EMDecryptx4Asm(out, ct, keys)
}

func areionEM2Encrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Encrypt256x4Software(out, msgs, keys)
		return
	}
	areion256EM2Encryptx4Asm(out, msgs, keys)
}

func areionEM2Decrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Decrypt256x4Software(out, ct, keys)
		return
	}
	areion256EM2Decryptx4Asm(out, ct, keys)
}

func areionEM2Encrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Encrypt512x4Software(out, msgs, keys)
		return
	}
	areion512EM2Encryptx4Asm(out, msgs, keys)
}

func areionEM2Decrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Decrypt512x4Software(out, ct, keys)
		return
	}
	areion512EM2Decryptx4Asm(out, ct, keys)
}

func areionTEMEncrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temEncrypt256x4Software(out, msgs, keys, tweaks)
		return
	}
	areion256TEMEncryptx4Asm(out, msgs, keys, tweaks)
}

func areionTEMDecrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temDecrypt256x4Software(out, ct, keys, tweaks)
		return
	}
	areion256TEMDecryptx4Asm(out, ct, keys, tweaks)
}

func areionTEMEncrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temEncrypt512x4Software(out, msgs, keys, tweaks)
		return
	}
	areion512TEMEncryptx4Asm(out, msgs, keys, tweaks)
}

func areionTEMDecrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temDecrypt512x4Software(out, ct, keys, tweaks)
		return
	}
	areion512TEMDecryptx4Asm(out, ct, keys, tweaks)
}

func areionTEM2Encrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Encrypt256x4Software(out, msgs, keys, tweaks)
		return
	}
	areion256TEM2Encryptx4Asm(out, msgs, keys, tweaks)
}

func areionTEM2Decrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Decrypt256x4Software(out, ct, keys, tweaks)
		return
	}
	areion256TEM2Decryptx4Asm(out, ct, keys, tweaks)
}

func areionTEM2Encrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Encrypt512x4Software(out, msgs, keys, tweaks)
		return
	}
	areion512TEM2Encryptx4Asm(out, msgs, keys, tweaks)
}

func areionTEM2Decrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Decrypt512x4Software(out, ct, keys, tweaks)
		return
	}
	areion512TEM2Decryptx4Asm(out, ct, keys, tweaks)
}

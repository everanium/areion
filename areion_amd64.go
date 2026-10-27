//go:build amd64 && !purego

package areion

import (
	"runtime"
)

//go:noescape
func aesRoundAsm(block, roundKey *Block)

//go:noescape
func aesRoundVexAsm(block, roundKey *Block)

//go:noescape
func aesFinalRoundAsm(block, roundKey *Block)

//go:noescape
func aesFinalRoundVexAsm(block, roundKey *Block)

//go:noescape
func aesRound4ZmmAsm(blocks, roundKeys *Block4)

//go:noescape
func aesFinalRound4ZmmAsm(blocks, roundKeys *Block4)

//go:noescape
func aesRound4YmmAsm(blocks, roundKeys *Block4)

//go:noescape
func aesFinalRound4YmmAsm(blocks, roundKeys *Block4)

//go:noescape
func aesRound4VexAsm(blocks, roundKeys *Block4)

//go:noescape
func aesFinalRound4VexAsm(blocks, roundKeys *Block4)

//go:noescape
func aesRound4AesNiAsm(blocks, roundKeys *Block4)

//go:noescape
func aesFinalRound4AesNiAsm(blocks, roundKeys *Block4)

//go:noescape
func aes128EncryptBlockAsm(rk *[11][16]byte, dst, src *[16]byte)

//go:noescape
func aes128EncryptBlockVexAsm(rk *[11][16]byte, dst, src *[16]byte)

//go:noescape
func aes128Encrypt4BlocksZmmAsm(rk *[11][16]byte, dst, src *[64]byte)

//go:noescape
func aes128Encrypt4BlocksYmmAsm(rk *[11][16]byte, dst, src *[64]byte)

//go:noescape
func aes128Encrypt4BlocksVexAsm(rk *[11][16]byte, dst, src *[64]byte)

//go:noescape
func aes128Encrypt4BlocksAesNiAsm(rk *[11][16]byte, dst, src *[64]byte)

//go:noescape
func areion256PermuteRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion256PermuteVexRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion512PermuteRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areion512PermuteVexRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areion256InversePermuteRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion256InversePermuteVexRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion512InversePermuteRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areion512InversePermuteVexRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areionSoEM256Asm(out *[32]byte, key *[64]byte, m *[32]byte)

//go:noescape
func areionSoEM256VexAsm(out *[32]byte, key *[64]byte, m *[32]byte)

//go:noescape
func areionSoEM512Asm(out *[64]byte, key *[128]byte, m *[64]byte)

//go:noescape
func areionSoEM512VexAsm(out *[64]byte, key *[128]byte, m *[64]byte)

//go:noescape
func areion256Permutex4RC(x0, x1 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion256InversePermutex4RC(x0, x1 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4RC(x0, x1, x2, x3 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion512InversePermutex4RC(x0, x1, x2, x3 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion256Permutex4Avx2RC(x0, x1 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion256InversePermutex4Avx2RC(x0, x1 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4Avx2RC(x0, x1, x2, x3 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion512InversePermutex4Avx2RC(x0, x1, x2, x3 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion256Permutex4VexRC(x0, x1 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion256InversePermutex4VexRC(x0, x1 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4VexRC(x0, x1, x2, x3 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion512InversePermutex4VexRC(x0, x1, x2, x3 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion256Permutex4AesNiRC(x0, x1 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion256InversePermutex4AesNiRC(x0, x1 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4AesNiRC(x0, x1, x2, x3 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion512InversePermutex4AesNiRC(x0, x1, x2, x3 *Block4, rc *[15 * 64]byte)

//go:noescape
func areion256SoEMPermutex4Interleaved(s1b0, s1b1, s2b0, s2b1 *Block4)

//go:noescape
func areion512SoEMPermutex4Interleaved(a1, b1, c1, d1, a2, b2, c2, d2 *Block4)

//go:noescape
func areion256SoEMPermutex4VaesAvx2(s1b0, s1b1, s2b0, s2b1 *Block4)

//go:noescape
func areion512SoEMPermutex4VaesAvx2(a1, b1, c1, d1, a2, b2, c2, d2 *Block4)

//go:noescape
func areion256SoEMPermutex4Vex(s1b0, s1b1, s2b0, s2b1 *Block4)

//go:noescape
func areion512SoEMPermutex4Vex(a1, b1, c1, d1, a2, b2, c2, d2 *Block4)

//go:noescape
func areion256SoEMPermutex4AesNi(s1b0, s1b1, s2b0, s2b1 *Block4)

//go:noescape
func areion512SoEMPermutex4AesNi(a1, b1, c1, d1, a2, b2, c2, d2 *Block4)

//go:noescape
func areion256EMEncryptAESNI(out *[32]byte, m *[32]byte, k *[64]byte)

//go:noescape
func areion256EMEncryptVEX(out *[32]byte, m *[32]byte, k *[64]byte)

//go:noescape
func areion256EMDecryptAESNI(out *[32]byte, c *[32]byte, k *[64]byte)

//go:noescape
func areion256EMDecryptVEX(out *[32]byte, c *[32]byte, k *[64]byte)

//go:noescape
func areion512EMEncryptAESNI(out *[64]byte, m *[64]byte, k *[128]byte)

//go:noescape
func areion512EMEncryptVEX(out *[64]byte, m *[64]byte, k *[128]byte)

//go:noescape
func areion512EMDecryptAESNI(out *[64]byte, c *[64]byte, k *[128]byte)

//go:noescape
func areion512EMDecryptVEX(out *[64]byte, c *[64]byte, k *[128]byte)

//go:noescape
func areion256EM2EncryptAESNI(out *[32]byte, m *[32]byte, k *[64]byte)

//go:noescape
func areion256EM2EncryptVEX(out *[32]byte, m *[32]byte, k *[64]byte)

//go:noescape
func areion256EM2DecryptAESNI(out *[32]byte, c *[32]byte, k *[64]byte)

//go:noescape
func areion256EM2DecryptVEX(out *[32]byte, c *[32]byte, k *[64]byte)

//go:noescape
func areion512EM2EncryptAESNI(out *[64]byte, m *[64]byte, k *[128]byte)

//go:noescape
func areion512EM2EncryptVEX(out *[64]byte, m *[64]byte, k *[128]byte)

//go:noescape
func areion512EM2DecryptAESNI(out *[64]byte, c *[64]byte, k *[128]byte)

//go:noescape
func areion512EM2DecryptVEX(out *[64]byte, c *[64]byte, k *[128]byte)

//go:noescape
func areion256TEMEncryptAESNI(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEMEncryptVEX(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEMDecryptAESNI(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEMDecryptVEX(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion512TEMEncryptAESNI(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEMEncryptVEX(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEMDecryptAESNI(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEMDecryptVEX(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion256TEM2EncryptAESNI(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEM2EncryptVEX(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEM2DecryptAESNI(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEM2DecryptVEX(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion512TEM2EncryptAESNI(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEM2EncryptVEX(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEM2DecryptAESNI(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEM2DecryptVEX(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte)

func aesRoundHW(block, roundKey *Block) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		aesRoundVexAsm(block, roundKey)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		aesRoundAsm(block, roundKey)
		return
	}
	Round(block, roundKey)
}

func aesFinalRoundHW(block, roundKey *Block) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		aesFinalRoundVexAsm(block, roundKey)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		aesFinalRoundAsm(block, roundKey)
		return
	}
	FinalRound(block, roundKey)
}

func aesRound4HW(blocks, roundKeys *Block4) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		aesRound4ZmmAsm(blocks, roundKeys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		aesRound4YmmAsm(blocks, roundKeys)
	case hasVEX && tier >= TierVEX:
		aesRound4VexAsm(blocks, roundKeys)
	case hasAESNI && tier >= TierAESNI:
		aesRound4AesNiAsm(blocks, roundKeys)
	default:
		aesRound4Software(blocks, roundKeys)
	}
}

func aesFinalRound4HW(blocks, roundKeys *Block4) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		aesFinalRound4ZmmAsm(blocks, roundKeys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		aesFinalRound4YmmAsm(blocks, roundKeys)
	case hasVEX && tier >= TierVEX:
		aesFinalRound4VexAsm(blocks, roundKeys)
	case hasAESNI && tier >= TierAESNI:
		aesFinalRound4AesNiAsm(blocks, roundKeys)
	default:
		aesFinalRound4Software(blocks, roundKeys)
	}
}

func aes128EncryptBlock(rk *[11][16]byte, dst, src *[16]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		aes128EncryptBlockVexAsm(rk, dst, src)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		aes128EncryptBlockAsm(rk, dst, src)
		return
	}
	aes128EncryptBlockSoftware(rk, dst, src)
}

func aes128Encrypt4Blocks(rk *[11][16]byte, dst, src *[64]byte) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		aes128Encrypt4BlocksZmmAsm(rk, dst, src)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		aes128Encrypt4BlocksYmmAsm(rk, dst, src)
	case hasVEX && tier >= TierVEX:
		aes128Encrypt4BlocksVexAsm(rk, dst, src)
	case hasAESNI && tier >= TierAESNI:
		aes128Encrypt4BlocksAesNiAsm(rk, dst, src)
	default:
		aes128Encrypt4BlocksSoftware(rk, dst, src)
	}
}

func areion256Permute(state *State256) {
	areion256PermuteRC(state, &roundConstantsP1)
}

func areion256PermuteP2(state *State256) {
	areion256PermuteRC(state, &roundConstantsP2)
}

func areion256PermuteRC(state *State256, rc *[15][16]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		areion256PermuteVexRCAsm(state, rc)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		areion256PermuteRCAsm(state, rc)
		return
	}
	areion256PermuteSoftwareRC(state, rc)
}

func areion256InversePermute(state *State256) {
	areion256InversePermuteRC(state, &roundConstantsP1)
}

func areion256InversePermuteP2(state *State256) {
	areion256InversePermuteRC(state, &roundConstantsP2)
}

func areion256InversePermuteRC(state *State256, rc *[15][16]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		areion256InversePermuteVexRCAsm(state, rc)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		areion256InversePermuteRCAsm(state, rc)
		return
	}
	areion256InversePermuteSoftwareRC(state, rc)
}

func areion512Permute(state *State512) {
	areion512PermuteRC(state, &roundConstantsP1)
}

func areion512PermuteP2(state *State512) {
	areion512PermuteRC(state, &roundConstantsP2)
}

func areion512PermuteRC(state *State512, rc *[15][16]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		areion512PermuteVexRCAsm(state, rc)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		areion512PermuteRCAsm(state, rc)
		return
	}
	areion512PermuteSoftwareRC(state, rc)
}

func areion512InversePermute(state *State512) {
	areion512InversePermuteRC(state, &roundConstantsP1)
}

func areion512InversePermuteP2(state *State512) {
	areion512InversePermuteRC(state, &roundConstantsP2)
}

func areion512InversePermuteRC(state *State512, rc *[15][16]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		areion512InversePermuteVexRCAsm(state, rc)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		areion512InversePermuteRCAsm(state, rc)
		return
	}
	areion512InversePermuteSoftwareRC(state, rc)
}

//go:noescape
func clobberScratchGPRs()

func areionSoEM256(key *[64]byte, m *[32]byte) [32]byte {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		return soem256Software(key, m)
	}
	var buf [32]byte
	if hasVEX && tier >= TierVEX {
		areionSoEM256VexAsm(&buf, key, m)
	} else {
		areionSoEM256Asm(&buf, key, m)
	}
	out := buf
	clear(buf[:])
	runtime.KeepAlive(&buf)
	clobberScratchGPRs()
	return out
}

func areionSoEM512(key *[128]byte, m *[64]byte) [64]byte {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		return soem512Software(key, m)
	}
	var buf [64]byte
	if hasVEX && tier >= TierVEX {
		areionSoEM512VexAsm(&buf, key, m)
	} else {
		areionSoEM512Asm(&buf, key, m)
	}
	out := buf
	clear(buf[:])
	runtime.KeepAlive(&buf)
	clobberScratchGPRs()
	return out
}

func areion256Permutex4(states *[4][32]byte) {
	areion256Permutex4Tables(states, &roundConstantsP1, &areionRC4x)
}

func areion256PermuteP2x4(states *[4][32]byte) {
	areion256Permutex4Tables(states, &roundConstantsP2, &areionRC4x2)
}

func areion256Permutex4Tables(states *[4][32]byte, rc *[15][16]byte, rc4 *[15 * 64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		areion256Permutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	var b0, b1 Block4
	pack256x4SoAInto(states, &b0, &b1)
	if hasAVX512 && hasVAESAVX2 && tier >= TierAVX512 {
		areion256Permutex4RC(&b0, &b1, rc4)
	} else if hasVAESAVX2 && tier >= TierVAESAVX2 {
		areion256Permutex4Avx2RC(&b0, &b1, rc4)
	} else if hasVEX && tier >= TierVEX {
		areion256Permutex4VexRC(&b0, &b1, rc4)
	} else {
		areion256Permutex4AesNiRC(&b0, &b1, rc4)
	}
	unpack256x4SoA(&b0, &b1, states)
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
}

func areion256InversePermutex4(states *[4][32]byte) {
	areion256InversePermutex4Tables(states, &roundConstantsP1, &areionRC4x)
}

func areion256InversePermuteP2x4(states *[4][32]byte) {
	areion256InversePermutex4Tables(states, &roundConstantsP2, &areionRC4x2)
}

func areion256InversePermutex4Tables(states *[4][32]byte, rc *[15][16]byte, rc4 *[15 * 64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		areion256InversePermutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	var b0, b1 Block4
	pack256x4SoAInto(states, &b0, &b1)
	if hasAVX512 && hasVAESAVX2 && tier >= TierAVX512 {
		areion256InversePermutex4RC(&b0, &b1, rc4)
	} else if hasVAESAVX2 && tier >= TierVAESAVX2 {
		areion256InversePermutex4Avx2RC(&b0, &b1, rc4)
	} else if hasVEX && tier >= TierVEX {
		areion256InversePermutex4VexRC(&b0, &b1, rc4)
	} else {
		areion256InversePermutex4AesNiRC(&b0, &b1, rc4)
	}
	unpack256x4SoA(&b0, &b1, states)
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
}

func areion512Permutex4(states *[4][64]byte) {
	areion512Permutex4Tables(states, &roundConstantsP1, &areionRC4x)
}

func areion512PermuteP2x4(states *[4][64]byte) {
	areion512Permutex4Tables(states, &roundConstantsP2, &areionRC4x2)
}

func areion512Permutex4Tables(states *[4][64]byte, rc *[15][16]byte, rc4 *[15 * 64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		areion512Permutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	var b0, b1, b2, b3 Block4
	pack512x4SoAInto(states, &b0, &b1, &b2, &b3)
	if hasAVX512 && hasVAESAVX2 && tier >= TierAVX512 {
		areion512Permutex4RC(&b0, &b1, &b2, &b3, rc4)
	} else if hasVAESAVX2 && tier >= TierVAESAVX2 {
		areion512Permutex4Avx2RC(&b0, &b1, &b2, &b3, rc4)
	} else if hasVEX && tier >= TierVEX {
		areion512Permutex4VexRC(&b0, &b1, &b2, &b3, rc4)
	} else {
		areion512Permutex4AesNiRC(&b0, &b1, &b2, &b3, rc4)
	}
	unpack512x4SoA(&b0, &b1, &b2, &b3, states)
	clear(b0[:])
	clear(b1[:])
	clear(b2[:])
	clear(b3[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&b2)
	runtime.KeepAlive(&b3)
	clobberScratchGPRs()
}

func areion512InversePermutex4(states *[4][64]byte) {
	areion512InversePermutex4Tables(states, &roundConstantsP1, &areionRC4x)
}

func areion512InversePermuteP2x4(states *[4][64]byte) {
	areion512InversePermutex4Tables(states, &roundConstantsP2, &areionRC4x2)
}

func areion512InversePermutex4Tables(states *[4][64]byte, rc *[15][16]byte, rc4 *[15 * 64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		areion512InversePermutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	var b0, b1, b2, b3 Block4
	pack512x4SoAInto(states, &b0, &b1, &b2, &b3)
	if hasAVX512 && hasVAESAVX2 && tier >= TierAVX512 {
		areion512InversePermutex4RC(&b0, &b1, &b2, &b3, rc4)
	} else if hasVAESAVX2 && tier >= TierVAESAVX2 {
		areion512InversePermutex4Avx2RC(&b0, &b1, &b2, &b3, rc4)
	} else if hasVEX && tier >= TierVEX {
		areion512InversePermutex4VexRC(&b0, &b1, &b2, &b3, rc4)
	} else {
		areion512InversePermutex4AesNiRC(&b0, &b1, &b2, &b3, rc4)
	}
	unpack512x4SoA(&b0, &b1, &b2, &b3, states)
	clear(b0[:])
	clear(b1[:])
	clear(b2[:])
	clear(b3[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&b2)
	runtime.KeepAlive(&b3)
	clobberScratchGPRs()
}

func areionSoEM256x4(keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		return soem256x4Software(keys, inputs)
	}

	var s1b0, s1b1, s2b0, s2b1 Block4
	for lane := 0; lane < 4; lane++ {

		xorBlock16(s1b0[lane*16:lane*16+16], inputs[lane][0:16], keys[lane][0:16])
		xorBlock16(s1b1[lane*16:lane*16+16], inputs[lane][16:32], keys[lane][16:32])

		xorBlock16(s2b0[lane*16:lane*16+16], inputs[lane][0:16], keys[lane][32:48])
		xorBlock16(s2b1[lane*16:lane*16+16], inputs[lane][16:32], keys[lane][48:64])
	}

	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256SoEMPermutex4Interleaved(&s1b0, &s1b1, &s2b0, &s2b1)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256SoEMPermutex4VaesAvx2(&s1b0, &s1b1, &s2b0, &s2b1)
	case hasVEX && tier >= TierVEX:
		areion256SoEMPermutex4Vex(&s1b0, &s1b1, &s2b0, &s2b1)
	default:
		areion256SoEMPermutex4AesNi(&s1b0, &s1b1, &s2b0, &s2b1)
	}

	var buf [4][32]byte
	for lane := 0; lane < 4; lane++ {

		xorBlock16_3(buf[lane][0:16], s1b0[lane*16:lane*16+16], keys[lane][0:16], keys[lane][32:48])
		xorBlock16_3(buf[lane][16:32], s1b1[lane*16:lane*16+16], keys[lane][16:32], keys[lane][48:64])
	}
	out := buf
	clear(buf[:])
	clear(s1b0[:])
	clear(s1b1[:])
	clear(s2b0[:])
	clear(s2b1[:])
	runtime.KeepAlive(&buf)
	runtime.KeepAlive(&s1b0)
	runtime.KeepAlive(&s1b1)
	runtime.KeepAlive(&s2b0)
	runtime.KeepAlive(&s2b1)
	clobberScratchGPRs()
	return out
}

func areionSoEM512x4(keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		return soem512x4Software(keys, inputs)
	}

	var a1, b1, c1, d1, a2, b2, c2, d2 Block4
	for lane := 0; lane < 4; lane++ {

		xorBlock16(a1[lane*16:lane*16+16], inputs[lane][0:16], keys[lane][0:16])
		xorBlock16(b1[lane*16:lane*16+16], inputs[lane][16:32], keys[lane][16:32])
		xorBlock16(c1[lane*16:lane*16+16], inputs[lane][32:48], keys[lane][32:48])
		xorBlock16(d1[lane*16:lane*16+16], inputs[lane][48:64], keys[lane][48:64])

		xorBlock16(a2[lane*16:lane*16+16], inputs[lane][0:16], keys[lane][64:80])
		xorBlock16(b2[lane*16:lane*16+16], inputs[lane][16:32], keys[lane][80:96])
		xorBlock16(c2[lane*16:lane*16+16], inputs[lane][32:48], keys[lane][96:112])
		xorBlock16(d2[lane*16:lane*16+16], inputs[lane][48:64], keys[lane][112:128])
	}

	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512SoEMPermutex4Interleaved(&a1, &b1, &c1, &d1, &a2, &b2, &c2, &d2)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512SoEMPermutex4VaesAvx2(&a1, &b1, &c1, &d1, &a2, &b2, &c2, &d2)
	case hasVEX && tier >= TierVEX:
		areion512SoEMPermutex4Vex(&a1, &b1, &c1, &d1, &a2, &b2, &c2, &d2)
	default:
		areion512SoEMPermutex4AesNi(&a1, &b1, &c1, &d1, &a2, &b2, &c2, &d2)
	}

	var buf [4][64]byte
	for lane := 0; lane < 4; lane++ {

		xorBlock16_3(buf[lane][0:16], a1[lane*16:lane*16+16], keys[lane][0:16], keys[lane][64:80])
		xorBlock16_3(buf[lane][16:32], b1[lane*16:lane*16+16], keys[lane][16:32], keys[lane][80:96])
		xorBlock16_3(buf[lane][32:48], c1[lane*16:lane*16+16], keys[lane][32:48], keys[lane][96:112])
		xorBlock16_3(buf[lane][48:64], d1[lane*16:lane*16+16], keys[lane][48:64], keys[lane][112:128])
	}
	out := buf
	clear(buf[:])
	clear(a1[:])
	clear(b1[:])
	clear(c1[:])
	clear(d1[:])
	clear(a2[:])
	clear(b2[:])
	clear(c2[:])
	clear(d2[:])
	runtime.KeepAlive(&buf)
	runtime.KeepAlive(&a1)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&c1)
	runtime.KeepAlive(&d1)
	runtime.KeepAlive(&a2)
	runtime.KeepAlive(&b2)
	runtime.KeepAlive(&c2)
	runtime.KeepAlive(&d2)
	clobberScratchGPRs()
	return out
}

func areion256Permutex4Block4(b0, b1 *Block4, rc4 *[15 * 64]byte, tier int32) {
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256Permutex4RC(b0, b1, rc4)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256Permutex4Avx2RC(b0, b1, rc4)
	case hasVEX && tier >= TierVEX:
		areion256Permutex4VexRC(b0, b1, rc4)
	default:
		areion256Permutex4AesNiRC(b0, b1, rc4)
	}
}

func areion256InversePermutex4Block4(b0, b1 *Block4, rc4 *[15 * 64]byte, tier int32) {
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256InversePermutex4RC(b0, b1, rc4)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256InversePermutex4Avx2RC(b0, b1, rc4)
	case hasVEX && tier >= TierVEX:
		areion256InversePermutex4VexRC(b0, b1, rc4)
	default:
		areion256InversePermutex4AesNiRC(b0, b1, rc4)
	}
}

func areion512Permutex4Block4(b0, b1, b2, b3 *Block4, rc4 *[15 * 64]byte, tier int32) {
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512Permutex4RC(b0, b1, b2, b3, rc4)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512Permutex4Avx2RC(b0, b1, b2, b3, rc4)
	case hasVEX && tier >= TierVEX:
		areion512Permutex4VexRC(b0, b1, b2, b3, rc4)
	default:
		areion512Permutex4AesNiRC(b0, b1, b2, b3, rc4)
	}
}

func areion512InversePermutex4Block4(b0, b1, b2, b3 *Block4, rc4 *[15 * 64]byte, tier int32) {
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512InversePermutex4RC(b0, b1, b2, b3, rc4)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512InversePermutex4Avx2RC(b0, b1, b2, b3, rc4)
	case hasVEX && tier >= TierVEX:
		areion512InversePermutex4VexRC(b0, b1, b2, b3, rc4)
	default:
		areion512InversePermutex4AesNiRC(b0, b1, b2, b3, rc4)
	}
}

func areionEMEncrypt256(out *[32]byte, m *[32]byte, k *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emEncrypt256Software(out, m, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256EMEncryptVEX(out, m, k)
	} else {
		areion256EMEncryptAESNI(out, m, k)
	}
	clobberScratchGPRs()
}

func areionEMDecrypt256(out *[32]byte, c *[32]byte, k *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emDecrypt256Software(out, c, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256EMDecryptVEX(out, c, k)
	} else {
		areion256EMDecryptAESNI(out, c, k)
	}
	clobberScratchGPRs()
}

func areionEMEncrypt512(out *[64]byte, m *[64]byte, k *[128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emEncrypt512Software(out, m, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512EMEncryptVEX(out, m, k)
	} else {
		areion512EMEncryptAESNI(out, m, k)
	}
	clobberScratchGPRs()
}

func areionEMDecrypt512(out *[64]byte, c *[64]byte, k *[128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emDecrypt512Software(out, c, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512EMDecryptVEX(out, c, k)
	} else {
		areion512EMDecryptAESNI(out, c, k)
	}
	clobberScratchGPRs()
}

func areionEM2Encrypt256(out *[32]byte, m *[32]byte, k *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Encrypt256Software(out, m, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256EM2EncryptVEX(out, m, k)
	} else {
		areion256EM2EncryptAESNI(out, m, k)
	}
	clobberScratchGPRs()
}

func areionEM2Decrypt256(out *[32]byte, c *[32]byte, k *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Decrypt256Software(out, c, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256EM2DecryptVEX(out, c, k)
	} else {
		areion256EM2DecryptAESNI(out, c, k)
	}
	clobberScratchGPRs()
}

func areionEM2Encrypt512(out *[64]byte, m *[64]byte, k *[128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Encrypt512Software(out, m, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512EM2EncryptVEX(out, m, k)
	} else {
		areion512EM2EncryptAESNI(out, m, k)
	}
	clobberScratchGPRs()
}

func areionEM2Decrypt512(out *[64]byte, c *[64]byte, k *[128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Decrypt512Software(out, c, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512EM2DecryptVEX(out, c, k)
	} else {
		areion512EM2DecryptAESNI(out, c, k)
	}
	clobberScratchGPRs()
}

func areionTEMEncrypt256(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temEncrypt256Software(out, m, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256TEMEncryptVEX(out, m, k, t)
	} else {
		areion256TEMEncryptAESNI(out, m, k, t)
	}
	clobberScratchGPRs()
}

func areionTEMDecrypt256(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temDecrypt256Software(out, c, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256TEMDecryptVEX(out, c, k, t)
	} else {
		areion256TEMDecryptAESNI(out, c, k, t)
	}
	clobberScratchGPRs()
}

func areionTEMEncrypt512(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temEncrypt512Software(out, m, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512TEMEncryptVEX(out, m, k, t)
	} else {
		areion512TEMEncryptAESNI(out, m, k, t)
	}
	clobberScratchGPRs()
}

func areionTEMDecrypt512(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temDecrypt512Software(out, c, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512TEMDecryptVEX(out, c, k, t)
	} else {
		areion512TEMDecryptAESNI(out, c, k, t)
	}
	clobberScratchGPRs()
}

func areionTEM2Encrypt256(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Encrypt256Software(out, m, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256TEM2EncryptVEX(out, m, k, t)
	} else {
		areion256TEM2EncryptAESNI(out, m, k, t)
	}
	clobberScratchGPRs()
}

func areionTEM2Decrypt256(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Decrypt256Software(out, c, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256TEM2DecryptVEX(out, c, k, t)
	} else {
		areion256TEM2DecryptAESNI(out, c, k, t)
	}
	clobberScratchGPRs()
}

func areionTEM2Encrypt512(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Encrypt512Software(out, m, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512TEM2EncryptVEX(out, m, k, t)
	} else {
		areion512TEM2EncryptAESNI(out, m, k, t)
	}
	clobberScratchGPRs()
}

func areionTEM2Decrypt512(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Decrypt512Software(out, c, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512TEM2DecryptVEX(out, c, k, t)
	} else {
		areion512TEM2DecryptAESNI(out, c, k, t)
	}
	clobberScratchGPRs()
}

func areionEMEncrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emEncrypt256x4Software(out, msgs, keys)
		return
	}
	var b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], keys[lane][0:16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], keys[lane][16:32])
	}
	areion256Permutex4Block4(&b0, &b1, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], keys[lane][32:48])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], keys[lane][48:64])
	}
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
}

func areionEMDecrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emDecrypt256x4Software(out, ct, keys)
		return
	}
	var b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(b0[lane*16:lane*16+16], ct[lane][0:16], keys[lane][32:48])
		xorBlock16(b1[lane*16:lane*16+16], ct[lane][16:32], keys[lane][48:64])
	}
	areion256InversePermutex4Block4(&b0, &b1, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], keys[lane][0:16])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], keys[lane][16:32])
	}
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
}

func areionEMEncrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emEncrypt512x4Software(out, msgs, keys)
		return
	}
	var b0, b1, b2, b3 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], keys[lane][0:16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], keys[lane][16:32])
		xorBlock16(b2[lane*16:lane*16+16], msgs[lane][32:48], keys[lane][32:48])
		xorBlock16(b3[lane*16:lane*16+16], msgs[lane][48:64], keys[lane][48:64])
	}
	areion512Permutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], keys[lane][64:80])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], keys[lane][80:96])
		xorBlock16(out[lane][32:48], b2[lane*16:lane*16+16], keys[lane][96:112])
		xorBlock16(out[lane][48:64], b3[lane*16:lane*16+16], keys[lane][112:128])
	}
	clear(b0[:])
	clear(b1[:])
	clear(b2[:])
	clear(b3[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&b2)
	runtime.KeepAlive(&b3)
	clobberScratchGPRs()
}

func areionEMDecrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emDecrypt512x4Software(out, ct, keys)
		return
	}
	var b0, b1, b2, b3 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(b0[lane*16:lane*16+16], ct[lane][0:16], keys[lane][64:80])
		xorBlock16(b1[lane*16:lane*16+16], ct[lane][16:32], keys[lane][80:96])
		xorBlock16(b2[lane*16:lane*16+16], ct[lane][32:48], keys[lane][96:112])
		xorBlock16(b3[lane*16:lane*16+16], ct[lane][48:64], keys[lane][112:128])
	}
	areion512InversePermutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], keys[lane][0:16])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], keys[lane][16:32])
		xorBlock16(out[lane][32:48], b2[lane*16:lane*16+16], keys[lane][32:48])
		xorBlock16(out[lane][48:64], b3[lane*16:lane*16+16], keys[lane][48:64])
	}
	clear(b0[:])
	clear(b1[:])
	clear(b2[:])
	clear(b3[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&b2)
	runtime.KeepAlive(&b3)
	clobberScratchGPRs()
}

func areionEM2Encrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Encrypt256x4Software(out, msgs, keys)
		return
	}
	var b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], keys[lane][0:16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], keys[lane][16:32])
	}
	areion256Permutex4Block4(&b0, &b1, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(b1[lane*16:lane*16+16], keys[lane][48:64])
	}
	areion256Permutex4Block4(&b0, &b1, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16_3(out[lane][0:16], b0[lane*16:lane*16+16], keys[lane][0:16], keys[lane][32:48])
		xorBlock16_3(out[lane][16:32], b1[lane*16:lane*16+16], keys[lane][16:32], keys[lane][48:64])
	}
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
}

func areionEM2Decrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Decrypt256x4Software(out, ct, keys)
		return
	}
	var b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16_3(b0[lane*16:lane*16+16], ct[lane][0:16], keys[lane][0:16], keys[lane][32:48])
		xorBlock16_3(b1[lane*16:lane*16+16], ct[lane][16:32], keys[lane][16:32], keys[lane][48:64])
	}
	areion256InversePermutex4Block4(&b0, &b1, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(b1[lane*16:lane*16+16], keys[lane][48:64])
	}
	areion256InversePermutex4Block4(&b0, &b1, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], keys[lane][0:16])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], keys[lane][16:32])
	}
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
}

func areionEM2Encrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Encrypt512x4Software(out, msgs, keys)
		return
	}
	var b0, b1, b2, b3 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], keys[lane][0:16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], keys[lane][16:32])
		xorBlock16(b2[lane*16:lane*16+16], msgs[lane][32:48], keys[lane][32:48])
		xorBlock16(b3[lane*16:lane*16+16], msgs[lane][48:64], keys[lane][48:64])
	}
	areion512Permutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], keys[lane][64:80])
		xorInto16(b1[lane*16:lane*16+16], keys[lane][80:96])
		xorInto16(b2[lane*16:lane*16+16], keys[lane][96:112])
		xorInto16(b3[lane*16:lane*16+16], keys[lane][112:128])
	}
	areion512Permutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16_3(out[lane][0:16], b0[lane*16:lane*16+16], keys[lane][0:16], keys[lane][64:80])
		xorBlock16_3(out[lane][16:32], b1[lane*16:lane*16+16], keys[lane][16:32], keys[lane][80:96])
		xorBlock16_3(out[lane][32:48], b2[lane*16:lane*16+16], keys[lane][32:48], keys[lane][96:112])
		xorBlock16_3(out[lane][48:64], b3[lane*16:lane*16+16], keys[lane][48:64], keys[lane][112:128])
	}
	clear(b0[:])
	clear(b1[:])
	clear(b2[:])
	clear(b3[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&b2)
	runtime.KeepAlive(&b3)
	clobberScratchGPRs()
}

func areionEM2Decrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Decrypt512x4Software(out, ct, keys)
		return
	}
	var b0, b1, b2, b3 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16_3(b0[lane*16:lane*16+16], ct[lane][0:16], keys[lane][0:16], keys[lane][64:80])
		xorBlock16_3(b1[lane*16:lane*16+16], ct[lane][16:32], keys[lane][16:32], keys[lane][80:96])
		xorBlock16_3(b2[lane*16:lane*16+16], ct[lane][32:48], keys[lane][32:48], keys[lane][96:112])
		xorBlock16_3(b3[lane*16:lane*16+16], ct[lane][48:64], keys[lane][48:64], keys[lane][112:128])
	}
	areion512InversePermutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], keys[lane][64:80])
		xorInto16(b1[lane*16:lane*16+16], keys[lane][80:96])
		xorInto16(b2[lane*16:lane*16+16], keys[lane][96:112])
		xorInto16(b3[lane*16:lane*16+16], keys[lane][112:128])
	}
	areion512InversePermutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], keys[lane][0:16])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], keys[lane][16:32])
		xorBlock16(out[lane][32:48], b2[lane*16:lane*16+16], keys[lane][32:48])
		xorBlock16(out[lane][48:64], b3[lane*16:lane*16+16], keys[lane][48:64])
	}
	clear(b0[:])
	clear(b1[:])
	clear(b2[:])
	clear(b3[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&b2)
	runtime.KeepAlive(&b3)
	clobberScratchGPRs()
}

func areionTEMEncrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temEncrypt256x4Software(out, msgs, keys, tweaks)
		return
	}
	var w0, w1, b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(w0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][32:48])
		xorBlock16(w1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][48:64])
	}
	areion256Permutex4Block4(&w0, &w1, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1[lane*16:lane*16+16], keys[lane][16:32])
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], w0[lane*16:lane*16+16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], w1[lane*16:lane*16+16])
	}
	areion256Permutex4Block4(&b0, &b1, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], w0[lane*16:lane*16+16])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], w1[lane*16:lane*16+16])
	}
	clear(w0[:])
	clear(w1[:])
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&w0)
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
}

func areionTEMDecrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temDecrypt256x4Software(out, ct, keys, tweaks)
		return
	}
	var w0, w1, b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(w0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][32:48])
		xorBlock16(w1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][48:64])
	}
	areion256Permutex4Block4(&w0, &w1, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1[lane*16:lane*16+16], keys[lane][16:32])
		xorBlock16(b0[lane*16:lane*16+16], ct[lane][0:16], w0[lane*16:lane*16+16])
		xorBlock16(b1[lane*16:lane*16+16], ct[lane][16:32], w1[lane*16:lane*16+16])
	}
	areion256InversePermutex4Block4(&b0, &b1, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], w0[lane*16:lane*16+16])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], w1[lane*16:lane*16+16])
	}
	clear(w0[:])
	clear(w1[:])
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&w0)
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
}

func areionTEMEncrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temEncrypt512x4Software(out, msgs, keys, tweaks)
		return
	}
	var w0, w1, w2, w3, b0, b1, b2, b3 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(w0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][64:80])
		xorBlock16(w1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][80:96])
		xorBlock16(w2[lane*16:lane*16+16], tweaks[lane][32:48], keys[lane][96:112])
		xorBlock16(w3[lane*16:lane*16+16], tweaks[lane][48:64], keys[lane][112:128])
	}
	areion512Permutex4Block4(&w0, &w1, &w2, &w3, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1[lane*16:lane*16+16], keys[lane][16:32])
		xorInto16(w2[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(w3[lane*16:lane*16+16], keys[lane][48:64])
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], w0[lane*16:lane*16+16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], w1[lane*16:lane*16+16])
		xorBlock16(b2[lane*16:lane*16+16], msgs[lane][32:48], w2[lane*16:lane*16+16])
		xorBlock16(b3[lane*16:lane*16+16], msgs[lane][48:64], w3[lane*16:lane*16+16])
	}
	areion512Permutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], w0[lane*16:lane*16+16])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], w1[lane*16:lane*16+16])
		xorBlock16(out[lane][32:48], b2[lane*16:lane*16+16], w2[lane*16:lane*16+16])
		xorBlock16(out[lane][48:64], b3[lane*16:lane*16+16], w3[lane*16:lane*16+16])
	}
	clear(w0[:])
	clear(w1[:])
	clear(w2[:])
	clear(w3[:])
	clear(b0[:])
	clear(b1[:])
	clear(b2[:])
	clear(b3[:])
	runtime.KeepAlive(&w0)
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&w2)
	runtime.KeepAlive(&w3)
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&b2)
	runtime.KeepAlive(&b3)
	clobberScratchGPRs()
}

func areionTEMDecrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temDecrypt512x4Software(out, ct, keys, tweaks)
		return
	}
	var w0, w1, w2, w3, b0, b1, b2, b3 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(w0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][64:80])
		xorBlock16(w1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][80:96])
		xorBlock16(w2[lane*16:lane*16+16], tweaks[lane][32:48], keys[lane][96:112])
		xorBlock16(w3[lane*16:lane*16+16], tweaks[lane][48:64], keys[lane][112:128])
	}
	areion512Permutex4Block4(&w0, &w1, &w2, &w3, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1[lane*16:lane*16+16], keys[lane][16:32])
		xorInto16(w2[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(w3[lane*16:lane*16+16], keys[lane][48:64])
		xorBlock16(b0[lane*16:lane*16+16], ct[lane][0:16], w0[lane*16:lane*16+16])
		xorBlock16(b1[lane*16:lane*16+16], ct[lane][16:32], w1[lane*16:lane*16+16])
		xorBlock16(b2[lane*16:lane*16+16], ct[lane][32:48], w2[lane*16:lane*16+16])
		xorBlock16(b3[lane*16:lane*16+16], ct[lane][48:64], w3[lane*16:lane*16+16])
	}
	areion512InversePermutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], w0[lane*16:lane*16+16])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], w1[lane*16:lane*16+16])
		xorBlock16(out[lane][32:48], b2[lane*16:lane*16+16], w2[lane*16:lane*16+16])
		xorBlock16(out[lane][48:64], b3[lane*16:lane*16+16], w3[lane*16:lane*16+16])
	}
	clear(w0[:])
	clear(w1[:])
	clear(w2[:])
	clear(w3[:])
	clear(b0[:])
	clear(b1[:])
	clear(b2[:])
	clear(b3[:])
	runtime.KeepAlive(&w0)
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&w2)
	runtime.KeepAlive(&w3)
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&b2)
	runtime.KeepAlive(&b3)
	clobberScratchGPRs()
}

func areionTEM2Encrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Encrypt256x4Software(out, msgs, keys, tweaks)
		return
	}
	var w1b0, w1b1, w2b0, w2b1, b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(w1b0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][0:16])
		xorBlock16(w1b1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][16:32])
		xorBlock16(w2b0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][32:48])
		xorBlock16(w2b1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][48:64])
	}
	areion256Permutex4Block4(&w1b0, &w1b1, &areionRC4x, tier)
	areion256Permutex4Block4(&w2b0, &w2b1, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w1b0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1b1[lane*16:lane*16+16], keys[lane][16:32])
		xorInto16(w2b0[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(w2b1[lane*16:lane*16+16], keys[lane][48:64])
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], w1b0[lane*16:lane*16+16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], w1b1[lane*16:lane*16+16])
	}
	areion256Permutex4Block4(&b0, &b1, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorInto16(b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
	}
	areion256Permutex4Block4(&b0, &b1, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16_3(out[lane][0:16], b0[lane*16:lane*16+16], w1b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorBlock16_3(out[lane][16:32], b1[lane*16:lane*16+16], w1b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
	}
	clear(w1b0[:])
	clear(w1b1[:])
	clear(w2b0[:])
	clear(w2b1[:])
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&w1b0)
	runtime.KeepAlive(&w1b1)
	runtime.KeepAlive(&w2b0)
	runtime.KeepAlive(&w2b1)
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
}

func areionTEM2Decrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Decrypt256x4Software(out, ct, keys, tweaks)
		return
	}
	var w1b0, w1b1, w2b0, w2b1, b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(w1b0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][0:16])
		xorBlock16(w1b1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][16:32])
		xorBlock16(w2b0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][32:48])
		xorBlock16(w2b1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][48:64])
	}
	areion256Permutex4Block4(&w1b0, &w1b1, &areionRC4x, tier)
	areion256Permutex4Block4(&w2b0, &w2b1, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w1b0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1b1[lane*16:lane*16+16], keys[lane][16:32])
		xorInto16(w2b0[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(w2b1[lane*16:lane*16+16], keys[lane][48:64])
		xorBlock16_3(b0[lane*16:lane*16+16], ct[lane][0:16], w1b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorBlock16_3(b1[lane*16:lane*16+16], ct[lane][16:32], w1b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
	}
	areion256InversePermutex4Block4(&b0, &b1, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorInto16(b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
	}
	areion256InversePermutex4Block4(&b0, &b1, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], w1b0[lane*16:lane*16+16])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], w1b1[lane*16:lane*16+16])
	}
	clear(w1b0[:])
	clear(w1b1[:])
	clear(w2b0[:])
	clear(w2b1[:])
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&w1b0)
	runtime.KeepAlive(&w1b1)
	runtime.KeepAlive(&w2b0)
	runtime.KeepAlive(&w2b1)
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
}

func areionTEM2Encrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Encrypt512x4Software(out, msgs, keys, tweaks)
		return
	}
	var w1b0, w1b1, w1b2, w1b3, w2b0, w2b1, w2b2, w2b3, b0, b1, b2, b3 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(w1b0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][0:16])
		xorBlock16(w1b1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][16:32])
		xorBlock16(w1b2[lane*16:lane*16+16], tweaks[lane][32:48], keys[lane][32:48])
		xorBlock16(w1b3[lane*16:lane*16+16], tweaks[lane][48:64], keys[lane][48:64])
		xorBlock16(w2b0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][64:80])
		xorBlock16(w2b1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][80:96])
		xorBlock16(w2b2[lane*16:lane*16+16], tweaks[lane][32:48], keys[lane][96:112])
		xorBlock16(w2b3[lane*16:lane*16+16], tweaks[lane][48:64], keys[lane][112:128])
	}
	areion512Permutex4Block4(&w1b0, &w1b1, &w1b2, &w1b3, &areionRC4x, tier)
	areion512Permutex4Block4(&w2b0, &w2b1, &w2b2, &w2b3, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w1b0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1b1[lane*16:lane*16+16], keys[lane][16:32])
		xorInto16(w1b2[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(w1b3[lane*16:lane*16+16], keys[lane][48:64])
		xorInto16(w2b0[lane*16:lane*16+16], keys[lane][64:80])
		xorInto16(w2b1[lane*16:lane*16+16], keys[lane][80:96])
		xorInto16(w2b2[lane*16:lane*16+16], keys[lane][96:112])
		xorInto16(w2b3[lane*16:lane*16+16], keys[lane][112:128])
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], w1b0[lane*16:lane*16+16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], w1b1[lane*16:lane*16+16])
		xorBlock16(b2[lane*16:lane*16+16], msgs[lane][32:48], w1b2[lane*16:lane*16+16])
		xorBlock16(b3[lane*16:lane*16+16], msgs[lane][48:64], w1b3[lane*16:lane*16+16])
	}
	areion512Permutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorInto16(b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
		xorInto16(b2[lane*16:lane*16+16], w2b2[lane*16:lane*16+16])
		xorInto16(b3[lane*16:lane*16+16], w2b3[lane*16:lane*16+16])
	}
	areion512Permutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16_3(out[lane][0:16], b0[lane*16:lane*16+16], w1b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorBlock16_3(out[lane][16:32], b1[lane*16:lane*16+16], w1b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
		xorBlock16_3(out[lane][32:48], b2[lane*16:lane*16+16], w1b2[lane*16:lane*16+16], w2b2[lane*16:lane*16+16])
		xorBlock16_3(out[lane][48:64], b3[lane*16:lane*16+16], w1b3[lane*16:lane*16+16], w2b3[lane*16:lane*16+16])
	}
	clear(w1b0[:])
	clear(w1b1[:])
	clear(w1b2[:])
	clear(w1b3[:])
	clear(w2b0[:])
	clear(w2b1[:])
	clear(w2b2[:])
	clear(w2b3[:])
	clear(b0[:])
	clear(b1[:])
	clear(b2[:])
	clear(b3[:])
	runtime.KeepAlive(&w1b0)
	runtime.KeepAlive(&w1b1)
	runtime.KeepAlive(&w1b2)
	runtime.KeepAlive(&w1b3)
	runtime.KeepAlive(&w2b0)
	runtime.KeepAlive(&w2b1)
	runtime.KeepAlive(&w2b2)
	runtime.KeepAlive(&w2b3)
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&b2)
	runtime.KeepAlive(&b3)
	clobberScratchGPRs()
}

func areionTEM2Decrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Decrypt512x4Software(out, ct, keys, tweaks)
		return
	}
	var w1b0, w1b1, w1b2, w1b3, w2b0, w2b1, w2b2, w2b3, b0, b1, b2, b3 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(w1b0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][0:16])
		xorBlock16(w1b1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][16:32])
		xorBlock16(w1b2[lane*16:lane*16+16], tweaks[lane][32:48], keys[lane][32:48])
		xorBlock16(w1b3[lane*16:lane*16+16], tweaks[lane][48:64], keys[lane][48:64])
		xorBlock16(w2b0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][64:80])
		xorBlock16(w2b1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][80:96])
		xorBlock16(w2b2[lane*16:lane*16+16], tweaks[lane][32:48], keys[lane][96:112])
		xorBlock16(w2b3[lane*16:lane*16+16], tweaks[lane][48:64], keys[lane][112:128])
	}
	areion512Permutex4Block4(&w1b0, &w1b1, &w1b2, &w1b3, &areionRC4x, tier)
	areion512Permutex4Block4(&w2b0, &w2b1, &w2b2, &w2b3, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w1b0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1b1[lane*16:lane*16+16], keys[lane][16:32])
		xorInto16(w1b2[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(w1b3[lane*16:lane*16+16], keys[lane][48:64])
		xorInto16(w2b0[lane*16:lane*16+16], keys[lane][64:80])
		xorInto16(w2b1[lane*16:lane*16+16], keys[lane][80:96])
		xorInto16(w2b2[lane*16:lane*16+16], keys[lane][96:112])
		xorInto16(w2b3[lane*16:lane*16+16], keys[lane][112:128])
		xorBlock16_3(b0[lane*16:lane*16+16], ct[lane][0:16], w1b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorBlock16_3(b1[lane*16:lane*16+16], ct[lane][16:32], w1b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
		xorBlock16_3(b2[lane*16:lane*16+16], ct[lane][32:48], w1b2[lane*16:lane*16+16], w2b2[lane*16:lane*16+16])
		xorBlock16_3(b3[lane*16:lane*16+16], ct[lane][48:64], w1b3[lane*16:lane*16+16], w2b3[lane*16:lane*16+16])
	}
	areion512InversePermutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x2, tier)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorInto16(b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
		xorInto16(b2[lane*16:lane*16+16], w2b2[lane*16:lane*16+16])
		xorInto16(b3[lane*16:lane*16+16], w2b3[lane*16:lane*16+16])
	}
	areion512InversePermutex4Block4(&b0, &b1, &b2, &b3, &areionRC4x, tier)
	for lane := 0; lane < 4; lane++ {
		xorBlock16(out[lane][0:16], b0[lane*16:lane*16+16], w1b0[lane*16:lane*16+16])
		xorBlock16(out[lane][16:32], b1[lane*16:lane*16+16], w1b1[lane*16:lane*16+16])
		xorBlock16(out[lane][32:48], b2[lane*16:lane*16+16], w1b2[lane*16:lane*16+16])
		xorBlock16(out[lane][48:64], b3[lane*16:lane*16+16], w1b3[lane*16:lane*16+16])
	}
	clear(w1b0[:])
	clear(w1b1[:])
	clear(w1b2[:])
	clear(w1b3[:])
	clear(w2b0[:])
	clear(w2b1[:])
	clear(w2b2[:])
	clear(w2b3[:])
	clear(b0[:])
	clear(b1[:])
	clear(b2[:])
	clear(b3[:])
	runtime.KeepAlive(&w1b0)
	runtime.KeepAlive(&w1b1)
	runtime.KeepAlive(&w1b2)
	runtime.KeepAlive(&w1b3)
	runtime.KeepAlive(&w2b0)
	runtime.KeepAlive(&w2b1)
	runtime.KeepAlive(&w2b2)
	runtime.KeepAlive(&w2b3)
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&b2)
	runtime.KeepAlive(&b3)
	clobberScratchGPRs()
}

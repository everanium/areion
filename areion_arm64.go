//go:build arm64 && !purego

package areion

import (
	"runtime"
)

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
func areion256Permutex4RC(x0, x1 *Block4, rc *[15][16]byte)

//go:noescape
func areion256InversePermutex4RC(x0, x1 *Block4, rc *[15][16]byte)

//go:noescape
func areion512Permutex4RC(x0, x1, x2, x3 *Block4, rc *[15][16]byte)

//go:noescape
func areion512InversePermutex4RC(x0, x1, x2, x3 *Block4, rc *[15][16]byte)

//go:noescape
func areion256SoEMPermutex4NEON(s1b0, s1b1, s2b0, s2b1 *Block4)

//go:noescape
func areion512SoEMPermutex4NEON(a1, b1, c1, d1, a2, b2, c2, d2 *Block4)

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

func areionSoEM256(key *[64]byte, m *[32]byte) [32]byte {
	if !hasARMCrypto || TierCode() == TierPureGo {
		return soem256Software(key, m)
	}
	var buf [32]byte
	areionSoEM256Asm(&buf, key, m)
	out := buf
	clear(buf[:])
	runtime.KeepAlive(&buf)
	clobberScratchGPRs()
	return out
}

func areionSoEM512(key *[128]byte, m *[64]byte) [64]byte {
	if !hasARMCrypto || TierCode() == TierPureGo {
		return soem512Software(key, m)
	}
	var buf [64]byte
	areionSoEM512Asm(&buf, key, m)
	out := buf
	clear(buf[:])
	runtime.KeepAlive(&buf)
	clobberScratchGPRs()
	return out
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
	var b0, b1 Block4
	pack256x4SoAInto(states, &b0, &b1)
	areion256Permutex4RC(&b0, &b1, rc)
	unpack256x4SoA(&b0, &b1, states)
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
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
	var b0, b1 Block4
	pack256x4SoAInto(states, &b0, &b1)
	areion256InversePermutex4RC(&b0, &b1, rc)
	unpack256x4SoA(&b0, &b1, states)
	clear(b0[:])
	clear(b1[:])
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	clobberScratchGPRs()
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
	var b0, b1, b2, b3 Block4
	pack512x4SoAInto(states, &b0, &b1, &b2, &b3)
	areion512Permutex4RC(&b0, &b1, &b2, &b3, rc)
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
	var b0, b1, b2, b3 Block4
	pack512x4SoAInto(states, &b0, &b1, &b2, &b3)
	areion512InversePermutex4RC(&b0, &b1, &b2, &b3, rc)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
		return soem256x4Software(keys, inputs)
	}

	var s1b0, s1b1, s2b0, s2b1 Block4
	for lane := 0; lane < 4; lane++ {

		xorBlock16(s1b0[lane*16:lane*16+16], inputs[lane][0:16], keys[lane][0:16])
		xorBlock16(s1b1[lane*16:lane*16+16], inputs[lane][16:32], keys[lane][16:32])

		xorBlock16(s2b0[lane*16:lane*16+16], inputs[lane][0:16], keys[lane][32:48])
		xorBlock16(s2b1[lane*16:lane*16+16], inputs[lane][16:32], keys[lane][48:64])
	}

	areion256SoEMPermutex4NEON(&s1b0, &s1b1, &s2b0, &s2b1)

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
	if !hasARMCrypto || TierCode() == TierPureGo {
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

	areion512SoEMPermutex4NEON(&a1, &b1, &c1, &d1, &a2, &b2, &c2, &d2)

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

func areionEMEncrypt256(out *[32]byte, m *[32]byte, k *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emEncrypt256Software(out, m, k)
		return
	}
	areion256EMEncryptAsm(out, m, k)
	clobberScratchGPRs()
}

func areionEMDecrypt256(out *[32]byte, c *[32]byte, k *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emDecrypt256Software(out, c, k)
		return
	}
	areion256EMDecryptAsm(out, c, k)
	clobberScratchGPRs()
}

func areionEMEncrypt512(out *[64]byte, m *[64]byte, k *[128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emEncrypt512Software(out, m, k)
		return
	}
	areion512EMEncryptAsm(out, m, k)
	clobberScratchGPRs()
}

func areionEMDecrypt512(out *[64]byte, c *[64]byte, k *[128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emDecrypt512Software(out, c, k)
		return
	}
	areion512EMDecryptAsm(out, c, k)
	clobberScratchGPRs()
}

func areionEM2Encrypt256(out *[32]byte, m *[32]byte, k *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Encrypt256Software(out, m, k)
		return
	}
	areion256EM2EncryptAsm(out, m, k)
	clobberScratchGPRs()
}

func areionEM2Decrypt256(out *[32]byte, c *[32]byte, k *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Decrypt256Software(out, c, k)
		return
	}
	areion256EM2DecryptAsm(out, c, k)
	clobberScratchGPRs()
}

func areionEM2Encrypt512(out *[64]byte, m *[64]byte, k *[128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Encrypt512Software(out, m, k)
		return
	}
	areion512EM2EncryptAsm(out, m, k)
	clobberScratchGPRs()
}

func areionEM2Decrypt512(out *[64]byte, c *[64]byte, k *[128]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Decrypt512Software(out, c, k)
		return
	}
	areion512EM2DecryptAsm(out, c, k)
	clobberScratchGPRs()
}

func areionTEMEncrypt256(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temEncrypt256Software(out, m, k, t)
		return
	}
	areion256TEMEncryptAsm(out, m, k, t)
	clobberScratchGPRs()
}

func areionTEMDecrypt256(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temDecrypt256Software(out, c, k, t)
		return
	}
	areion256TEMDecryptAsm(out, c, k, t)
	clobberScratchGPRs()
}

func areionTEMEncrypt512(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temEncrypt512Software(out, m, k, t)
		return
	}
	areion512TEMEncryptAsm(out, m, k, t)
	clobberScratchGPRs()
}

func areionTEMDecrypt512(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		temDecrypt512Software(out, c, k, t)
		return
	}
	areion512TEMDecryptAsm(out, c, k, t)
	clobberScratchGPRs()
}

func areionTEM2Encrypt256(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Encrypt256Software(out, m, k, t)
		return
	}
	areion256TEM2EncryptAsm(out, m, k, t)
	clobberScratchGPRs()
}

func areionTEM2Decrypt256(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Decrypt256Software(out, c, k, t)
		return
	}
	areion256TEM2DecryptAsm(out, c, k, t)
	clobberScratchGPRs()
}

func areionTEM2Encrypt512(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Encrypt512Software(out, m, k, t)
		return
	}
	areion512TEM2EncryptAsm(out, m, k, t)
	clobberScratchGPRs()
}

func areionTEM2Decrypt512(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		tem2Decrypt512Software(out, c, k, t)
		return
	}
	areion512TEM2DecryptAsm(out, c, k, t)
	clobberScratchGPRs()
}

func areionEMEncrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte) {
	if !hasARMCrypto || TierCode() == TierPureGo {
		emEncrypt256x4Software(out, msgs, keys)
		return
	}
	var b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], keys[lane][0:16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], keys[lane][16:32])
	}
	areion256Permutex4RC(&b0, &b1, &roundConstantsP1)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
		emDecrypt256x4Software(out, ct, keys)
		return
	}
	var b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(b0[lane*16:lane*16+16], ct[lane][0:16], keys[lane][32:48])
		xorBlock16(b1[lane*16:lane*16+16], ct[lane][16:32], keys[lane][48:64])
	}
	areion256InversePermutex4RC(&b0, &b1, &roundConstantsP1)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	areion512Permutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP1)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	areion512InversePermutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP1)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Encrypt256x4Software(out, msgs, keys)
		return
	}
	var b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], keys[lane][0:16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], keys[lane][16:32])
	}
	areion256Permutex4RC(&b0, &b1, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(b1[lane*16:lane*16+16], keys[lane][48:64])
	}
	areion256Permutex4RC(&b0, &b1, &roundConstantsP2)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
		em2Decrypt256x4Software(out, ct, keys)
		return
	}
	var b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16_3(b0[lane*16:lane*16+16], ct[lane][0:16], keys[lane][0:16], keys[lane][32:48])
		xorBlock16_3(b1[lane*16:lane*16+16], ct[lane][16:32], keys[lane][16:32], keys[lane][48:64])
	}
	areion256InversePermutex4RC(&b0, &b1, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(b1[lane*16:lane*16+16], keys[lane][48:64])
	}
	areion256InversePermutex4RC(&b0, &b1, &roundConstantsP1)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	areion512Permutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], keys[lane][64:80])
		xorInto16(b1[lane*16:lane*16+16], keys[lane][80:96])
		xorInto16(b2[lane*16:lane*16+16], keys[lane][96:112])
		xorInto16(b3[lane*16:lane*16+16], keys[lane][112:128])
	}
	areion512Permutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP2)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	areion512InversePermutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], keys[lane][64:80])
		xorInto16(b1[lane*16:lane*16+16], keys[lane][80:96])
		xorInto16(b2[lane*16:lane*16+16], keys[lane][96:112])
		xorInto16(b3[lane*16:lane*16+16], keys[lane][112:128])
	}
	areion512InversePermutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP1)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
		temEncrypt256x4Software(out, msgs, keys, tweaks)
		return
	}
	var w0, w1, b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(w0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][32:48])
		xorBlock16(w1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][48:64])
	}
	areion256Permutex4RC(&w0, &w1, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1[lane*16:lane*16+16], keys[lane][16:32])
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], w0[lane*16:lane*16+16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], w1[lane*16:lane*16+16])
	}
	areion256Permutex4RC(&b0, &b1, &roundConstantsP1)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
		temDecrypt256x4Software(out, ct, keys, tweaks)
		return
	}
	var w0, w1, b0, b1 Block4
	for lane := 0; lane < 4; lane++ {
		xorBlock16(w0[lane*16:lane*16+16], tweaks[lane][0:16], keys[lane][32:48])
		xorBlock16(w1[lane*16:lane*16+16], tweaks[lane][16:32], keys[lane][48:64])
	}
	areion256Permutex4RC(&w0, &w1, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1[lane*16:lane*16+16], keys[lane][16:32])
		xorBlock16(b0[lane*16:lane*16+16], ct[lane][0:16], w0[lane*16:lane*16+16])
		xorBlock16(b1[lane*16:lane*16+16], ct[lane][16:32], w1[lane*16:lane*16+16])
	}
	areion256InversePermutex4RC(&b0, &b1, &roundConstantsP1)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	areion512Permutex4RC(&w0, &w1, &w2, &w3, &roundConstantsP2)
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
	areion512Permutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP1)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	areion512Permutex4RC(&w0, &w1, &w2, &w3, &roundConstantsP2)
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
	areion512InversePermutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP1)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	areion256Permutex4RC(&w1b0, &w1b1, &roundConstantsP1)
	areion256Permutex4RC(&w2b0, &w2b1, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w1b0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1b1[lane*16:lane*16+16], keys[lane][16:32])
		xorInto16(w2b0[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(w2b1[lane*16:lane*16+16], keys[lane][48:64])
		xorBlock16(b0[lane*16:lane*16+16], msgs[lane][0:16], w1b0[lane*16:lane*16+16])
		xorBlock16(b1[lane*16:lane*16+16], msgs[lane][16:32], w1b1[lane*16:lane*16+16])
	}
	areion256Permutex4RC(&b0, &b1, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorInto16(b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
	}
	areion256Permutex4RC(&b0, &b1, &roundConstantsP2)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	areion256Permutex4RC(&w1b0, &w1b1, &roundConstantsP1)
	areion256Permutex4RC(&w2b0, &w2b1, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		xorInto16(w1b0[lane*16:lane*16+16], keys[lane][0:16])
		xorInto16(w1b1[lane*16:lane*16+16], keys[lane][16:32])
		xorInto16(w2b0[lane*16:lane*16+16], keys[lane][32:48])
		xorInto16(w2b1[lane*16:lane*16+16], keys[lane][48:64])
		xorBlock16_3(b0[lane*16:lane*16+16], ct[lane][0:16], w1b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorBlock16_3(b1[lane*16:lane*16+16], ct[lane][16:32], w1b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
	}
	areion256InversePermutex4RC(&b0, &b1, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorInto16(b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
	}
	areion256InversePermutex4RC(&b0, &b1, &roundConstantsP1)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	areion512Permutex4RC(&w1b0, &w1b1, &w1b2, &w1b3, &roundConstantsP1)
	areion512Permutex4RC(&w2b0, &w2b1, &w2b2, &w2b3, &roundConstantsP2)
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
	areion512Permutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorInto16(b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
		xorInto16(b2[lane*16:lane*16+16], w2b2[lane*16:lane*16+16])
		xorInto16(b3[lane*16:lane*16+16], w2b3[lane*16:lane*16+16])
	}
	areion512Permutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP2)
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
	if !hasARMCrypto || TierCode() == TierPureGo {
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
	areion512Permutex4RC(&w1b0, &w1b1, &w1b2, &w1b3, &roundConstantsP1)
	areion512Permutex4RC(&w2b0, &w2b1, &w2b2, &w2b3, &roundConstantsP2)
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
	areion512InversePermutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		xorInto16(b0[lane*16:lane*16+16], w2b0[lane*16:lane*16+16])
		xorInto16(b1[lane*16:lane*16+16], w2b1[lane*16:lane*16+16])
		xorInto16(b2[lane*16:lane*16+16], w2b2[lane*16:lane*16+16])
		xorInto16(b3[lane*16:lane*16+16], w2b3[lane*16:lane*16+16])
	}
	areion512InversePermutex4RC(&b0, &b1, &b2, &b3, &roundConstantsP1)
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

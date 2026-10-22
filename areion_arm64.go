//go:build arm64 && !purego

package areion

import (
	"runtime"
	"unsafe"
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

	areion256SoEMPermutex4NEON(&s1b0, &s1b1, &s2b0, &s2b1)

	var buf [4][32]byte
	for lane := 0; lane < 4; lane++ {
		s1b0U64 := (*[2]uint64)(unsafe.Pointer(&s1b0[lane*16]))
		s1b1U64 := (*[2]uint64)(unsafe.Pointer(&s1b1[lane*16]))
		outU64 := (*[4]uint64)(unsafe.Pointer(&buf[lane]))
		k := &keysU64[lane]

		outU64[0] = s1b0U64[0] ^ k[0] ^ k[4]
		outU64[1] = s1b0U64[1] ^ k[1] ^ k[5]
		outU64[2] = s1b1U64[0] ^ k[2] ^ k[6]
		outU64[3] = s1b1U64[1] ^ k[3] ^ k[7]
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

	areion512SoEMPermutex4NEON(&a1, &b1, &c1, &d1, &a2, &b2, &c2, &d2)

	var buf [4][64]byte
	for lane := 0; lane < 4; lane++ {
		a1U64 := (*[2]uint64)(unsafe.Pointer(&a1[lane*16]))
		b1U64 := (*[2]uint64)(unsafe.Pointer(&b1[lane*16]))
		c1U64 := (*[2]uint64)(unsafe.Pointer(&c1[lane*16]))
		d1U64 := (*[2]uint64)(unsafe.Pointer(&d1[lane*16]))
		outU64 := (*[8]uint64)(unsafe.Pointer(&buf[lane]))
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

package areion

import "encoding/binary"

func asuraXorBlock3(dst, a, b, c *Block) {
	lo := binary.LittleEndian.Uint64(a[0:8]) ^ binary.LittleEndian.Uint64(b[0:8]) ^ binary.LittleEndian.Uint64(c[0:8])
	hi := binary.LittleEndian.Uint64(a[8:16]) ^ binary.LittleEndian.Uint64(b[8:16]) ^ binary.LittleEndian.Uint64(c[8:16])
	binary.LittleEndian.PutUint64(dst[0:8], lo)
	binary.LittleEndian.PutUint64(dst[8:16], hi)
}

func asuraXorBlock4(dst, a, b, c, d *Block) {
	lo := binary.LittleEndian.Uint64(a[0:8]) ^ binary.LittleEndian.Uint64(b[0:8]) ^
		binary.LittleEndian.Uint64(c[0:8]) ^ binary.LittleEndian.Uint64(d[0:8])
	hi := binary.LittleEndian.Uint64(a[8:16]) ^ binary.LittleEndian.Uint64(b[8:16]) ^
		binary.LittleEndian.Uint64(c[8:16]) ^ binary.LittleEndian.Uint64(d[8:16])
	binary.LittleEndian.PutUint64(dst[0:8], lo)
	binary.LittleEndian.PutUint64(dst[8:16], hi)
}

func asuraGFMul2Byte(b byte) byte {
	return (b << 1) ^ (((b >> 7) & 1) * 0x1b)
}

func asuraGFDiv2Byte(b byte) byte {
	return (b >> 1) ^ ((b & 1) * 0x8d)
}

func asuraKappaSoftware(k *[32]byte) {
	var next [32]byte
	for i := 0; i < 32; i++ {
		next[i] = asuraGFMul2Byte(k[asuraKappaPerm[i]])
	}
	*k = next
}

func asuraInvKappaSoftware(k *[32]byte) {
	var prev [32]byte
	for i := 0; i < 32; i++ {
		prev[i] = asuraGFDiv2Byte(k[asuraInvKappaPerm[i]])
	}
	*k = prev
}

func asuraPerm256(x0, x1 *Block) {
	var m0, m1 Block
	for i := 0; i < 8; i++ {
		m0[i] = x0[2*i]
		m0[8+i] = x1[2*i]
		m1[i] = x0[2*i+1]
		m1[8+i] = x1[2*i+1]
	}
	*x0 = m0
	*x1 = m1
}

func asuraInvPerm256(x0, x1 *Block) {
	var m0, m1 Block
	for i := 0; i < 8; i++ {
		m0[2*i] = x0[i]
		m0[2*i+1] = x1[i]
		m1[2*i] = x0[8+i]
		m1[2*i+1] = x1[8+i]
	}
	*x0 = m0
	*x1 = m1
}

func asuraExpandTweakeyCore(rtk *[13][32]byte, key *[32]byte, tweak *[16]byte) {
	var k [32]byte
	var t Block
	var qT bsState
	k = *key
	t = *tweak
	asuraXorBlock3((*Block)(rtk[0][0:16]), &t, (*Block)(k[0:16]), &asuraRoundConstants[0])
	xorBlock((*Block)(rtk[0][16:32]), &t, (*Block)(k[16:32]))

	bsPack1(&qT, &t)
	for r := 1; r < 13; r++ {
		bsRoundNoKey(&qT)
		bsUnpack1(&qT, &t)
		asuraKappaSoftware(&k)
		asuraXorBlock3((*Block)(rtk[r][0:16]), &t, (*Block)(k[0:16]), &asuraRoundConstants[r])
		xorBlock((*Block)(rtk[r][16:32]), &t, (*Block)(k[16:32]))
	}
}

//go:noinline
func asuraExpandTweakeySoftBody(rtk *[13][32]byte, key *[32]byte, tweak *[16]byte) {
	asuraExpandTweakeyCore(rtk, key, tweak)
}

func asuraExpandTweakeySoft(rtk *[13][32]byte, key *[32]byte, tweak *[16]byte) {
	asuraExpandTweakeySoftBody(rtk, key, tweak)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func asuraEncryptBlockCore(rtk *[13][32]byte, dst, src *[32]byte) {
	var x0, x1 Block
	var q bsState
	copy(x0[:], src[0:16])
	copy(x1[:], src[16:32])

	for r := 0; r < 6; r++ {
		xorBlock(&x0, &x0, (*Block)(rtk[2*r][0:16]))
		xorBlock(&x1, &x1, (*Block)(rtk[2*r][16:32]))
		bsPack2(&q, &x0, &x1)
		bsInvFinalRoundNoKey(&q)
		bsInvMixColumns(&q)
		bsUnpack2(&q, &x0, &x1)

		xorBlock(&x0, &x0, (*Block)(rtk[2*r+1][0:16]))
		xorBlock(&x1, &x1, (*Block)(rtk[2*r+1][16:32]))
		bsPack1(&q, &x0)
		bsRoundNoKey(&q)
		bsUnpack1(&q, &x0)
		bsPack1(&q, &x1)
		bsInvFinalRoundNoKey(&q)
		bsInvMixColumns(&q)
		bsUnpack1(&q, &x1)

		if r < 5 {
			asuraPerm256(&x0, &x1)
		}
	}

	xorBlock((*Block)(dst[0:16]), &x0, (*Block)(rtk[12][0:16]))
	xorBlock((*Block)(dst[16:32]), &x1, (*Block)(rtk[12][16:32]))
}

//go:noinline
func asuraEncryptBlockSoftBody(rtk *[13][32]byte, dst, src *[32]byte) {
	asuraEncryptBlockCore(rtk, dst, src)
}

func asuraEncryptBlockSoft(rtk *[13][32]byte, dst, src *[32]byte) {
	asuraEncryptBlockSoftBody(rtk, dst, src)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func asuraDecryptBlockCore(rtk *[13][32]byte, dst, src *[32]byte) {
	var x0, x1 Block
	var q bsState
	xorBlock(&x0, (*Block)(src[0:16]), (*Block)(rtk[12][0:16]))
	xorBlock(&x1, (*Block)(src[16:32]), (*Block)(rtk[12][16:32]))

	for r := 5; r >= 0; r-- {
		if r < 5 {
			asuraInvPerm256(&x0, &x1)
		}

		bsPack1(&q, &x0)
		bsInvMixColumns(&q)
		bsInvFinalRoundNoKey(&q)
		bsUnpack1(&q, &x0)
		xorBlock(&x0, &x0, (*Block)(rtk[2*r+1][0:16]))

		bsPack1(&q, &x1)
		bsMixColumns(&q)
		bsFinalRoundNoKey(&q)
		bsUnpack1(&q, &x1)
		xorBlock(&x1, &x1, (*Block)(rtk[2*r+1][16:32]))

		bsPack2(&q, &x0, &x1)
		bsMixColumns(&q)
		bsFinalRoundNoKey(&q)
		bsUnpack2(&q, &x0, &x1)
		xorBlock(&x0, &x0, (*Block)(rtk[2*r][0:16]))
		xorBlock(&x1, &x1, (*Block)(rtk[2*r][16:32]))
	}

	copy(dst[0:16], x0[:])
	copy(dst[16:32], x1[:])
}

//go:noinline
func asuraDecryptBlockSoftBody(rtk *[13][32]byte, dst, src *[32]byte) {
	asuraDecryptBlockCore(rtk, dst, src)
}

func asuraDecryptBlockSoft(rtk *[13][32]byte, dst, src *[32]byte) {
	asuraDecryptBlockSoftBody(rtk, dst, src)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func asuraEncrypt4BlocksCore(rtk *[13][32]byte, dst, src *[4][32]byte) {
	var s0, s1 [4]Block
	var q0, q1 bsState
	for lane := 0; lane < 4; lane++ {
		copy(s0[lane][:], src[lane][0:16])
		copy(s1[lane][:], src[lane][16:32])
	}

	for r := 0; r < 6; r++ {
		for lane := 0; lane < 4; lane++ {
			xorBlock(&s0[lane], &s0[lane], (*Block)(rtk[2*r][0:16]))
			xorBlock(&s1[lane], &s1[lane], (*Block)(rtk[2*r][16:32]))
		}
		bsPack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsPack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
		bsInvFinalRoundNoKey(&q0)
		bsInvMixColumns(&q0)
		bsInvFinalRoundNoKey(&q1)
		bsInvMixColumns(&q1)
		bsUnpack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsUnpack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])

		for lane := 0; lane < 4; lane++ {
			xorBlock(&s0[lane], &s0[lane], (*Block)(rtk[2*r+1][0:16]))
			xorBlock(&s1[lane], &s1[lane], (*Block)(rtk[2*r+1][16:32]))
		}
		bsPack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsPack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
		bsRoundNoKey(&q0)
		bsInvFinalRoundNoKey(&q1)
		bsInvMixColumns(&q1)
		bsUnpack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsUnpack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])

		if r < 5 {
			for lane := 0; lane < 4; lane++ {
				asuraPerm256(&s0[lane], &s1[lane])
			}
		}
	}

	for lane := 0; lane < 4; lane++ {
		xorBlock((*Block)(dst[lane][0:16]), &s0[lane], (*Block)(rtk[12][0:16]))
		xorBlock((*Block)(dst[lane][16:32]), &s1[lane], (*Block)(rtk[12][16:32]))
	}
}

//go:noinline
func asuraEncrypt4BlocksSoftBody(rtk *[13][32]byte, dst, src *[4][32]byte) {
	asuraEncrypt4BlocksCore(rtk, dst, src)
}

func asuraEncrypt4BlocksSoft(rtk *[13][32]byte, dst, src *[4][32]byte) {
	asuraEncrypt4BlocksSoftBody(rtk, dst, src)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func asuraDecrypt4BlocksCore(rtk *[13][32]byte, dst, src *[4][32]byte) {
	var s0, s1 [4]Block
	var q0, q1 bsState
	for lane := 0; lane < 4; lane++ {
		xorBlock(&s0[lane], (*Block)(src[lane][0:16]), (*Block)(rtk[12][0:16]))
		xorBlock(&s1[lane], (*Block)(src[lane][16:32]), (*Block)(rtk[12][16:32]))
	}

	for r := 5; r >= 0; r-- {
		if r < 5 {
			for lane := 0; lane < 4; lane++ {
				asuraInvPerm256(&s0[lane], &s1[lane])
			}
		}

		bsPack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsPack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
		bsInvMixColumns(&q0)
		bsInvFinalRoundNoKey(&q0)
		bsMixColumns(&q1)
		bsFinalRoundNoKey(&q1)
		bsUnpack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsUnpack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])

		for lane := 0; lane < 4; lane++ {
			xorBlock(&s0[lane], &s0[lane], (*Block)(rtk[2*r+1][0:16]))
			xorBlock(&s1[lane], &s1[lane], (*Block)(rtk[2*r+1][16:32]))
		}

		bsPack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsPack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
		bsMixColumns(&q0)
		bsFinalRoundNoKey(&q0)
		bsMixColumns(&q1)
		bsFinalRoundNoKey(&q1)
		bsUnpack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsUnpack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])

		for lane := 0; lane < 4; lane++ {
			xorBlock(&s0[lane], &s0[lane], (*Block)(rtk[2*r][0:16]))
			xorBlock(&s1[lane], &s1[lane], (*Block)(rtk[2*r][16:32]))
		}
	}

	for lane := 0; lane < 4; lane++ {
		copy(dst[lane][0:16], s0[lane][:])
		copy(dst[lane][16:32], s1[lane][:])
	}
}

//go:noinline
func asuraDecrypt4BlocksSoftBody(rtk *[13][32]byte, dst, src *[4][32]byte) {
	asuraDecrypt4BlocksCore(rtk, dst, src)
}

func asuraDecrypt4BlocksSoft(rtk *[13][32]byte, dst, src *[4][32]byte) {
	asuraDecrypt4BlocksSoftBody(rtk, dst, src)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func asuraEncryptBlockOTFCore(dst, src, key *[32]byte, tweak *[16]byte) {
	var k [32]byte
	var t, x0, x1 Block
	var q, qT bsState
	k = *key
	t = *tweak
	copy(x0[:], src[0:16])
	copy(x1[:], src[16:32])
	bsPack1(&qT, &t)

	for r := 0; r < 6; r++ {
		asuraXorBlock4(&x0, &x0, &t, (*Block)(k[0:16]), &asuraRoundConstants[2*r])
		asuraXorBlock3(&x1, &x1, &t, (*Block)(k[16:32]))
		bsPack2(&q, &x0, &x1)
		bsInvFinalRoundNoKey(&q)
		bsInvMixColumns(&q)
		bsUnpack2(&q, &x0, &x1)

		bsRoundNoKey(&qT)
		bsUnpack1(&qT, &t)
		asuraKappaSoftware(&k)
		asuraXorBlock4(&x0, &x0, &t, (*Block)(k[0:16]), &asuraRoundConstants[2*r+1])
		asuraXorBlock3(&x1, &x1, &t, (*Block)(k[16:32]))
		bsPack1(&q, &x0)
		bsRoundNoKey(&q)
		bsUnpack1(&q, &x0)
		bsPack1(&q, &x1)
		bsInvFinalRoundNoKey(&q)
		bsInvMixColumns(&q)
		bsUnpack1(&q, &x1)

		if r < 5 {
			asuraPerm256(&x0, &x1)
		}

		bsRoundNoKey(&qT)
		bsUnpack1(&qT, &t)
		asuraKappaSoftware(&k)
	}

	asuraXorBlock4((*Block)(dst[0:16]), &x0, &t, (*Block)(k[0:16]), &asuraRoundConstants[12])
	asuraXorBlock3((*Block)(dst[16:32]), &x1, &t, (*Block)(k[16:32]))
}

//go:noinline
func asuraEncryptBlockOTFSoftBody(dst, src, key *[32]byte, tweak *[16]byte) {
	asuraEncryptBlockOTFCore(dst, src, key, tweak)
}

func asuraEncryptBlockOTFSoft(dst, src, key *[32]byte, tweak *[16]byte) {
	asuraEncryptBlockOTFSoftBody(dst, src, key, tweak)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func asuraTBCEncryptBlockSoft(dst, src, key *[32]byte, tweak *[16]byte) {
	asuraEncryptBlockOTFSoft(dst, src, key, tweak)
}

func asuraDecryptBlockOTFCore(dst, src, key *[32]byte, tweak *[16]byte) {
	var k [32]byte
	var t, x0, x1 Block
	var q, qT bsState
	k = *key
	t = *tweak
	bsPack1(&qT, &t)
	for i := 0; i < 12; i++ {
		bsRoundNoKey(&qT)
		asuraKappaSoftware(&k)
	}
	bsUnpack1(&qT, &t)
	asuraXorBlock4(&x0, (*Block)(src[0:16]), &t, (*Block)(k[0:16]), &asuraRoundConstants[12])
	asuraXorBlock3(&x1, (*Block)(src[16:32]), &t, (*Block)(k[16:32]))

	for r := 5; r >= 0; r-- {
		if r < 5 {
			asuraInvPerm256(&x0, &x1)
		}

		bsPack1(&q, &x0)
		bsInvMixColumns(&q)
		bsInvFinalRoundNoKey(&q)
		bsUnpack1(&q, &x0)
		bsPack1(&q, &x1)
		bsMixColumns(&q)
		bsFinalRoundNoKey(&q)
		bsUnpack1(&q, &x1)

		bsInvMixColumns(&qT)
		bsInvFinalRoundNoKey(&qT)
		bsUnpack1(&qT, &t)
		asuraInvKappaSoftware(&k)
		asuraXorBlock4(&x0, &x0, &t, (*Block)(k[0:16]), &asuraRoundConstants[2*r+1])
		asuraXorBlock3(&x1, &x1, &t, (*Block)(k[16:32]))

		bsPack2(&q, &x0, &x1)
		bsMixColumns(&q)
		bsFinalRoundNoKey(&q)
		bsUnpack2(&q, &x0, &x1)

		bsInvMixColumns(&qT)
		bsInvFinalRoundNoKey(&qT)
		bsUnpack1(&qT, &t)
		asuraInvKappaSoftware(&k)
		asuraXorBlock4(&x0, &x0, &t, (*Block)(k[0:16]), &asuraRoundConstants[2*r])
		asuraXorBlock3(&x1, &x1, &t, (*Block)(k[16:32]))
	}

	copy(dst[0:16], x0[:])
	copy(dst[16:32], x1[:])
}

//go:noinline
func asuraDecryptBlockOTFSoftBody(dst, src, key *[32]byte, tweak *[16]byte) {
	asuraDecryptBlockOTFCore(dst, src, key, tweak)
}

func asuraDecryptBlockOTFSoft(dst, src, key *[32]byte, tweak *[16]byte) {
	asuraDecryptBlockOTFSoftBody(dst, src, key, tweak)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func asuraTBCDecryptBlockSoft(dst, src, key *[32]byte, tweak *[16]byte) {
	asuraDecryptBlockOTFSoft(dst, src, key, tweak)
}

func asuraEncrypt4BlocksOTFCore(dst, src *[4][32]byte, key *[32]byte, tweak *[16]byte) {
	var s0, s1 [4]Block
	var k [32]byte
	var t, tk0, tk1 Block
	var q0, q1, qT bsState
	for lane := 0; lane < 4; lane++ {
		copy(s0[lane][:], src[lane][0:16])
		copy(s1[lane][:], src[lane][16:32])
	}
	k = *key
	t = *tweak
	bsPack1(&qT, &t)

	for r := 0; r < 6; r++ {
		asuraXorBlock3(&tk0, &t, (*Block)(k[0:16]), &asuraRoundConstants[2*r])
		xorBlock(&tk1, &t, (*Block)(k[16:32]))
		for lane := 0; lane < 4; lane++ {
			xorBlock(&s0[lane], &s0[lane], &tk0)
			xorBlock(&s1[lane], &s1[lane], &tk1)
		}
		bsPack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsPack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
		bsInvFinalRoundNoKey(&q0)
		bsInvMixColumns(&q0)
		bsInvFinalRoundNoKey(&q1)
		bsInvMixColumns(&q1)
		bsUnpack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsUnpack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])

		bsRoundNoKey(&qT)
		bsUnpack1(&qT, &t)
		asuraKappaSoftware(&k)
		asuraXorBlock3(&tk0, &t, (*Block)(k[0:16]), &asuraRoundConstants[2*r+1])
		xorBlock(&tk1, &t, (*Block)(k[16:32]))
		for lane := 0; lane < 4; lane++ {
			xorBlock(&s0[lane], &s0[lane], &tk0)
			xorBlock(&s1[lane], &s1[lane], &tk1)
		}
		bsPack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsPack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
		bsRoundNoKey(&q0)
		bsInvFinalRoundNoKey(&q1)
		bsInvMixColumns(&q1)
		bsUnpack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsUnpack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])

		if r < 5 {
			for lane := 0; lane < 4; lane++ {
				asuraPerm256(&s0[lane], &s1[lane])
			}
		}

		bsRoundNoKey(&qT)
		bsUnpack1(&qT, &t)
		asuraKappaSoftware(&k)
	}

	asuraXorBlock3(&tk0, &t, (*Block)(k[0:16]), &asuraRoundConstants[12])
	xorBlock(&tk1, &t, (*Block)(k[16:32]))
	for lane := 0; lane < 4; lane++ {
		xorBlock((*Block)(dst[lane][0:16]), &s0[lane], &tk0)
		xorBlock((*Block)(dst[lane][16:32]), &s1[lane], &tk1)
	}
}

//go:noinline
func asuraEncrypt4BlocksOTFSoftBody(dst, src *[4][32]byte, key *[32]byte, tweak *[16]byte) {
	asuraEncrypt4BlocksOTFCore(dst, src, key, tweak)
}

func asuraEncrypt4BlocksOTFSoft(dst, src *[4][32]byte, key *[32]byte, tweak *[16]byte) {
	asuraEncrypt4BlocksOTFSoftBody(dst, src, key, tweak)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func asuraTBCEncrypt4BlocksSoft(dst, src *[4][32]byte, key *[32]byte, tweak *[16]byte) {
	asuraEncrypt4BlocksOTFSoft(dst, src, key, tweak)
}

func asuraDecrypt4BlocksOTFCore(dst, src *[4][32]byte, key *[32]byte, tweak *[16]byte) {
	var s0, s1 [4]Block
	var k [32]byte
	var t, tk0, tk1 Block
	var q0, q1, qT bsState
	k = *key
	t = *tweak
	bsPack1(&qT, &t)
	for i := 0; i < 12; i++ {
		bsRoundNoKey(&qT)
		asuraKappaSoftware(&k)
	}
	bsUnpack1(&qT, &t)

	asuraXorBlock3(&tk0, &t, (*Block)(k[0:16]), &asuraRoundConstants[12])
	xorBlock(&tk1, &t, (*Block)(k[16:32]))
	for lane := 0; lane < 4; lane++ {
		xorBlock(&s0[lane], (*Block)(src[lane][0:16]), &tk0)
		xorBlock(&s1[lane], (*Block)(src[lane][16:32]), &tk1)
	}

	for r := 5; r >= 0; r-- {
		if r < 5 {
			for lane := 0; lane < 4; lane++ {
				asuraInvPerm256(&s0[lane], &s1[lane])
			}
		}

		bsPack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsPack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
		bsInvMixColumns(&q0)
		bsInvFinalRoundNoKey(&q0)
		bsMixColumns(&q1)
		bsFinalRoundNoKey(&q1)
		bsUnpack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsUnpack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])

		bsInvMixColumns(&qT)
		bsInvFinalRoundNoKey(&qT)
		bsUnpack1(&qT, &t)
		asuraInvKappaSoftware(&k)
		asuraXorBlock3(&tk0, &t, (*Block)(k[0:16]), &asuraRoundConstants[2*r+1])
		xorBlock(&tk1, &t, (*Block)(k[16:32]))
		for lane := 0; lane < 4; lane++ {
			xorBlock(&s0[lane], &s0[lane], &tk0)
			xorBlock(&s1[lane], &s1[lane], &tk1)
		}

		bsPack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsPack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
		bsMixColumns(&q0)
		bsFinalRoundNoKey(&q0)
		bsMixColumns(&q1)
		bsFinalRoundNoKey(&q1)
		bsUnpack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsUnpack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])

		bsInvMixColumns(&qT)
		bsInvFinalRoundNoKey(&qT)
		bsUnpack1(&qT, &t)
		asuraInvKappaSoftware(&k)
		asuraXorBlock3(&tk0, &t, (*Block)(k[0:16]), &asuraRoundConstants[2*r])
		xorBlock(&tk1, &t, (*Block)(k[16:32]))
		for lane := 0; lane < 4; lane++ {
			xorBlock(&s0[lane], &s0[lane], &tk0)
			xorBlock(&s1[lane], &s1[lane], &tk1)
		}
	}

	for lane := 0; lane < 4; lane++ {
		copy(dst[lane][0:16], s0[lane][:])
		copy(dst[lane][16:32], s1[lane][:])
	}
}

//go:noinline
func asuraDecrypt4BlocksOTFSoftBody(dst, src *[4][32]byte, key *[32]byte, tweak *[16]byte) {
	asuraDecrypt4BlocksOTFCore(dst, src, key, tweak)
}

func asuraDecrypt4BlocksOTFSoft(dst, src *[4][32]byte, key *[32]byte, tweak *[16]byte) {
	asuraDecrypt4BlocksOTFSoftBody(dst, src, key, tweak)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func asuraTBCDecrypt4BlocksSoft(dst, src *[4][32]byte, key *[32]byte, tweak *[16]byte) {
	asuraDecrypt4BlocksOTFSoft(dst, src, key, tweak)
}

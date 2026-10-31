package areion

import (
	"encoding/binary"
	"math/bits"
	"runtime"
)

var rijndael256Rcon = [15]uint32{
	0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
	0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
}

//go:noinline
func rijndael256ExpandKeyBody(key *[32]byte, rk *[15][32]byte) {
	var w [120]uint32
	for i := 0; i < 8; i++ {
		w[i] = binary.LittleEndian.Uint32(key[4*i : 4*i+4])
	}
	for i := 8; i < 120; i++ {
		tmp := w[i-1]
		switch i % 8 {
		case 0:
			rot := (tmp >> 8) | (tmp << 24)
			tmp = bsSubWord(rot) ^ rijndael256Rcon[i/8]
		case 4:
			tmp = bsSubWord(tmp)
		}
		w[i] = w[i-8] ^ tmp
	}
	for r := 0; r < 15; r++ {
		for c := 0; c < 8; c++ {
			binary.LittleEndian.PutUint32(rk[r][4*c:4*c+4], w[8*r+c])
		}
	}
	clear(w[:])
	runtime.KeepAlive(&w)
}

func rijndael256ExpandKey(key *[32]byte, rk *[15][32]byte) {
	rijndael256ExpandKeyBody(key, rk)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func rijndael256InvertRoundKeysBody(drk, erk *[15][32]byte) {
	var q bsState
	var loA, hiA, loB, hiB Block
	r0 := erk[14]
	r14 := erk[0]
	drk[0] = r0
	drk[14] = r14
	for r := 1; r <= 6; r++ {
		loA = *(*Block)(erk[14-r][0:16])
		hiA = *(*Block)(erk[14-r][16:32])
		loB = *(*Block)(erk[r][0:16])
		hiB = *(*Block)(erk[r][16:32])
		bsPack4(&q, &loA, &hiA, &loB, &hiB)
		bsInvMixColumns(&q)
		bsUnpack4(&q, (*Block)(drk[r][0:16]), (*Block)(drk[r][16:32]), (*Block)(drk[14-r][0:16]), (*Block)(drk[14-r][16:32]))
	}
	loA = *(*Block)(erk[7][0:16])
	hiA = *(*Block)(erk[7][16:32])
	bsPack2(&q, &loA, &hiA)
	bsInvMixColumns(&q)
	bsUnpack2(&q, (*Block)(drk[7][0:16]), (*Block)(drk[7][16:32]))
	clear(r0[:])
	clear(r14[:])
	clear(loA[:])
	clear(hiA[:])
	clear(loB[:])
	clear(hiB[:])
	clear(q[:])
	runtime.KeepAlive(&r0)
	runtime.KeepAlive(&r14)
	runtime.KeepAlive(&loA)
	runtime.KeepAlive(&hiA)
	runtime.KeepAlive(&loB)
	runtime.KeepAlive(&hiB)
	runtime.KeepAlive(&q)
}

func rijndael256InvertRoundKeys(drk, erk *[15][32]byte) {
	rijndael256InvertRoundKeysBody(drk, erk)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func rijndael256ExpandKeyDecBody(key *[32]byte, drk *[15][32]byte) {
	var erk [15][32]byte
	rijndael256ExpandKeyBody(key, &erk)
	rijndael256InvertRoundKeysBody(drk, &erk)
	clear(erk[:])
	runtime.KeepAlive(&erk)
}

func rijndael256ExpandKeyDec(key *[32]byte, drk *[15][32]byte) {
	rijndael256ExpandKeyDecBody(key, drk)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func bsShiftRowsR256Single(q *bsState) {
	for k := 0; k < 8; k++ {
		x := q[k]
		r0 := uint64(uint16(x))

		x1 := uint16(x >> 16)
		lo1 := x1 & 0x1111
		hi1 := (x1 >> 1) & 0x1111
		nlo1 := (lo1 >> 4) | ((hi1 & 0x0001) << 12)
		nhi1 := (hi1 >> 4) | ((lo1 & 0x0001) << 12)
		r1 := uint64(nlo1|(nhi1<<1)) << 16

		x2 := uint16(x >> 32)
		lo2 := x2 & 0x1111
		hi2 := (x2 >> 1) & 0x1111
		nlo2 := (lo2 >> 12) | ((hi2 & 0x0111) << 4)
		nhi2 := (hi2 >> 12) | ((lo2 & 0x0111) << 4)
		r2 := uint64(nlo2|(nhi2<<1)) << 32

		x3 := uint16(x >> 48)
		r3 := uint64(((x3&0x1111)<<1)|((x3>>1)&0x1111)) << 48

		q[k] = r0 | r1 | r2 | r3
	}
}

func bsInvShiftRowsR256Single(q *bsState) {
	for k := 0; k < 8; k++ {
		x := q[k]
		r0 := uint64(uint16(x))

		x1 := uint16(x >> 16)
		lo1 := x1 & 0x1111
		hi1 := (x1 >> 1) & 0x1111
		nlo1 := ((lo1 & 0x0111) << 4) | (hi1 >> 12)
		nhi1 := ((hi1 & 0x0111) << 4) | (lo1 >> 12)
		r1 := uint64(nlo1|(nhi1<<1)) << 16

		x2 := uint16(x >> 32)
		lo2 := x2 & 0x1111
		hi2 := (x2 >> 1) & 0x1111
		nlo2 := ((lo2 & 0x0001) << 12) | (hi2 >> 4)
		nhi2 := ((hi2 & 0x0001) << 12) | (lo2 >> 4)
		r2 := uint64(nlo2|(nhi2<<1)) << 32

		x3 := uint16(x >> 48)
		r3 := uint64(((x3&0x1111)<<1)|((x3>>1)&0x1111)) << 48

		q[k] = r0 | r1 | r2 | r3
	}
}

func bsShiftRowsR256Pair(qLo, qHi *bsState) {
	for k := 0; k < 8; k++ {
		lo := qLo[k]
		hi := qHi[k]

		r1 := bits.RotateLeft32(uint32(uint16(lo>>16))|(uint32(uint16(hi>>16))<<16), -4)
		r2 := bits.RotateLeft32(uint32(uint16(lo>>32))|(uint32(uint16(hi>>32))<<16), -12)

		qLo[k] = uint64(uint16(lo)) |
			(uint64(uint16(r1)) << 16) |
			(uint64(uint16(r2)) << 32) |
			((hi >> 48) << 48)
		qHi[k] = uint64(uint16(hi)) |
			(uint64(uint16(r1>>16)) << 16) |
			(uint64(uint16(r2>>16)) << 32) |
			((lo >> 48) << 48)
	}
}

func bsInvShiftRowsR256Pair(qLo, qHi *bsState) {
	for k := 0; k < 8; k++ {
		lo := qLo[k]
		hi := qHi[k]

		r1 := bits.RotateLeft32(uint32(uint16(lo>>16))|(uint32(uint16(hi>>16))<<16), 4)
		r2 := bits.RotateLeft32(uint32(uint16(lo>>32))|(uint32(uint16(hi>>32))<<16), 12)

		qLo[k] = uint64(uint16(lo)) |
			(uint64(uint16(r1)) << 16) |
			(uint64(uint16(r2)) << 32) |
			((hi >> 48) << 48)
		qHi[k] = uint64(uint16(hi)) |
			(uint64(uint16(r1>>16)) << 16) |
			(uint64(uint16(r2>>16)) << 32) |
			((lo >> 48) << 48)
	}
}

//go:noinline
func rijndael256EncryptBlockSoftwareBody(rk *[15][32]byte, dst, src *[32]byte) {
	var lo, hi Block
	xorBlock(&lo, (*Block)(src[0:16]), (*Block)(rk[0][0:16]))
	xorBlock(&hi, (*Block)(src[16:32]), (*Block)(rk[0][16:32]))

	var q, kr bsState
	bsPack2(&q, &lo, &hi)

	for r := 1; r <= 11; r += 2 {
		bsPack4(&kr, (*Block)(rk[r][0:16]), (*Block)(rk[r][16:32]), (*Block)(rk[r+1][0:16]), (*Block)(rk[r+1][16:32]))
		bsSubBytes(&q)
		bsShiftRowsR256Single(&q)
		bsMixColumns(&q)
		for k := 0; k < 8; k++ {
			q[k] ^= kr[k] & bsLane01Mask
		}
		bsSubBytes(&q)
		bsShiftRowsR256Single(&q)
		bsMixColumns(&q)
		for k := 0; k < 8; k++ {
			q[k] ^= (kr[k] >> 2) & bsLane01Mask
		}
	}

	bsPack4(&kr, (*Block)(rk[13][0:16]), (*Block)(rk[13][16:32]), (*Block)(rk[14][0:16]), (*Block)(rk[14][16:32]))
	bsSubBytes(&q)
	bsShiftRowsR256Single(&q)
	bsMixColumns(&q)
	for k := 0; k < 8; k++ {
		q[k] ^= kr[k] & bsLane01Mask
	}
	bsSubBytes(&q)
	bsShiftRowsR256Single(&q)
	for k := 0; k < 8; k++ {
		q[k] ^= (kr[k] >> 2) & bsLane01Mask
	}

	bsUnpack2(&q, (*Block)(dst[0:16]), (*Block)(dst[16:32]))
	clear(lo[:])
	clear(hi[:])
	clear(q[:])
	clear(kr[:])
	runtime.KeepAlive(&lo)
	runtime.KeepAlive(&hi)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&kr)
}

func rijndael256EncryptBlockSoftware(rk *[15][32]byte, dst, src *[32]byte) {
	rijndael256EncryptBlockSoftwareBody(rk, dst, src)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func rijndael256DecryptBlockSoftwareBody(drk *[15][32]byte, dst, src *[32]byte) {
	var lo, hi Block
	xorBlock(&lo, (*Block)(src[0:16]), (*Block)(drk[0][0:16]))
	xorBlock(&hi, (*Block)(src[16:32]), (*Block)(drk[0][16:32]))
	var q, kr bsState
	bsPack2(&q, &lo, &hi)

	for r := 1; r <= 11; r += 2 {
		bsPack4(&kr, (*Block)(drk[r][0:16]), (*Block)(drk[r][16:32]), (*Block)(drk[r+1][0:16]), (*Block)(drk[r+1][16:32]))
		bsInvShiftRowsR256Single(&q)
		bsInvSubBytes(&q)
		bsInvMixColumns(&q)
		for k := 0; k < 8; k++ {
			q[k] ^= kr[k] & bsLane01Mask
		}
		bsInvShiftRowsR256Single(&q)
		bsInvSubBytes(&q)
		bsInvMixColumns(&q)
		for k := 0; k < 8; k++ {
			q[k] ^= (kr[k] >> 2) & bsLane01Mask
		}
	}

	bsPack4(&kr, (*Block)(drk[13][0:16]), (*Block)(drk[13][16:32]), (*Block)(drk[14][0:16]), (*Block)(drk[14][16:32]))
	bsInvShiftRowsR256Single(&q)
	bsInvSubBytes(&q)
	bsInvMixColumns(&q)
	for k := 0; k < 8; k++ {
		q[k] ^= kr[k] & bsLane01Mask
	}
	bsInvShiftRowsR256Single(&q)
	bsInvSubBytes(&q)
	for k := 0; k < 8; k++ {
		q[k] ^= (kr[k] >> 2) & bsLane01Mask
	}

	bsUnpack2(&q, (*Block)(dst[0:16]), (*Block)(dst[16:32]))
	clear(lo[:])
	clear(hi[:])
	clear(q[:])
	clear(kr[:])
	runtime.KeepAlive(&lo)
	runtime.KeepAlive(&hi)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&kr)
}

func rijndael256DecryptBlockSoftware(drk *[15][32]byte, dst, src *[32]byte) {
	rijndael256DecryptBlockSoftwareBody(drk, dst, src)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func rijndael256Encrypt4BlocksSoftwareBody(rk *[15][32]byte, dst, src *[4][32]byte) {
	var bLo, bHi [4]Block
	for lane := 0; lane < 4; lane++ {
		xorBlock(&bLo[lane], (*Block)(src[lane][0:16]), (*Block)(rk[0][0:16]))
		xorBlock(&bHi[lane], (*Block)(src[lane][16:32]), (*Block)(rk[0][16:32]))
	}

	var qLo, qHi, kLo, kHi bsState
	bsPack4(&qLo, &bLo[0], &bLo[1], &bLo[2], &bLo[3])
	bsPack4(&qHi, &bHi[0], &bHi[1], &bHi[2], &bHi[3])

	for base := 1; base <= 9; base += 4 {
		bsPack4(&kLo, (*Block)(rk[base][0:16]), (*Block)(rk[base+1][0:16]), (*Block)(rk[base+2][0:16]), (*Block)(rk[base+3][0:16]))
		bsPack4(&kHi, (*Block)(rk[base][16:32]), (*Block)(rk[base+1][16:32]), (*Block)(rk[base+2][16:32]), (*Block)(rk[base+3][16:32]))
		for lane := uint(0); lane < 4; lane++ {
			bsSubBytes(&qLo)
			bsSubBytes(&qHi)
			bsShiftRowsR256Pair(&qLo, &qHi)
			bsMixColumns(&qLo)
			bsMixColumns(&qHi)
			for k := 0; k < 8; k++ {
				qLo[k] ^= ((kLo[k] >> lane) & bsLane0Mask) * 0xf
				qHi[k] ^= ((kHi[k] >> lane) & bsLane0Mask) * 0xf
			}
		}
	}

	bsPack2(&kLo, (*Block)(rk[13][0:16]), (*Block)(rk[14][0:16]))
	bsPack2(&kHi, (*Block)(rk[13][16:32]), (*Block)(rk[14][16:32]))
	bsSubBytes(&qLo)
	bsSubBytes(&qHi)
	bsShiftRowsR256Pair(&qLo, &qHi)
	bsMixColumns(&qLo)
	bsMixColumns(&qHi)
	for k := 0; k < 8; k++ {
		qLo[k] ^= (kLo[k] & bsLane0Mask) * 0xf
		qHi[k] ^= (kHi[k] & bsLane0Mask) * 0xf
	}

	bsSubBytes(&qLo)
	bsSubBytes(&qHi)
	bsShiftRowsR256Pair(&qLo, &qHi)
	for k := 0; k < 8; k++ {
		qLo[k] ^= ((kLo[k] >> 1) & bsLane0Mask) * 0xf
		qHi[k] ^= ((kHi[k] >> 1) & bsLane0Mask) * 0xf
	}

	bsUnpack4(&qLo, (*Block)(dst[0][0:16]), (*Block)(dst[1][0:16]), (*Block)(dst[2][0:16]), (*Block)(dst[3][0:16]))
	bsUnpack4(&qHi, (*Block)(dst[0][16:32]), (*Block)(dst[1][16:32]), (*Block)(dst[2][16:32]), (*Block)(dst[3][16:32]))
	clear(bLo[:])
	clear(bHi[:])
	clear(qLo[:])
	clear(qHi[:])
	clear(kLo[:])
	clear(kHi[:])
	runtime.KeepAlive(&bLo)
	runtime.KeepAlive(&bHi)
	runtime.KeepAlive(&qLo)
	runtime.KeepAlive(&qHi)
	runtime.KeepAlive(&kLo)
	runtime.KeepAlive(&kHi)
}

func rijndael256Encrypt4BlocksSoftware(rk *[15][32]byte, dst, src *[4][32]byte) {
	rijndael256Encrypt4BlocksSoftwareBody(rk, dst, src)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func rijndael256Decrypt4BlocksSoftwareBody(drk *[15][32]byte, dst, src *[4][32]byte) {
	var bLo, bHi [4]Block
	for lane := 0; lane < 4; lane++ {
		xorBlock(&bLo[lane], (*Block)(src[lane][0:16]), (*Block)(drk[0][0:16]))
		xorBlock(&bHi[lane], (*Block)(src[lane][16:32]), (*Block)(drk[0][16:32]))
	}

	var qLo, qHi, kLo, kHi bsState
	bsPack4(&qLo, &bLo[0], &bLo[1], &bLo[2], &bLo[3])
	bsPack4(&qHi, &bHi[0], &bHi[1], &bHi[2], &bHi[3])

	for base := 1; base <= 9; base += 4 {
		bsPack4(&kLo, (*Block)(drk[base][0:16]), (*Block)(drk[base+1][0:16]), (*Block)(drk[base+2][0:16]), (*Block)(drk[base+3][0:16]))
		bsPack4(&kHi, (*Block)(drk[base][16:32]), (*Block)(drk[base+1][16:32]), (*Block)(drk[base+2][16:32]), (*Block)(drk[base+3][16:32]))
		for lane := uint(0); lane < 4; lane++ {
			bsInvShiftRowsR256Pair(&qLo, &qHi)
			bsInvSubBytes(&qLo)
			bsInvSubBytes(&qHi)
			bsInvMixColumns(&qLo)
			bsInvMixColumns(&qHi)
			for k := 0; k < 8; k++ {
				qLo[k] ^= ((kLo[k] >> lane) & bsLane0Mask) * 0xf
				qHi[k] ^= ((kHi[k] >> lane) & bsLane0Mask) * 0xf
			}
		}
	}

	bsPack2(&kLo, (*Block)(drk[13][0:16]), (*Block)(drk[14][0:16]))
	bsPack2(&kHi, (*Block)(drk[13][16:32]), (*Block)(drk[14][16:32]))
	bsInvShiftRowsR256Pair(&qLo, &qHi)
	bsInvSubBytes(&qLo)
	bsInvSubBytes(&qHi)
	bsInvMixColumns(&qLo)
	bsInvMixColumns(&qHi)
	for k := 0; k < 8; k++ {
		qLo[k] ^= (kLo[k] & bsLane0Mask) * 0xf
		qHi[k] ^= (kHi[k] & bsLane0Mask) * 0xf
	}

	bsInvShiftRowsR256Pair(&qLo, &qHi)
	bsInvSubBytes(&qLo)
	bsInvSubBytes(&qHi)
	for k := 0; k < 8; k++ {
		qLo[k] ^= ((kLo[k] >> 1) & bsLane0Mask) * 0xf
		qHi[k] ^= ((kHi[k] >> 1) & bsLane0Mask) * 0xf
	}

	bsUnpack4(&qLo, (*Block)(dst[0][0:16]), (*Block)(dst[1][0:16]), (*Block)(dst[2][0:16]), (*Block)(dst[3][0:16]))
	bsUnpack4(&qHi, (*Block)(dst[0][16:32]), (*Block)(dst[1][16:32]), (*Block)(dst[2][16:32]), (*Block)(dst[3][16:32]))
	clear(bLo[:])
	clear(bHi[:])
	clear(qLo[:])
	clear(qHi[:])
	clear(kLo[:])
	clear(kHi[:])
	runtime.KeepAlive(&bLo)
	runtime.KeepAlive(&bHi)
	runtime.KeepAlive(&qLo)
	runtime.KeepAlive(&qHi)
	runtime.KeepAlive(&kLo)
	runtime.KeepAlive(&kHi)
}

func rijndael256Decrypt4BlocksSoftware(drk *[15][32]byte, dst, src *[4][32]byte) {
	rijndael256Decrypt4BlocksSoftwareBody(drk, dst, src)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

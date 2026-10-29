package areion

import (
	"math/bits"
	"runtime"
)

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

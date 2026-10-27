package areion

import (
	"encoding/binary"
	"math/bits"
	"runtime"
)

// bsState holds up to four 128-bit AES blocks (64 bytes) in 64-bit bitsliced form.
// Bitplane q[k] (k in 0..7, where 0 is LSB and 7 is MSB) stores bit k of byte
// (col*4 + row) of block blk (blk in 0..3) at bit position:
//
//	pos = 16*row + 4*col + blk
//
// In this layout:
//   - The four AES rows occupy the four 16-bit quarters of each uint64, so row
//     rotations in MixColumns / InvMixColumns are mask-free 64-bit rotations by
//     multiples of 16 bits.
//   - Within each 16-bit row quarter, the four columns occupy the four 4-bit
//     nibbles, so ShiftRows / InvShiftRows are 16-bit rotations by multiples of 4 bits.
//   - The four parallel AES blocks occupy bit offsets 0, 1, 2, 3 within every 4-bit nibble.
type bsState [8]uint64

const (
	bsLane01Mask = 0x3333333333333333
	bsLane0Mask  = 0x1111111111111111
	bsByte0Mask  = 0x0101010101010101
)

var (
	bsRCP1   [15]bsState
	bsRCP2   [15]bsState
	bsRCP1P2 [15]bsState
)

func init() {
	for r := 0; r < 15; r++ {
		bsPackBroadcast(&bsRCP1[r], &roundConstantsP1[r])
		bsPackBroadcast(&bsRCP2[r], &roundConstantsP2[r])
		bsPack2Broadcast(&bsRCP1P2[r], &roundConstantsP1[r], &roundConstantsP2[r])
	}
}

func bsPrepWord(u uint64) uint64 {
	t := ((u >> 24) ^ u) & 0x00000000ff00ff00
	u ^= t ^ (t << 24)
	t = ((u >> 16) ^ u) & 0x00000000ffff0000
	u ^= t ^ (t << 16)
	return u
}

func bsUnprepWord(u uint64) uint64 {
	t := ((u >> 16) ^ u) & 0x00000000ffff0000
	u ^= t ^ (t << 16)
	t = ((u >> 24) ^ u) & 0x00000000ff00ff00
	u ^= t ^ (t << 24)
	return u
}

func bsPrepBlock(lo, hi uint64) (uint64, uint64) {
	u0 := uint64(uint32(lo)) | (hi << 32)
	u1 := (lo >> 32) | (hi & 0xffffffff00000000)
	return bsPrepWord(u0), bsPrepWord(u1)
}

func bsUnprepBlock(u0, u1 uint64) (uint64, uint64) {
	u0 = bsUnprepWord(u0)
	u1 = bsUnprepWord(u1)
	lo := uint64(uint32(u0)) | (u1 << 32)
	hi := (u0 >> 32) | (u1 & 0xffffffff00000000)
	return lo, hi
}

// bsOrtho performs an in-place 8x8 bit-transpose across the low 3 bits of the
// word index and the low 3 bits of the bit position within each byte. It is an
// involution (its own inverse).
func bsOrtho(w *[8]uint64) {
	const (
		m1 = 0x5555555555555555
		m2 = 0x3333333333333333
		m4 = 0x0f0f0f0f0f0f0f0f
	)
	t := ((w[0] >> 1) ^ w[1]) & m1
	w[0] ^= t << 1
	w[1] ^= t
	t = ((w[2] >> 1) ^ w[3]) & m1
	w[2] ^= t << 1
	w[3] ^= t
	t = ((w[4] >> 1) ^ w[5]) & m1
	w[4] ^= t << 1
	w[5] ^= t
	t = ((w[6] >> 1) ^ w[7]) & m1
	w[6] ^= t << 1
	w[7] ^= t

	t = ((w[0] >> 2) ^ w[2]) & m2
	w[0] ^= t << 2
	w[2] ^= t
	t = ((w[1] >> 2) ^ w[3]) & m2
	w[1] ^= t << 2
	w[3] ^= t
	t = ((w[4] >> 2) ^ w[6]) & m2
	w[4] ^= t << 2
	w[6] ^= t
	t = ((w[5] >> 2) ^ w[7]) & m2
	w[5] ^= t << 2
	w[7] ^= t

	t = ((w[0] >> 4) ^ w[4]) & m4
	w[0] ^= t << 4
	w[4] ^= t
	t = ((w[1] >> 4) ^ w[5]) & m4
	w[1] ^= t << 4
	w[5] ^= t
	t = ((w[2] >> 4) ^ w[6]) & m4
	w[2] ^= t << 4
	w[6] ^= t
	t = ((w[3] >> 4) ^ w[7]) & m4
	w[3] ^= t << 4
	w[7] ^= t
}

func bsPack1(q *bsState, b0 *Block) {
	lo := binary.LittleEndian.Uint64(b0[0:8])
	hi := binary.LittleEndian.Uint64(b0[8:16])
	u0, u1 := bsPrepBlock(lo, hi)
	q[0] = (u0 & bsByte0Mask) | ((u1 & bsByte0Mask) << 4)
	q[1] = ((u0 >> 1) & bsByte0Mask) | (((u1 >> 1) & bsByte0Mask) << 4)
	q[2] = ((u0 >> 2) & bsByte0Mask) | (((u1 >> 2) & bsByte0Mask) << 4)
	q[3] = ((u0 >> 3) & bsByte0Mask) | (((u1 >> 3) & bsByte0Mask) << 4)
	q[4] = ((u0 >> 4) & bsByte0Mask) | (((u1 >> 4) & bsByte0Mask) << 4)
	q[5] = ((u0 >> 5) & bsByte0Mask) | (((u1 >> 5) & bsByte0Mask) << 4)
	q[6] = ((u0 >> 6) & bsByte0Mask) | (((u1 >> 6) & bsByte0Mask) << 4)
	q[7] = ((u0 >> 7) & bsByte0Mask) | (((u1 >> 7) & bsByte0Mask) << 4)
}

func bsUnpack1(q *bsState, b0 *Block) {
	u0 := (q[0] & bsByte0Mask) |
		((q[1] & bsByte0Mask) << 1) |
		((q[2] & bsByte0Mask) << 2) |
		((q[3] & bsByte0Mask) << 3) |
		((q[4] & bsByte0Mask) << 4) |
		((q[5] & bsByte0Mask) << 5) |
		((q[6] & bsByte0Mask) << 6) |
		((q[7] & bsByte0Mask) << 7)
	u1 := ((q[0] >> 4) & bsByte0Mask) |
		(((q[1] >> 4) & bsByte0Mask) << 1) |
		(((q[2] >> 4) & bsByte0Mask) << 2) |
		(((q[3] >> 4) & bsByte0Mask) << 3) |
		(((q[4] >> 4) & bsByte0Mask) << 4) |
		(((q[5] >> 4) & bsByte0Mask) << 5) |
		(((q[6] >> 4) & bsByte0Mask) << 6) |
		(((q[7] >> 4) & bsByte0Mask) << 7)
	lo, hi := bsUnprepBlock(u0, u1)
	binary.LittleEndian.PutUint64(b0[0:8], lo)
	binary.LittleEndian.PutUint64(b0[8:16], hi)
}

func bsPack2(q *bsState, b0, b1 *Block) {
	u00, u10 := bsPrepBlock(binary.LittleEndian.Uint64(b0[0:8]), binary.LittleEndian.Uint64(b0[8:16]))
	u01, u11 := bsPrepBlock(binary.LittleEndian.Uint64(b1[0:8]), binary.LittleEndian.Uint64(b1[8:16]))
	for k := uint(0); k < 8; k++ {
		c0 := ((u00 >> k) & bsByte0Mask) | (((u01 >> k) & bsByte0Mask) << 1)
		c1 := ((u10 >> k) & bsByte0Mask) | (((u11 >> k) & bsByte0Mask) << 1)
		q[k] = c0 | (c1 << 4)
	}
}

func bsUnpack2(q *bsState, b0, b1 *Block) {
	var u00, u10, u01, u11 uint64
	for k := uint(0); k < 8; k++ {
		xk := q[k]
		u00 |= (xk & bsByte0Mask) << k
		u01 |= ((xk >> 1) & bsByte0Mask) << k
		u10 |= ((xk >> 4) & bsByte0Mask) << k
		u11 |= ((xk >> 5) & bsByte0Mask) << k
	}
	lo0, hi0 := bsUnprepBlock(u00, u10)
	lo1, hi1 := bsUnprepBlock(u01, u11)
	binary.LittleEndian.PutUint64(b0[0:8], lo0)
	binary.LittleEndian.PutUint64(b0[8:16], hi0)
	binary.LittleEndian.PutUint64(b1[0:8], lo1)
	binary.LittleEndian.PutUint64(b1[8:16], hi1)
}

func bsPackBroadcast(q *bsState, b0 *Block) {
	bsPack1(q, b0)
	for k := 0; k < 8; k++ {
		q[k] *= 0xf
	}
}

func bsPack2Broadcast(q *bsState, b0, b1 *Block) {
	bsPack2(q, b0, b1)
	for k := 0; k < 8; k++ {
		q[k] |= q[k] << 2
	}
}

func bsPack4(q *bsState, b0, b1, b2, b3 *Block) {
	u00, u10 := bsPrepBlock(binary.LittleEndian.Uint64(b0[0:8]), binary.LittleEndian.Uint64(b0[8:16]))
	u01, u11 := bsPrepBlock(binary.LittleEndian.Uint64(b1[0:8]), binary.LittleEndian.Uint64(b1[8:16]))
	u02, u12 := bsPrepBlock(binary.LittleEndian.Uint64(b2[0:8]), binary.LittleEndian.Uint64(b2[8:16]))
	u03, u13 := bsPrepBlock(binary.LittleEndian.Uint64(b3[0:8]), binary.LittleEndian.Uint64(b3[8:16]))
	*q = bsState{u00, u01, u02, u03, u10, u11, u12, u13}
	bsOrtho((*[8]uint64)(q))
}

func bsUnpack4(q *bsState, b0, b1, b2, b3 *Block) {
	w := *(*[8]uint64)(q)
	bsOrtho(&w)
	lo0, hi0 := bsUnprepBlock(w[0], w[4])
	lo1, hi1 := bsUnprepBlock(w[1], w[5])
	lo2, hi2 := bsUnprepBlock(w[2], w[6])
	lo3, hi3 := bsUnprepBlock(w[3], w[7])
	binary.LittleEndian.PutUint64(b0[0:8], lo0)
	binary.LittleEndian.PutUint64(b0[8:16], hi0)
	binary.LittleEndian.PutUint64(b1[0:8], lo1)
	binary.LittleEndian.PutUint64(b1[8:16], hi1)
	binary.LittleEndian.PutUint64(b2[0:8], lo2)
	binary.LittleEndian.PutUint64(b2[8:16], hi2)
	binary.LittleEndian.PutUint64(b3[0:8], lo3)
	binary.LittleEndian.PutUint64(b3[8:16], hi3)
	clear(w[:])
	runtime.KeepAlive(&w)
}

// bsSubBytes evaluates the constant-time Boyar-Peralta combinational AES S-box
// circuit on all 64 bytes (4 AES blocks) in parallel.
func bsSubBytes(q *bsState) {
	u0, u1, u2, u3, u4, u5, u6, u7 := q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0]

	y14 := u3 ^ u5
	y13 := u0 ^ u6
	y9 := u0 ^ u3
	y8 := u0 ^ u5
	t0 := u1 ^ u2
	y1 := t0 ^ u7
	y4 := y1 ^ u3
	y12 := y13 ^ y14
	y2 := y1 ^ u0
	y5 := y1 ^ u6
	y3 := y5 ^ y8
	t1 := u4 ^ y12
	y15 := t1 ^ u5
	y20 := t1 ^ u1
	y6 := y15 ^ u7
	y10 := y15 ^ t0
	y11 := y20 ^ y9
	y7 := u7 ^ y11
	y17 := y10 ^ y11
	y19 := y10 ^ y8
	y16 := t0 ^ y11
	y21 := y13 ^ y16
	y18 := u0 ^ y16

	t2 := y12 & y15
	t3 := y3 & y6
	t4 := t3 ^ t2
	t5 := y4 & u7
	t6 := t5 ^ t2
	t7 := y13 & y16
	t8 := y5 & y1
	t9 := t8 ^ t7
	t10 := y2 & y7
	t11 := t10 ^ t7
	t12 := y9 & y11
	t13 := y14 & y17
	t14 := t13 ^ t12
	t15 := y8 & y10
	t16 := t15 ^ t12
	t17 := t4 ^ t14
	t18 := t6 ^ t16
	t19 := t9 ^ t14
	t20 := t11 ^ t16
	t21 := t17 ^ y20
	t22 := t18 ^ y19
	t23 := t19 ^ y21
	t24 := t20 ^ y18

	t25 := t21 ^ t22
	t26 := t21 & t23
	t27 := t24 ^ t26
	t28 := t25 & t27
	t29 := t28 ^ t22
	t30 := t23 ^ t24
	t31 := t22 ^ t26
	t32 := t31 & t30
	t33 := t32 ^ t24
	t34 := t23 ^ t33
	t35 := t27 ^ t33
	t36 := t24 & t35
	t37 := t36 ^ t34
	t38 := t27 ^ t36
	t39 := t29 & t38
	t40 := t25 ^ t39
	t41 := t40 ^ t37
	t42 := t29 ^ t33
	t43 := t29 ^ t40
	t44 := t33 ^ t37
	t45 := t42 ^ t41

	z0 := t44 & y15
	z1 := t37 & y6
	z2 := t33 & u7
	z3 := t43 & y16
	z4 := t40 & y1
	z5 := t29 & y7
	z6 := t42 & y11
	z7 := t45 & y17
	z8 := t41 & y10
	z9 := t44 & y12
	z10 := t37 & y3
	z11 := t33 & y4
	z12 := t43 & y13
	z13 := t40 & y5
	z14 := t29 & y2
	z15 := t42 & y9
	z16 := t45 & y14
	z17 := t41 & y8

	t46 := z15 ^ z16
	t47 := z10 ^ z11
	t48 := z5 ^ z13
	t49 := z9 ^ z10
	t50 := z2 ^ z12
	t51 := z2 ^ z5
	t52 := z7 ^ z8
	t53 := z0 ^ z3
	t54 := z6 ^ z7
	t55 := z16 ^ z17
	t56 := z12 ^ t48
	t57 := t50 ^ t53
	t58 := z4 ^ t46
	t59 := z3 ^ t54
	t60 := t46 ^ t57
	t61 := z14 ^ t57
	t62 := t52 ^ t58
	t63 := t49 ^ t58
	t64 := z4 ^ t59
	t65 := t61 ^ t62
	t66 := z1 ^ t63
	s0 := t59 ^ t63
	s6 := ^(t56 ^ t62)
	s7 := ^(t48 ^ t60)
	t67 := t64 ^ t65
	s3 := t53 ^ t66
	s4 := t51 ^ t66
	s5 := t47 ^ t65
	s1 := ^(t64 ^ s3)
	s2 := ^(t55 ^ t67)

	q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0] = s0, s1, s2, s3, s4, s5, s6, s7
}

// bsInvSubBytes evaluates the constant-time combinational AES inverse S-box
// circuit on all 64 bytes (4 AES blocks) in parallel.
func bsInvSubBytes(q *bsState) {
	p05 := q[0] ^ q[5]
	p14 := q[1] ^ q[4]
	p27 := q[2] ^ q[7]
	p36 := q[3] ^ q[6]

	u7 := ^(p27 ^ q[5])
	u6 := p36 ^ q[0]
	u5 := ^(p14 ^ q[7])
	u4 := p05 ^ q[2]
	u3 := p36 ^ q[1]
	u2 := p27 ^ q[4]
	u1 := p05 ^ q[3]
	u0 := p14 ^ q[6]

	y14 := u3 ^ u5
	y13 := u0 ^ u6
	y9 := u0 ^ u3
	y8 := u0 ^ u5
	t0 := u1 ^ u2
	y1 := t0 ^ u7
	y4 := y1 ^ u3
	y12 := y13 ^ y14
	y2 := y1 ^ u0
	y5 := y1 ^ u6
	y3 := y5 ^ y8
	t1 := u4 ^ y12
	y15 := t1 ^ u5
	y20 := t1 ^ u1
	y6 := y15 ^ u7
	y10 := y15 ^ t0
	y11 := y20 ^ y9
	y7 := u7 ^ y11
	y17 := y10 ^ y11
	y19 := y10 ^ y8
	y16 := t0 ^ y11
	y21 := y13 ^ y16
	y18 := u0 ^ y16

	t2 := y12 & y15
	t3 := y3 & y6
	t4 := t3 ^ t2
	t5 := y4 & u7
	t6 := t5 ^ t2
	t7 := y13 & y16
	t8 := y5 & y1
	t9 := t8 ^ t7
	t10 := y2 & y7
	t11 := t10 ^ t7
	t12 := y9 & y11
	t13 := y14 & y17
	t14 := t13 ^ t12
	t15 := y8 & y10
	t16 := t15 ^ t12
	t17 := t4 ^ t14
	t18 := t6 ^ t16
	t19 := t9 ^ t14
	t20 := t11 ^ t16
	t21 := t17 ^ y20
	t22 := t18 ^ y19
	t23 := t19 ^ y21
	t24 := t20 ^ y18

	t25 := t21 ^ t22
	t26 := t21 & t23
	t27 := t24 ^ t26
	t28 := t25 & t27
	t29 := t28 ^ t22
	t30 := t23 ^ t24
	t31 := t22 ^ t26
	t32 := t31 & t30
	t33 := t32 ^ t24
	t34 := t23 ^ t33
	t35 := t27 ^ t33
	t36 := t24 & t35
	t37 := t36 ^ t34
	t38 := t27 ^ t36
	t39 := t29 & t38
	t40 := t25 ^ t39
	t41 := t40 ^ t37
	t42 := t29 ^ t33
	t43 := t29 ^ t40
	t44 := t33 ^ t37
	t45 := t42 ^ t41

	z0 := t44 & y15
	z1 := t37 & y6
	z2 := t33 & u7
	z3 := t43 & y16
	z4 := t40 & y1
	z5 := t29 & y7
	z6 := t42 & y11
	z7 := t45 & y17
	z8 := t41 & y10
	z9 := t44 & y12
	z10 := t37 & y3
	z11 := t33 & y4
	z12 := t43 & y13
	z13 := t40 & y5
	z14 := t29 & y2
	z15 := t42 & y9
	z16 := t45 & y14
	z17 := t41 & y8

	t46 := z15 ^ z16
	t47 := z10 ^ z11
	t48 := z5 ^ z13
	t49 := z9 ^ z10
	t50 := z2 ^ z12
	t51 := z2 ^ z5
	t52 := z7 ^ z8
	t53 := z0 ^ z3
	t54 := z6 ^ z7
	t55 := z16 ^ z17
	t56 := z12 ^ t48
	t57 := t50 ^ t53
	t58 := z4 ^ t46
	t59 := z3 ^ t54
	t60 := t46 ^ t57
	t61 := z14 ^ t57
	t62 := t52 ^ t58
	t63 := t49 ^ t58
	t64 := z4 ^ t59
	t65 := t61 ^ t62
	t66 := z1 ^ t63
	w7 := t59 ^ t63
	w1 := t56 ^ t62
	w0 := t48 ^ t60
	t67 := t64 ^ t65
	w4 := t53 ^ t66
	w3 := t51 ^ t66
	w2 := t47 ^ t65
	w6 := t64 ^ w4
	w5 := t55 ^ t67

	q05 := w0 ^ w5
	q14 := w1 ^ w4
	q27 := w2 ^ w7
	q36 := w3 ^ w6

	q[0] = q27 ^ w5
	q[1] = q36 ^ w0
	q[2] = q14 ^ w7
	q[3] = q05 ^ w2
	q[4] = q36 ^ w1
	q[5] = q27 ^ w4
	q[6] = q05 ^ w3
	q[7] = q14 ^ w6
}

func bsShiftRows(q *bsState) {
	for k := 0; k < 8; k++ {
		x := q[k]
		q[k] = uint64(uint16(x)) |
			uint64(bits.RotateLeft16(uint16(x>>16), -4))<<16 |
			uint64(bits.RotateLeft16(uint16(x>>32), 8))<<32 |
			uint64(bits.RotateLeft16(uint16(x>>48), 4))<<48
	}
}

func bsInvShiftRows(q *bsState) {
	for k := 0; k < 8; k++ {
		x := q[k]
		q[k] = uint64(uint16(x)) |
			uint64(bits.RotateLeft16(uint16(x>>16), 4))<<16 |
			uint64(bits.RotateLeft16(uint16(x>>32), 8))<<32 |
			uint64(bits.RotateLeft16(uint16(x>>48), -4))<<48
	}
}

func bsMixColumns(q *bsState) {
	var a, b [8]uint64
	for k := 0; k < 8; k++ {
		r1 := bits.RotateLeft64(q[k], -16)
		ak := q[k] ^ r1
		a[k] = ak
		b[k] = r1 ^ bits.RotateLeft64(ak, 32)
	}
	a7 := a[7]
	q[0] = a7 ^ b[0]
	q[1] = a[0] ^ a7 ^ b[1]
	q[2] = a[1] ^ b[2]
	q[3] = a[2] ^ a7 ^ b[3]
	q[4] = a[3] ^ a7 ^ b[4]
	q[5] = a[4] ^ b[5]
	q[6] = a[5] ^ b[6]
	q[7] = a[6] ^ b[7]
	clear(a[:])
	clear(b[:])
	runtime.KeepAlive(&a)
	runtime.KeepAlive(&b)
}

func bsInvMixColumns(q *bsState) {
	var d, u, f [8]uint64
	for k := 0; k < 8; k++ {
		d[k] = q[k] ^ bits.RotateLeft64(q[k], 32)
	}
	d6, d7 := d[6], d[7]
	d67 := d6 ^ d7
	u[0] = d6
	u[1] = d67
	u[2] = d[0] ^ d7
	u[3] = d[1] ^ d6
	u[4] = d[2] ^ d67
	u[5] = d[3] ^ d7
	u[6] = d[4]
	u[7] = d[5]

	for k := 0; k < 8; k++ {
		f[k] = u[k] ^ bits.RotateLeft64(u[k], -16)
	}
	bsMixColumns(q)
	f7 := f[7]
	q[0] ^= u[0] ^ f7
	q[1] ^= u[1] ^ f[0] ^ f7
	q[2] ^= u[2] ^ f[1]
	q[3] ^= u[3] ^ f[2] ^ f7
	q[4] ^= u[4] ^ f[3] ^ f7
	q[5] ^= u[5] ^ f[4]
	q[6] ^= u[6] ^ f[5]
	q[7] ^= u[7] ^ f[6]
	clear(d[:])
	clear(u[:])
	clear(f[:])
	runtime.KeepAlive(&d)
	runtime.KeepAlive(&u)
	runtime.KeepAlive(&f)
}

func bsXor(dst, src *bsState) {
	for k := 0; k < 8; k++ {
		dst[k] ^= src[k]
	}
}

func bsRoundNoKey(q *bsState) {
	bsSubBytes(q)
	bsShiftRows(q)
	bsMixColumns(q)
}

func bsFinalRoundNoKey(q *bsState) {
	bsSubBytes(q)
	bsShiftRows(q)
}

func bsInvFinalRoundNoKey(q *bsState) {
	bsInvShiftRows(q)
	bsInvSubBytes(q)
}

func getBSRC(rcs *[15][16]byte) *[15]bsState {
	if rcs == &roundConstantsP1 {
		return &bsRCP1
	}
	if rcs == &roundConstantsP2 {
		return &bsRCP2
	}
	var custom [15]bsState
	for r := 0; r < 15; r++ {
		bsPackBroadcast(&custom[r], &rcs[r])
	}
	return &custom
}

//go:noinline
func wipeSoftwareStack() {
	var frame [128]uint64
	clear(frame[:])
	runtime.KeepAlive(&frame)
}

func roundNoKey(block *Block) {
	var q bsState
	bsPack1(&q, block)
	bsRoundNoKey(&q)
	bsUnpack1(&q, block)
	clear(q[:])
	runtime.KeepAlive(&q)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func finalRoundNoKey(block *Block) {
	var q bsState
	bsPack1(&q, block)
	bsFinalRoundNoKey(&q)
	bsUnpack1(&q, block)
	clear(q[:])
	runtime.KeepAlive(&q)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

// xorBlock sets dst = a ⊕ b. It makes no alignment assumption about its
// operands, so it is safe on every architecture the portable path serves.
func xorBlock(dst, a, b *Block) {
	lo := binary.LittleEndian.Uint64(a[0:8]) ^ binary.LittleEndian.Uint64(b[0:8])
	hi := binary.LittleEndian.Uint64(a[8:16]) ^ binary.LittleEndian.Uint64(b[8:16])
	binary.LittleEndian.PutUint64(dst[0:8], lo)
	binary.LittleEndian.PutUint64(dst[8:16], hi)
}

func areion256PermuteBS(x0, x1 *bsState, rcs *[15]bsState) {
	var temp bsState
	for r := 0; r < 10; r += 2 {
		bsSubBytes(x0)
		bsShiftRows(x0)
		temp = *x0
		bsMixColumns(&temp)
		bsXor(&temp, &rcs[r])
		bsRoundNoKey(&temp)
		bsXor(x1, &temp)

		bsSubBytes(x1)
		bsShiftRows(x1)
		temp = *x1
		bsMixColumns(&temp)
		bsXor(&temp, &rcs[r+1])
		bsRoundNoKey(&temp)
		bsXor(x0, &temp)
	}
	clear(temp[:])
	runtime.KeepAlive(&temp)
}

func areion256InversePermuteBS(x0, x1 *bsState, rcs *[15]bsState) {
	var temp bsState
	for i := 0; i < 10; i += 2 {
		temp = *x1
		bsMixColumns(&temp)
		bsXor(&temp, &rcs[9-i])
		bsRoundNoKey(&temp)
		bsXor(x0, &temp)
		bsInvFinalRoundNoKey(x1)

		temp = *x0
		bsMixColumns(&temp)
		bsXor(&temp, &rcs[8-i])
		bsRoundNoKey(&temp)
		bsXor(x1, &temp)
		bsInvFinalRoundNoKey(x0)
	}
	clear(temp[:])
	runtime.KeepAlive(&temp)
}

func areion512RoundBS12(a, b, c, d, ac, tmp *bsState, rc *bsState) {
	for k := 0; k < 8; k++ {
		ac[k] = (a[k] & bsLane01Mask) | ((c[k] & bsLane01Mask) << 2)
	}
	bsSubBytes(ac)
	bsShiftRows(ac)
	*tmp = *ac
	bsMixColumns(tmp)
	for k := 0; k < 8; k++ {
		a[k] = ac[k] & bsLane01Mask
		b[k] ^= tmp[k] & bsLane01Mask
		d[k] ^= (tmp[k] >> 2) & bsLane01Mask
		c[k] = ((ac[k] >> 2) & bsLane01Mask) ^ (rc[k] & bsLane01Mask)
	}
	bsRoundNoKey(c)
}

func areion512PermuteBS12(x0, x1, x2, x3 *bsState, rcs *[15]bsState) {
	var ac, tmp bsState
	for i := 0; i < 12; i += 4 {
		areion512RoundBS12(x0, x1, x2, x3, &ac, &tmp, &rcs[i+0])
		areion512RoundBS12(x1, x2, x3, x0, &ac, &tmp, &rcs[i+1])
		areion512RoundBS12(x2, x3, x0, x1, &ac, &tmp, &rcs[i+2])
		areion512RoundBS12(x3, x0, x1, x2, &ac, &tmp, &rcs[i+3])
	}
	areion512RoundBS12(x0, x1, x2, x3, &ac, &tmp, &rcs[12])
	areion512RoundBS12(x1, x2, x3, x0, &ac, &tmp, &rcs[13])
	areion512RoundBS12(x2, x3, x0, x1, &ac, &tmp, &rcs[14])

	*x0, *x1, *x2, *x3 = *x3, *x0, *x1, *x2
	clear(ac[:])
	clear(tmp[:])
	runtime.KeepAlive(&ac)
	runtime.KeepAlive(&tmp)
}

func areion512RoundBS4(a, b, c, d, tmp *bsState, rc *bsState) {
	bsSubBytes(a)
	bsShiftRows(a)
	*tmp = *a
	bsMixColumns(tmp)
	bsXor(b, tmp)

	bsSubBytes(c)
	bsShiftRows(c)
	*tmp = *c
	bsMixColumns(tmp)
	bsXor(d, tmp)

	bsXor(c, rc)
	bsRoundNoKey(c)
}

func areion512PermuteBS4(x0, x1, x2, x3 *bsState, rcs *[15]bsState) {
	var tmp bsState
	for i := 0; i < 12; i += 4 {
		areion512RoundBS4(x0, x1, x2, x3, &tmp, &rcs[i+0])
		areion512RoundBS4(x1, x2, x3, x0, &tmp, &rcs[i+1])
		areion512RoundBS4(x2, x3, x0, x1, &tmp, &rcs[i+2])
		areion512RoundBS4(x3, x0, x1, x2, &tmp, &rcs[i+3])
	}
	areion512RoundBS4(x0, x1, x2, x3, &tmp, &rcs[12])
	areion512RoundBS4(x1, x2, x3, x0, &tmp, &rcs[13])
	areion512RoundBS4(x2, x3, x0, x1, &tmp, &rcs[14])

	*x0, *x1, *x2, *x3 = *x3, *x0, *x1, *x2
	clear(tmp[:])
	runtime.KeepAlive(&tmp)
}

func areion512InvRoundBS12(a, b, c, d, ac, tmp *bsState, rc *bsState) {
	*tmp = *a
	bsMixColumns(tmp)
	bsXor(b, tmp)

	bsInvMixColumns(c)
	for k := 0; k < 8; k++ {
		ac[k] = (a[k] & bsLane01Mask) | ((c[k] & bsLane01Mask) << 2)
	}
	bsInvShiftRows(ac)
	bsInvSubBytes(ac)
	for k := 0; k < 8; k++ {
		a[k] = ac[k] & bsLane01Mask
		c[k] = ((ac[k] >> 2) & bsLane01Mask) ^ (rc[k] & bsLane01Mask)
	}
	*tmp = *c
	bsMixColumns(tmp)
	bsXor(d, tmp)
	bsInvFinalRoundNoKey(c)
}

func areion512InversePermuteBS12(x0, x1, x2, x3 *bsState, rcs *[15]bsState) {
	*x0, *x1, *x2, *x3 = *x1, *x2, *x3, *x0

	var ac, tmp bsState
	areion512InvRoundBS12(x2, x3, x0, x1, &ac, &tmp, &rcs[14])
	areion512InvRoundBS12(x1, x2, x3, x0, &ac, &tmp, &rcs[13])
	areion512InvRoundBS12(x0, x1, x2, x3, &ac, &tmp, &rcs[12])

	for i := 0; i < 12; i += 4 {
		areion512InvRoundBS12(x3, x0, x1, x2, &ac, &tmp, &rcs[11-i])
		areion512InvRoundBS12(x2, x3, x0, x1, &ac, &tmp, &rcs[10-i])
		areion512InvRoundBS12(x1, x2, x3, x0, &ac, &tmp, &rcs[9-i])
		areion512InvRoundBS12(x0, x1, x2, x3, &ac, &tmp, &rcs[8-i])
	}
	clear(ac[:])
	clear(tmp[:])
	runtime.KeepAlive(&ac)
	runtime.KeepAlive(&tmp)
}

func areion512InvRoundBS4(a, b, c, d, tmp *bsState, rc *bsState) {
	*tmp = *a
	bsMixColumns(tmp)
	bsXor(b, tmp)
	bsInvFinalRoundNoKey(a)

	bsInvMixColumns(c)
	bsInvFinalRoundNoKey(c)
	bsXor(c, rc)
	*tmp = *c
	bsMixColumns(tmp)
	bsXor(d, tmp)
	bsInvFinalRoundNoKey(c)
}

func areion512InversePermuteBS4(x0, x1, x2, x3 *bsState, rcs *[15]bsState) {
	*x0, *x1, *x2, *x3 = *x1, *x2, *x3, *x0

	var tmp bsState
	areion512InvRoundBS4(x2, x3, x0, x1, &tmp, &rcs[14])
	areion512InvRoundBS4(x1, x2, x3, x0, &tmp, &rcs[13])
	areion512InvRoundBS4(x0, x1, x2, x3, &tmp, &rcs[12])

	for i := 0; i < 12; i += 4 {
		areion512InvRoundBS4(x3, x0, x1, x2, &tmp, &rcs[11-i])
		areion512InvRoundBS4(x2, x3, x0, x1, &tmp, &rcs[10-i])
		areion512InvRoundBS4(x1, x2, x3, x0, &tmp, &rcs[9-i])
		areion512InvRoundBS4(x0, x1, x2, x3, &tmp, &rcs[8-i])
	}
	clear(tmp[:])
	runtime.KeepAlive(&tmp)
}

// areion256PermuteSoftwareRC runs 10 rounds of Areion-256 with the specified round constants.
func areion256PermuteSoftwareRC(state *State256, rcs *[15][16]byte) {
	var x0, x1 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256PermuteBS(&x0, &x1, getBSRC(rcs))
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	clear(x0[:])
	clear(x1[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

// areion256InversePermuteSoftwareRC runs 10 inverse rounds of Areion-256 with the specified round constants.
func areion256InversePermuteSoftwareRC(state *State256, rcs *[15][16]byte) {
	var x0, x1 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256InversePermuteBS(&x0, &x1, getBSRC(rcs))
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	clear(x0[:])
	clear(x1[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

// areion512PermuteSoftwareRC runs 15 rounds of Areion-512 with the specified round constants.
func areion512PermuteSoftwareRC(state *State512, rcs *[15][16]byte) {
	var x0, x1, x2, x3 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, getBSRC(rcs))
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

// areion512InversePermuteSoftwareRC runs 15 inverse rounds of Areion-512 with the specified round constants.
func areion512InversePermuteSoftwareRC(state *State512, rcs *[15][16]byte) {
	var x0, x1, x2, x3 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512InversePermuteBS12(&x0, &x1, &x2, &x3, getBSRC(rcs))
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func areion256Permutex4SoftwareRC(states *[4][32]byte, rcs *[15][16]byte) {
	var x0, x1 bsState
	bsPack4(&x0, (*Block)(states[0][0:16]), (*Block)(states[1][0:16]), (*Block)(states[2][0:16]), (*Block)(states[3][0:16]))
	bsPack4(&x1, (*Block)(states[0][16:32]), (*Block)(states[1][16:32]), (*Block)(states[2][16:32]), (*Block)(states[3][16:32]))
	areion256PermuteBS(&x0, &x1, getBSRC(rcs))
	bsUnpack4(&x0, (*Block)(states[0][0:16]), (*Block)(states[1][0:16]), (*Block)(states[2][0:16]), (*Block)(states[3][0:16]))
	bsUnpack4(&x1, (*Block)(states[0][16:32]), (*Block)(states[1][16:32]), (*Block)(states[2][16:32]), (*Block)(states[3][16:32]))
	clear(x0[:])
	clear(x1[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func areion256InversePermutex4SoftwareRC(states *[4][32]byte, rcs *[15][16]byte) {
	var x0, x1 bsState
	bsPack4(&x0, (*Block)(states[0][0:16]), (*Block)(states[1][0:16]), (*Block)(states[2][0:16]), (*Block)(states[3][0:16]))
	bsPack4(&x1, (*Block)(states[0][16:32]), (*Block)(states[1][16:32]), (*Block)(states[2][16:32]), (*Block)(states[3][16:32]))
	areion256InversePermuteBS(&x0, &x1, getBSRC(rcs))
	bsUnpack4(&x0, (*Block)(states[0][0:16]), (*Block)(states[1][0:16]), (*Block)(states[2][0:16]), (*Block)(states[3][0:16]))
	bsUnpack4(&x1, (*Block)(states[0][16:32]), (*Block)(states[1][16:32]), (*Block)(states[2][16:32]), (*Block)(states[3][16:32]))
	clear(x0[:])
	clear(x1[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func areion512Permutex4SoftwareRC(states *[4][64]byte, rcs *[15][16]byte) {
	var x0, x1, x2, x3 bsState
	bsPack4(&x0, (*Block)(states[0][0:16]), (*Block)(states[1][0:16]), (*Block)(states[2][0:16]), (*Block)(states[3][0:16]))
	bsPack4(&x1, (*Block)(states[0][16:32]), (*Block)(states[1][16:32]), (*Block)(states[2][16:32]), (*Block)(states[3][16:32]))
	bsPack4(&x2, (*Block)(states[0][32:48]), (*Block)(states[1][32:48]), (*Block)(states[2][32:48]), (*Block)(states[3][32:48]))
	bsPack4(&x3, (*Block)(states[0][48:64]), (*Block)(states[1][48:64]), (*Block)(states[2][48:64]), (*Block)(states[3][48:64]))
	areion512PermuteBS4(&x0, &x1, &x2, &x3, getBSRC(rcs))
	bsUnpack4(&x0, (*Block)(states[0][0:16]), (*Block)(states[1][0:16]), (*Block)(states[2][0:16]), (*Block)(states[3][0:16]))
	bsUnpack4(&x1, (*Block)(states[0][16:32]), (*Block)(states[1][16:32]), (*Block)(states[2][16:32]), (*Block)(states[3][16:32]))
	bsUnpack4(&x2, (*Block)(states[0][32:48]), (*Block)(states[1][32:48]), (*Block)(states[2][32:48]), (*Block)(states[3][32:48]))
	bsUnpack4(&x3, (*Block)(states[0][48:64]), (*Block)(states[1][48:64]), (*Block)(states[2][48:64]), (*Block)(states[3][48:64]))
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func areion512InversePermutex4SoftwareRC(states *[4][64]byte, rcs *[15][16]byte) {
	var x0, x1, x2, x3 bsState
	bsPack4(&x0, (*Block)(states[0][0:16]), (*Block)(states[1][0:16]), (*Block)(states[2][0:16]), (*Block)(states[3][0:16]))
	bsPack4(&x1, (*Block)(states[0][16:32]), (*Block)(states[1][16:32]), (*Block)(states[2][16:32]), (*Block)(states[3][16:32]))
	bsPack4(&x2, (*Block)(states[0][32:48]), (*Block)(states[1][32:48]), (*Block)(states[2][32:48]), (*Block)(states[3][32:48]))
	bsPack4(&x3, (*Block)(states[0][48:64]), (*Block)(states[1][48:64]), (*Block)(states[2][48:64]), (*Block)(states[3][48:64]))
	areion512InversePermuteBS4(&x0, &x1, &x2, &x3, getBSRC(rcs))
	bsUnpack4(&x0, (*Block)(states[0][0:16]), (*Block)(states[1][0:16]), (*Block)(states[2][0:16]), (*Block)(states[3][0:16]))
	bsUnpack4(&x1, (*Block)(states[0][16:32]), (*Block)(states[1][16:32]), (*Block)(states[2][16:32]), (*Block)(states[3][16:32]))
	bsUnpack4(&x2, (*Block)(states[0][32:48]), (*Block)(states[1][32:48]), (*Block)(states[2][32:48]), (*Block)(states[3][32:48]))
	bsUnpack4(&x3, (*Block)(states[0][48:64]), (*Block)(states[1][48:64]), (*Block)(states[2][48:64]), (*Block)(states[3][48:64]))
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

// soem256Software evaluates SoEM22 in constant-time bitsliced pure Go software,
// running P1 and P2 simultaneously in lanes 0 and 1.
func soem256Software(key *[64]byte, input *[32]byte) [32]byte {
	var state1, state2 State256
	for i := 0; i < 32; i += 8 {
		m := binary.LittleEndian.Uint64(input[i : i+8])
		k1 := binary.LittleEndian.Uint64(key[i : i+8])
		k2 := binary.LittleEndian.Uint64(key[32+i : 32+i+8])
		binary.LittleEndian.PutUint64(state1[i:i+8], m^k1)
		binary.LittleEndian.PutUint64(state2[i:i+8], m^k2)
	}
	var x0, x1 bsState
	bsPack2(&x0, (*Block)(state1[0:16]), (*Block)(state2[0:16]))
	bsPack2(&x1, (*Block)(state1[16:32]), (*Block)(state2[16:32]))
	areion256PermuteBS(&x0, &x1, &bsRCP1P2)
	bsUnpack2(&x0, (*Block)(state1[0:16]), (*Block)(state2[0:16]))
	bsUnpack2(&x1, (*Block)(state1[16:32]), (*Block)(state2[16:32]))
	var out [32]byte
	for i := 0; i < 32; i += 8 {
		v1 := binary.LittleEndian.Uint64(state1[i : i+8])
		v2 := binary.LittleEndian.Uint64(state2[i : i+8])
		k1 := binary.LittleEndian.Uint64(key[i : i+8])
		k2 := binary.LittleEndian.Uint64(key[32+i : 32+i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v1^v2^k1^k2)
	}
	clear(x0[:])
	clear(x1[:])
	clear(state1[:])
	clear(state2[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&state1)
	runtime.KeepAlive(&state2)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return out
}

// soem512Software evaluates SoEM22 in constant-time bitsliced pure Go software,
// running P1 and P2 simultaneously in lanes 0 and 1.
func soem512Software(key *[128]byte, input *[64]byte) [64]byte {
	var state1, state2 State512
	for i := 0; i < 64; i += 8 {
		m := binary.LittleEndian.Uint64(input[i : i+8])
		k1 := binary.LittleEndian.Uint64(key[i : i+8])
		k2 := binary.LittleEndian.Uint64(key[64+i : 64+i+8])
		binary.LittleEndian.PutUint64(state1[i:i+8], m^k1)
		binary.LittleEndian.PutUint64(state2[i:i+8], m^k2)
	}
	var x0, x1, x2, x3 bsState
	bsPack2(&x0, (*Block)(state1[0:16]), (*Block)(state2[0:16]))
	bsPack2(&x1, (*Block)(state1[16:32]), (*Block)(state2[16:32]))
	bsPack2(&x2, (*Block)(state1[32:48]), (*Block)(state2[32:48]))
	bsPack2(&x3, (*Block)(state1[48:64]), (*Block)(state2[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, &bsRCP1P2)
	bsUnpack2(&x0, (*Block)(state1[0:16]), (*Block)(state2[0:16]))
	bsUnpack2(&x1, (*Block)(state1[16:32]), (*Block)(state2[16:32]))
	bsUnpack2(&x2, (*Block)(state1[32:48]), (*Block)(state2[32:48]))
	bsUnpack2(&x3, (*Block)(state1[48:64]), (*Block)(state2[48:64]))
	var out [64]byte
	for i := 0; i < 64; i += 8 {
		v1 := binary.LittleEndian.Uint64(state1[i : i+8])
		v2 := binary.LittleEndian.Uint64(state2[i : i+8])
		k1 := binary.LittleEndian.Uint64(key[i : i+8])
		k2 := binary.LittleEndian.Uint64(key[64+i : 64+i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v1^v2^k1^k2)
	}
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	clear(state1[:])
	clear(state2[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	runtime.KeepAlive(&state1)
	runtime.KeepAlive(&state2)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return out
}

func soem256x4Software(keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte {
	var state1, state2 [4]State256
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			m := binary.LittleEndian.Uint64(inputs[lane][i : i+8])
			k1 := binary.LittleEndian.Uint64(keys[lane][i : i+8])
			k2 := binary.LittleEndian.Uint64(keys[lane][32+i : 32+i+8])
			binary.LittleEndian.PutUint64(state1[lane][i:i+8], m^k1)
			binary.LittleEndian.PutUint64(state2[lane][i:i+8], m^k2)
		}
	}
	areion256Permutex4SoftwareRC(&state1, &roundConstantsP1)
	areion256Permutex4SoftwareRC(&state2, &roundConstantsP2)
	var out [4][32]byte
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v1 := binary.LittleEndian.Uint64(state1[lane][i : i+8])
			v2 := binary.LittleEndian.Uint64(state2[lane][i : i+8])
			k1 := binary.LittleEndian.Uint64(keys[lane][i : i+8])
			k2 := binary.LittleEndian.Uint64(keys[lane][32+i : 32+i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v1^v2^k1^k2)
		}
	}
	clear(state1[:])
	clear(state2[:])
	runtime.KeepAlive(&state1)
	runtime.KeepAlive(&state2)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return out
}

func soem512x4Software(keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte {
	var state1, state2 [4]State512
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			m := binary.LittleEndian.Uint64(inputs[lane][i : i+8])
			k1 := binary.LittleEndian.Uint64(keys[lane][i : i+8])
			k2 := binary.LittleEndian.Uint64(keys[lane][64+i : 64+i+8])
			binary.LittleEndian.PutUint64(state1[lane][i:i+8], m^k1)
			binary.LittleEndian.PutUint64(state2[lane][i:i+8], m^k2)
		}
	}
	areion512Permutex4SoftwareRC(&state1, &roundConstantsP1)
	areion512Permutex4SoftwareRC(&state2, &roundConstantsP2)
	var out [4][64]byte
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v1 := binary.LittleEndian.Uint64(state1[lane][i : i+8])
			v2 := binary.LittleEndian.Uint64(state2[lane][i : i+8])
			k1 := binary.LittleEndian.Uint64(keys[lane][i : i+8])
			k2 := binary.LittleEndian.Uint64(keys[lane][64+i : 64+i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v1^v2^k1^k2)
		}
	}
	clear(state1[:])
	clear(state2[:])
	runtime.KeepAlive(&state1)
	runtime.KeepAlive(&state2)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return out
}

// xorBlock4 sets dst = a ⊕ b on 64-byte (4-block) vectors.
func xorBlock4(dst, a, b *Block4) {
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(a[i:i+8]) ^ binary.LittleEndian.Uint64(b[i:i+8])
		binary.LittleEndian.PutUint64(dst[i:i+8], v)
	}
}

var aesRcon = [11]uint32{
	0x00,
	0x01, 0x02, 0x04, 0x08,
	0x10, 0x20, 0x40, 0x80,
	0x1b, 0x36,
}

func bsSubWord(rot uint32) uint32 {
	r := uint64(rot)
	w := bsState{
		r & bsByte0Mask,
		(r >> 1) & bsByte0Mask,
		(r >> 2) & bsByte0Mask,
		(r >> 3) & bsByte0Mask,
		(r >> 4) & bsByte0Mask,
		(r >> 5) & bsByte0Mask,
		(r >> 6) & bsByte0Mask,
		(r >> 7) & bsByte0Mask,
	}
	bsSubBytes(&w)
	out := (w[0] & bsByte0Mask) |
		((w[1] & bsByte0Mask) << 1) |
		((w[2] & bsByte0Mask) << 2) |
		((w[3] & bsByte0Mask) << 3) |
		((w[4] & bsByte0Mask) << 4) |
		((w[5] & bsByte0Mask) << 5) |
		((w[6] & bsByte0Mask) << 6) |
		((w[7] & bsByte0Mask) << 7)
	clear(w[:])
	runtime.KeepAlive(&w)
	return uint32(out)
}

func expandKey128(key *[16]byte, rk *[11][16]byte) {
	var w [44]uint32
	for i := 0; i < 4; i++ {
		w[i] = binary.LittleEndian.Uint32(key[i*4 : i*4+4])
	}
	var blk, zeroBlk Block
	useHW := (hasAESNI || hasARMCrypto) && TierCode() != TierPureGo
	for i := 4; i < 44; i++ {
		temp := w[i-1]
		if i%4 == 0 {
			rot := (temp >> 8) | (temp << 24)
			if useHW {
				binary.LittleEndian.PutUint32(blk[0:4], rot)
				binary.LittleEndian.PutUint32(blk[4:8], rot)
				binary.LittleEndian.PutUint32(blk[8:12], rot)
				binary.LittleEndian.PutUint32(blk[12:16], rot)
				aesFinalRoundHW(&blk, &zeroBlk)
				temp = binary.LittleEndian.Uint32(blk[0:4]) ^ aesRcon[i/4]
			} else {
				temp = bsSubWord(rot) ^ aesRcon[i/4]
			}
		}
		w[i] = w[i-4] ^ temp
	}
	for r := 0; r < 11; r++ {
		for j := 0; j < 4; j++ {
			binary.LittleEndian.PutUint32(rk[r][j*4:j*4+4], w[r*4+j])
		}
	}
	clear(w[:])
	clear(blk[:])
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&blk)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func aesRound4Software(blocks, roundKeys *Block4) {
	var q bsState
	rk := *roundKeys
	bsPack4(&q, (*Block)(blocks[0:16]), (*Block)(blocks[16:32]), (*Block)(blocks[32:48]), (*Block)(blocks[48:64]))
	bsRoundNoKey(&q)
	bsUnpack4(&q, (*Block)(blocks[0:16]), (*Block)(blocks[16:32]), (*Block)(blocks[32:48]), (*Block)(blocks[48:64]))
	xorBlock4(blocks, blocks, &rk)
	clear(rk[:])
	clear(q[:])
	runtime.KeepAlive(&rk)
	runtime.KeepAlive(&q)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func aesFinalRound4Software(blocks, roundKeys *Block4) {
	var q bsState
	rk := *roundKeys
	bsPack4(&q, (*Block)(blocks[0:16]), (*Block)(blocks[16:32]), (*Block)(blocks[32:48]), (*Block)(blocks[48:64]))
	bsFinalRoundNoKey(&q)
	bsUnpack4(&q, (*Block)(blocks[0:16]), (*Block)(blocks[16:32]), (*Block)(blocks[32:48]), (*Block)(blocks[48:64]))
	xorBlock4(blocks, blocks, &rk)
	clear(rk[:])
	clear(q[:])
	runtime.KeepAlive(&rk)
	runtime.KeepAlive(&q)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func aes128EncryptBlockSoftware(rk *[11][16]byte, dst, src *[16]byte) {
	var state Block
	xorBlock(&state, src, &rk[0])
	var q, k14, k58, k910 bsState
	bsPack1(&q, &state)
	bsPack4(&k14, &rk[1], &rk[2], &rk[3], &rk[4])
	bsPack4(&k58, &rk[5], &rk[6], &rk[7], &rk[8])
	bsPack2(&k910, &rk[9], &rk[10])

	for lane := uint(0); lane < 4; lane++ {
		bsRoundNoKey(&q)
		for k := 0; k < 8; k++ {
			q[k] ^= (k14[k] >> lane) & bsLane0Mask
		}
	}
	for lane := uint(0); lane < 4; lane++ {
		bsRoundNoKey(&q)
		for k := 0; k < 8; k++ {
			q[k] ^= (k58[k] >> lane) & bsLane0Mask
		}
	}
	bsRoundNoKey(&q)
	for k := 0; k < 8; k++ {
		q[k] ^= k910[k] & bsLane0Mask
	}
	bsFinalRoundNoKey(&q)
	for k := 0; k < 8; k++ {
		q[k] ^= (k910[k] >> 1) & bsLane0Mask
	}
	bsUnpack1(&q, dst)
	clear(state[:])
	clear(q[:])
	clear(k14[:])
	clear(k58[:])
	clear(k910[:])
	runtime.KeepAlive(&state)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&k14)
	runtime.KeepAlive(&k58)
	runtime.KeepAlive(&k910)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func aes128Encrypt4BlocksSoftware(rk *[11][16]byte, dst, src *[64]byte) {
	var b [4]Block
	for lane := 0; lane < 4; lane++ {
		xorBlock(&b[lane], (*Block)(src[lane*16:lane*16+16]), &rk[0])
	}
	var q, k14, k58, k910 bsState
	bsPack4(&q, &b[0], &b[1], &b[2], &b[3])
	bsPack4(&k14, &rk[1], &rk[2], &rk[3], &rk[4])
	bsPack4(&k58, &rk[5], &rk[6], &rk[7], &rk[8])
	bsPack2(&k910, &rk[9], &rk[10])

	for lane := uint(0); lane < 4; lane++ {
		bsRoundNoKey(&q)
		for k := 0; k < 8; k++ {
			q[k] ^= ((k14[k] >> lane) & bsLane0Mask) * 0xf
		}
	}
	for lane := uint(0); lane < 4; lane++ {
		bsRoundNoKey(&q)
		for k := 0; k < 8; k++ {
			q[k] ^= ((k58[k] >> lane) & bsLane0Mask) * 0xf
		}
	}
	bsRoundNoKey(&q)
	for k := 0; k < 8; k++ {
		q[k] ^= (k910[k] & bsLane0Mask) * 0xf
	}
	bsFinalRoundNoKey(&q)
	for k := 0; k < 8; k++ {
		q[k] ^= ((k910[k] >> 1) & bsLane0Mask) * 0xf
	}
	bsUnpack4(&q, (*Block)(dst[0:16]), (*Block)(dst[16:32]), (*Block)(dst[32:48]), (*Block)(dst[48:64]))
	clear(b[:])
	clear(q[:])
	clear(k14[:])
	clear(k58[:])
	clear(k910[:])
	runtime.KeepAlive(&b)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&k14)
	runtime.KeepAlive(&k58)
	runtime.KeepAlive(&k910)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func emEncrypt256Software(out, m *[32]byte, k *[64]byte) {
	var state State256
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(m[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	var x0, x1 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256PermuteBS(&x0, &x1, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(k[32+i:32+i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func emDecrypt256Software(out, c *[32]byte, k *[64]byte) {
	var state State256
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(c[i:i+8]) ^ binary.LittleEndian.Uint64(k[32+i:32+i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	var x0, x1 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256InversePermuteBS(&x0, &x1, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func emEncrypt512Software(out, m *[64]byte, k *[128]byte) {
	var state State512
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(m[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	var x0, x1, x2, x3 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(k[64+i:64+i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func emDecrypt512Software(out, c *[64]byte, k *[128]byte) {
	var state State512
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(c[i:i+8]) ^ binary.LittleEndian.Uint64(k[64+i:64+i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	var x0, x1, x2, x3 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512InversePermuteBS12(&x0, &x1, &x2, &x3, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func emEncrypt256x4Software(out, msgs *[4][32]byte, keys *[4][64]byte) {
	var states [4]State256
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(msgs[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion256Permutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][32+i:32+i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(states[:])
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func emDecrypt256x4Software(out, ct *[4][32]byte, keys *[4][64]byte) {
	var states [4]State256
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(ct[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][32+i:32+i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion256InversePermutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(states[:])
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func emEncrypt512x4Software(out, msgs *[4][64]byte, keys *[4][128]byte) {
	var states [4]State512
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(msgs[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion512Permutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][64+i:64+i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(states[:])
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func emDecrypt512x4Software(out, ct *[4][64]byte, keys *[4][128]byte) {
	var states [4]State512
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(ct[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][64+i:64+i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion512InversePermutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(states[:])
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func em2Encrypt256Software(out, m *[32]byte, k *[64]byte) {
	var state State256
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(m[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	var x0, x1 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256PermuteBS(&x0, &x1, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(k[32+i:32+i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256PermuteBS(&x0, &x1, &bsRCP2)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^
			binary.LittleEndian.Uint64(k[i:i+8]) ^
			binary.LittleEndian.Uint64(k[32+i:32+i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func em2Decrypt256Software(out, c *[32]byte, k *[64]byte) {
	var state State256
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(c[i:i+8]) ^
			binary.LittleEndian.Uint64(k[i:i+8]) ^
			binary.LittleEndian.Uint64(k[32+i:32+i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	var x0, x1 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256InversePermuteBS(&x0, &x1, &bsRCP2)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(k[32+i:32+i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256InversePermuteBS(&x0, &x1, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func em2Encrypt512Software(out, m *[64]byte, k *[128]byte) {
	var state State512
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(m[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	var x0, x1, x2, x3 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(k[64+i:64+i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, &bsRCP2)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^
			binary.LittleEndian.Uint64(k[i:i+8]) ^
			binary.LittleEndian.Uint64(k[64+i:64+i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func em2Decrypt512Software(out, c *[64]byte, k *[128]byte) {
	var state State512
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(c[i:i+8]) ^
			binary.LittleEndian.Uint64(k[i:i+8]) ^
			binary.LittleEndian.Uint64(k[64+i:64+i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	var x0, x1, x2, x3 bsState
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512InversePermuteBS12(&x0, &x1, &x2, &x3, &bsRCP2)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(k[64+i:64+i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512InversePermuteBS12(&x0, &x1, &x2, &x3, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func em2Encrypt256x4Software(out, msgs *[4][32]byte, keys *[4][64]byte) {
	var states [4]State256
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(msgs[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion256Permutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][32+i:32+i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion256Permutex4SoftwareRC(&states, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(keys[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(keys[lane][32+i:32+i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(states[:])
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func em2Decrypt256x4Software(out, ct *[4][32]byte, keys *[4][64]byte) {
	var states [4]State256
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(ct[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(keys[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(keys[lane][32+i:32+i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion256InversePermutex4SoftwareRC(&states, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][32+i:32+i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion256InversePermutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(states[:])
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func em2Encrypt512x4Software(out, msgs *[4][64]byte, keys *[4][128]byte) {
	var states [4]State512
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(msgs[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion512Permutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][64+i:64+i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion512Permutex4SoftwareRC(&states, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(keys[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(keys[lane][64+i:64+i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(states[:])
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func em2Decrypt512x4Software(out, ct *[4][64]byte, keys *[4][128]byte) {
	var states [4]State512
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(ct[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(keys[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(keys[lane][64+i:64+i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion512InversePermutex4SoftwareRC(&states, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][64+i:64+i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion512InversePermutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(states[:])
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func temEncrypt256Software(out, m *[32]byte, k *[64]byte, t *[32]byte) {
	var w, state State256
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(t[i:i+8]) ^ binary.LittleEndian.Uint64(k[32+i:32+i+8])
		binary.LittleEndian.PutUint64(w[i:i+8], v)
	}
	var x0, x1 bsState
	bsPack1(&x0, (*Block)(w[0:16]))
	bsPack1(&x1, (*Block)(w[16:32]))
	areion256PermuteBS(&x0, &x1, &bsRCP2)
	bsUnpack1(&x0, (*Block)(w[0:16]))
	bsUnpack1(&x1, (*Block)(w[16:32]))
	for i := 0; i < 32; i += 8 {
		wv := binary.LittleEndian.Uint64(w[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(w[i:i+8], wv)
		binary.LittleEndian.PutUint64(state[i:i+8], binary.LittleEndian.Uint64(m[i:i+8])^wv)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256PermuteBS(&x0, &x1, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(w[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(w[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func temDecrypt256Software(out, c *[32]byte, k *[64]byte, t *[32]byte) {
	var w, state State256
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(t[i:i+8]) ^ binary.LittleEndian.Uint64(k[32+i:32+i+8])
		binary.LittleEndian.PutUint64(w[i:i+8], v)
	}
	var x0, x1 bsState
	bsPack1(&x0, (*Block)(w[0:16]))
	bsPack1(&x1, (*Block)(w[16:32]))
	areion256PermuteBS(&x0, &x1, &bsRCP2)
	bsUnpack1(&x0, (*Block)(w[0:16]))
	bsUnpack1(&x1, (*Block)(w[16:32]))
	for i := 0; i < 32; i += 8 {
		wv := binary.LittleEndian.Uint64(w[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(w[i:i+8], wv)
		binary.LittleEndian.PutUint64(state[i:i+8], binary.LittleEndian.Uint64(c[i:i+8])^wv)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256InversePermuteBS(&x0, &x1, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(w[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(w[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func temEncrypt512Software(out, m *[64]byte, k *[128]byte, t *[64]byte) {
	var w, state State512
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(t[i:i+8]) ^ binary.LittleEndian.Uint64(k[64+i:64+i+8])
		binary.LittleEndian.PutUint64(w[i:i+8], v)
	}
	var x0, x1, x2, x3 bsState
	bsPack1(&x0, (*Block)(w[0:16]))
	bsPack1(&x1, (*Block)(w[16:32]))
	bsPack1(&x2, (*Block)(w[32:48]))
	bsPack1(&x3, (*Block)(w[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, &bsRCP2)
	bsUnpack1(&x0, (*Block)(w[0:16]))
	bsUnpack1(&x1, (*Block)(w[16:32]))
	bsUnpack1(&x2, (*Block)(w[32:48]))
	bsUnpack1(&x3, (*Block)(w[48:64]))
	for i := 0; i < 64; i += 8 {
		wv := binary.LittleEndian.Uint64(w[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(w[i:i+8], wv)
		binary.LittleEndian.PutUint64(state[i:i+8], binary.LittleEndian.Uint64(m[i:i+8])^wv)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(w[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	clear(w[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func temDecrypt512Software(out, c *[64]byte, k *[128]byte, t *[64]byte) {
	var w, state State512
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(t[i:i+8]) ^ binary.LittleEndian.Uint64(k[64+i:64+i+8])
		binary.LittleEndian.PutUint64(w[i:i+8], v)
	}
	var x0, x1, x2, x3 bsState
	bsPack1(&x0, (*Block)(w[0:16]))
	bsPack1(&x1, (*Block)(w[16:32]))
	bsPack1(&x2, (*Block)(w[32:48]))
	bsPack1(&x3, (*Block)(w[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, &bsRCP2)
	bsUnpack1(&x0, (*Block)(w[0:16]))
	bsUnpack1(&x1, (*Block)(w[16:32]))
	bsUnpack1(&x2, (*Block)(w[32:48]))
	bsUnpack1(&x3, (*Block)(w[48:64]))
	for i := 0; i < 64; i += 8 {
		wv := binary.LittleEndian.Uint64(w[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		binary.LittleEndian.PutUint64(w[i:i+8], wv)
		binary.LittleEndian.PutUint64(state[i:i+8], binary.LittleEndian.Uint64(c[i:i+8])^wv)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512InversePermuteBS12(&x0, &x1, &x2, &x3, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(w[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	clear(w[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func temEncrypt256x4Software(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	var w, states [4]State256
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(tweaks[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][32+i:32+i+8])
			binary.LittleEndian.PutUint64(w[lane][i:i+8], v)
		}
	}
	areion256Permutex4SoftwareRC(&w, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			wv := binary.LittleEndian.Uint64(w[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(w[lane][i:i+8], wv)
			binary.LittleEndian.PutUint64(states[lane][i:i+8], binary.LittleEndian.Uint64(msgs[lane][i:i+8])^wv)
		}
	}
	areion256Permutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(w[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(w[:])
	clear(states[:])
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func temDecrypt256x4Software(out, ct *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	var w, states [4]State256
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(tweaks[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][32+i:32+i+8])
			binary.LittleEndian.PutUint64(w[lane][i:i+8], v)
		}
	}
	areion256Permutex4SoftwareRC(&w, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			wv := binary.LittleEndian.Uint64(w[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(w[lane][i:i+8], wv)
			binary.LittleEndian.PutUint64(states[lane][i:i+8], binary.LittleEndian.Uint64(ct[lane][i:i+8])^wv)
		}
	}
	areion256InversePermutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(w[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(w[:])
	clear(states[:])
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func temEncrypt512x4Software(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	var w, states [4]State512
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(tweaks[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][64+i:64+i+8])
			binary.LittleEndian.PutUint64(w[lane][i:i+8], v)
		}
	}
	areion512Permutex4SoftwareRC(&w, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			wv := binary.LittleEndian.Uint64(w[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(w[lane][i:i+8], wv)
			binary.LittleEndian.PutUint64(states[lane][i:i+8], binary.LittleEndian.Uint64(msgs[lane][i:i+8])^wv)
		}
	}
	areion512Permutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(w[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(w[:])
	clear(states[:])
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func temDecrypt512x4Software(out, ct *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	var w, states [4]State512
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(tweaks[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][64+i:64+i+8])
			binary.LittleEndian.PutUint64(w[lane][i:i+8], v)
		}
	}
	areion512Permutex4SoftwareRC(&w, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			wv := binary.LittleEndian.Uint64(w[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			binary.LittleEndian.PutUint64(w[lane][i:i+8], wv)
			binary.LittleEndian.PutUint64(states[lane][i:i+8], binary.LittleEndian.Uint64(ct[lane][i:i+8])^wv)
		}
	}
	areion512InversePermutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(w[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(w[:])
	clear(states[:])
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func tem2Encrypt256Software(out, m *[32]byte, k *[64]byte, t *[32]byte) {
	var w1, w2, state State256
	for i := 0; i < 32; i += 8 {
		tv := binary.LittleEndian.Uint64(t[i : i+8])
		k1 := binary.LittleEndian.Uint64(k[i : i+8])
		k2 := binary.LittleEndian.Uint64(k[32+i : 32+i+8])
		binary.LittleEndian.PutUint64(w1[i:i+8], tv^k1)
		binary.LittleEndian.PutUint64(w2[i:i+8], tv^k2)
	}
	var x0, x1 bsState
	bsPack2(&x0, (*Block)(w1[0:16]), (*Block)(w2[0:16]))
	bsPack2(&x1, (*Block)(w1[16:32]), (*Block)(w2[16:32]))
	areion256PermuteBS(&x0, &x1, &bsRCP1P2)
	bsUnpack2(&x0, (*Block)(w1[0:16]), (*Block)(w2[0:16]))
	bsUnpack2(&x1, (*Block)(w1[16:32]), (*Block)(w2[16:32]))
	for i := 0; i < 32; i += 8 {
		w1v := binary.LittleEndian.Uint64(w1[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		w2v := binary.LittleEndian.Uint64(w2[i:i+8]) ^ binary.LittleEndian.Uint64(k[32+i:32+i+8])
		binary.LittleEndian.PutUint64(w1[i:i+8], w1v)
		binary.LittleEndian.PutUint64(w2[i:i+8], w2v)
		binary.LittleEndian.PutUint64(state[i:i+8], binary.LittleEndian.Uint64(m[i:i+8])^w1v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256PermuteBS(&x0, &x1, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(w2[i:i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256PermuteBS(&x0, &x1, &bsRCP2)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^
			binary.LittleEndian.Uint64(w1[i:i+8]) ^
			binary.LittleEndian.Uint64(w2[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(w1[:])
	clear(w2[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&w2)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func tem2Decrypt256Software(out, c *[32]byte, k *[64]byte, t *[32]byte) {
	var w1, w2, state State256
	for i := 0; i < 32; i += 8 {
		tv := binary.LittleEndian.Uint64(t[i : i+8])
		k1 := binary.LittleEndian.Uint64(k[i : i+8])
		k2 := binary.LittleEndian.Uint64(k[32+i : 32+i+8])
		binary.LittleEndian.PutUint64(w1[i:i+8], tv^k1)
		binary.LittleEndian.PutUint64(w2[i:i+8], tv^k2)
	}
	var x0, x1 bsState
	bsPack2(&x0, (*Block)(w1[0:16]), (*Block)(w2[0:16]))
	bsPack2(&x1, (*Block)(w1[16:32]), (*Block)(w2[16:32]))
	areion256PermuteBS(&x0, &x1, &bsRCP1P2)
	bsUnpack2(&x0, (*Block)(w1[0:16]), (*Block)(w2[0:16]))
	bsUnpack2(&x1, (*Block)(w1[16:32]), (*Block)(w2[16:32]))
	for i := 0; i < 32; i += 8 {
		w1v := binary.LittleEndian.Uint64(w1[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		w2v := binary.LittleEndian.Uint64(w2[i:i+8]) ^ binary.LittleEndian.Uint64(k[32+i:32+i+8])
		binary.LittleEndian.PutUint64(w1[i:i+8], w1v)
		binary.LittleEndian.PutUint64(w2[i:i+8], w2v)
		binary.LittleEndian.PutUint64(state[i:i+8], binary.LittleEndian.Uint64(c[i:i+8])^w1v^w2v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256InversePermuteBS(&x0, &x1, &bsRCP2)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(w2[i:i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	areion256InversePermuteBS(&x0, &x1, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(w1[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(w1[:])
	clear(w2[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&w2)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func tem2Encrypt512Software(out, m *[64]byte, k *[128]byte, t *[64]byte) {
	var w1, w2, state State512
	for i := 0; i < 64; i += 8 {
		tv := binary.LittleEndian.Uint64(t[i : i+8])
		k1 := binary.LittleEndian.Uint64(k[i : i+8])
		k2 := binary.LittleEndian.Uint64(k[64+i : 64+i+8])
		binary.LittleEndian.PutUint64(w1[i:i+8], tv^k1)
		binary.LittleEndian.PutUint64(w2[i:i+8], tv^k2)
	}
	var x0, x1, x2, x3 bsState
	bsPack2(&x0, (*Block)(w1[0:16]), (*Block)(w2[0:16]))
	bsPack2(&x1, (*Block)(w1[16:32]), (*Block)(w2[16:32]))
	bsPack2(&x2, (*Block)(w1[32:48]), (*Block)(w2[32:48]))
	bsPack2(&x3, (*Block)(w1[48:64]), (*Block)(w2[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, &bsRCP1P2)
	bsUnpack2(&x0, (*Block)(w1[0:16]), (*Block)(w2[0:16]))
	bsUnpack2(&x1, (*Block)(w1[16:32]), (*Block)(w2[16:32]))
	bsUnpack2(&x2, (*Block)(w1[32:48]), (*Block)(w2[32:48]))
	bsUnpack2(&x3, (*Block)(w1[48:64]), (*Block)(w2[48:64]))
	for i := 0; i < 64; i += 8 {
		w1v := binary.LittleEndian.Uint64(w1[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		w2v := binary.LittleEndian.Uint64(w2[i:i+8]) ^ binary.LittleEndian.Uint64(k[64+i:64+i+8])
		binary.LittleEndian.PutUint64(w1[i:i+8], w1v)
		binary.LittleEndian.PutUint64(w2[i:i+8], w2v)
		binary.LittleEndian.PutUint64(state[i:i+8], binary.LittleEndian.Uint64(m[i:i+8])^w1v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(w2[i:i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, &bsRCP2)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^
			binary.LittleEndian.Uint64(w1[i:i+8]) ^
			binary.LittleEndian.Uint64(w2[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	clear(w1[:])
	clear(w2[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&w2)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func tem2Decrypt512Software(out, c *[64]byte, k *[128]byte, t *[64]byte) {
	var w1, w2, state State512
	for i := 0; i < 64; i += 8 {
		tv := binary.LittleEndian.Uint64(t[i : i+8])
		k1 := binary.LittleEndian.Uint64(k[i : i+8])
		k2 := binary.LittleEndian.Uint64(k[64+i : 64+i+8])
		binary.LittleEndian.PutUint64(w1[i:i+8], tv^k1)
		binary.LittleEndian.PutUint64(w2[i:i+8], tv^k2)
	}
	var x0, x1, x2, x3 bsState
	bsPack2(&x0, (*Block)(w1[0:16]), (*Block)(w2[0:16]))
	bsPack2(&x1, (*Block)(w1[16:32]), (*Block)(w2[16:32]))
	bsPack2(&x2, (*Block)(w1[32:48]), (*Block)(w2[32:48]))
	bsPack2(&x3, (*Block)(w1[48:64]), (*Block)(w2[48:64]))
	areion512PermuteBS12(&x0, &x1, &x2, &x3, &bsRCP1P2)
	bsUnpack2(&x0, (*Block)(w1[0:16]), (*Block)(w2[0:16]))
	bsUnpack2(&x1, (*Block)(w1[16:32]), (*Block)(w2[16:32]))
	bsUnpack2(&x2, (*Block)(w1[32:48]), (*Block)(w2[32:48]))
	bsUnpack2(&x3, (*Block)(w1[48:64]), (*Block)(w2[48:64]))
	for i := 0; i < 64; i += 8 {
		w1v := binary.LittleEndian.Uint64(w1[i:i+8]) ^ binary.LittleEndian.Uint64(k[i:i+8])
		w2v := binary.LittleEndian.Uint64(w2[i:i+8]) ^ binary.LittleEndian.Uint64(k[64+i:64+i+8])
		binary.LittleEndian.PutUint64(w1[i:i+8], w1v)
		binary.LittleEndian.PutUint64(w2[i:i+8], w2v)
		binary.LittleEndian.PutUint64(state[i:i+8], binary.LittleEndian.Uint64(c[i:i+8])^w1v^w2v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512InversePermuteBS12(&x0, &x1, &x2, &x3, &bsRCP2)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(w2[i:i+8])
		binary.LittleEndian.PutUint64(state[i:i+8], v)
	}
	bsPack1(&x0, (*Block)(state[0:16]))
	bsPack1(&x1, (*Block)(state[16:32]))
	bsPack1(&x2, (*Block)(state[32:48]))
	bsPack1(&x3, (*Block)(state[48:64]))
	areion512InversePermuteBS12(&x0, &x1, &x2, &x3, &bsRCP1)
	bsUnpack1(&x0, (*Block)(state[0:16]))
	bsUnpack1(&x1, (*Block)(state[16:32]))
	bsUnpack1(&x2, (*Block)(state[32:48]))
	bsUnpack1(&x3, (*Block)(state[48:64]))
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(state[i:i+8]) ^ binary.LittleEndian.Uint64(w1[i:i+8])
		binary.LittleEndian.PutUint64(out[i:i+8], v)
	}
	clear(x0[:])
	clear(x1[:])
	clear(x2[:])
	clear(x3[:])
	clear(w1[:])
	clear(w2[:])
	clear(state[:])
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&x2)
	runtime.KeepAlive(&x3)
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&w2)
	runtime.KeepAlive(&state)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func tem2Encrypt256x4Software(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	var w1, w2, states [4]State256
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			tv := binary.LittleEndian.Uint64(tweaks[lane][i : i+8])
			k1 := binary.LittleEndian.Uint64(keys[lane][i : i+8])
			k2 := binary.LittleEndian.Uint64(keys[lane][32+i : 32+i+8])
			binary.LittleEndian.PutUint64(w1[lane][i:i+8], tv^k1)
			binary.LittleEndian.PutUint64(w2[lane][i:i+8], tv^k2)
		}
	}
	areion256Permutex4SoftwareRC(&w1, &roundConstantsP1)
	areion256Permutex4SoftwareRC(&w2, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			w1v := binary.LittleEndian.Uint64(w1[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			w2v := binary.LittleEndian.Uint64(w2[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][32+i:32+i+8])
			binary.LittleEndian.PutUint64(w1[lane][i:i+8], w1v)
			binary.LittleEndian.PutUint64(w2[lane][i:i+8], w2v)
			binary.LittleEndian.PutUint64(states[lane][i:i+8], binary.LittleEndian.Uint64(msgs[lane][i:i+8])^w1v)
		}
	}
	areion256Permutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(w2[lane][i:i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion256Permutex4SoftwareRC(&states, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(w1[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(w2[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(w1[:])
	clear(w2[:])
	clear(states[:])
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&w2)
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func tem2Decrypt256x4Software(out, ct *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	var w1, w2, states [4]State256
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			tv := binary.LittleEndian.Uint64(tweaks[lane][i : i+8])
			k1 := binary.LittleEndian.Uint64(keys[lane][i : i+8])
			k2 := binary.LittleEndian.Uint64(keys[lane][32+i : 32+i+8])
			binary.LittleEndian.PutUint64(w1[lane][i:i+8], tv^k1)
			binary.LittleEndian.PutUint64(w2[lane][i:i+8], tv^k2)
		}
	}
	areion256Permutex4SoftwareRC(&w1, &roundConstantsP1)
	areion256Permutex4SoftwareRC(&w2, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			w1v := binary.LittleEndian.Uint64(w1[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			w2v := binary.LittleEndian.Uint64(w2[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][32+i:32+i+8])
			binary.LittleEndian.PutUint64(w1[lane][i:i+8], w1v)
			binary.LittleEndian.PutUint64(w2[lane][i:i+8], w2v)
			binary.LittleEndian.PutUint64(states[lane][i:i+8], binary.LittleEndian.Uint64(ct[lane][i:i+8])^w1v^w2v)
		}
	}
	areion256InversePermutex4SoftwareRC(&states, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(w2[lane][i:i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion256InversePermutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 32; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(w1[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(w1[:])
	clear(w2[:])
	clear(states[:])
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&w2)
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func tem2Encrypt512x4Software(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	var w1, w2, states [4]State512
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			tv := binary.LittleEndian.Uint64(tweaks[lane][i : i+8])
			k1 := binary.LittleEndian.Uint64(keys[lane][i : i+8])
			k2 := binary.LittleEndian.Uint64(keys[lane][64+i : 64+i+8])
			binary.LittleEndian.PutUint64(w1[lane][i:i+8], tv^k1)
			binary.LittleEndian.PutUint64(w2[lane][i:i+8], tv^k2)
		}
	}
	areion512Permutex4SoftwareRC(&w1, &roundConstantsP1)
	areion512Permutex4SoftwareRC(&w2, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			w1v := binary.LittleEndian.Uint64(w1[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			w2v := binary.LittleEndian.Uint64(w2[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][64+i:64+i+8])
			binary.LittleEndian.PutUint64(w1[lane][i:i+8], w1v)
			binary.LittleEndian.PutUint64(w2[lane][i:i+8], w2v)
			binary.LittleEndian.PutUint64(states[lane][i:i+8], binary.LittleEndian.Uint64(msgs[lane][i:i+8])^w1v)
		}
	}
	areion512Permutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(w2[lane][i:i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion512Permutex4SoftwareRC(&states, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(w1[lane][i:i+8]) ^
				binary.LittleEndian.Uint64(w2[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(w1[:])
	clear(w2[:])
	clear(states[:])
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&w2)
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func tem2Decrypt512x4Software(out, ct *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	var w1, w2, states [4]State512
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			tv := binary.LittleEndian.Uint64(tweaks[lane][i : i+8])
			k1 := binary.LittleEndian.Uint64(keys[lane][i : i+8])
			k2 := binary.LittleEndian.Uint64(keys[lane][64+i : 64+i+8])
			binary.LittleEndian.PutUint64(w1[lane][i:i+8], tv^k1)
			binary.LittleEndian.PutUint64(w2[lane][i:i+8], tv^k2)
		}
	}
	areion512Permutex4SoftwareRC(&w1, &roundConstantsP1)
	areion512Permutex4SoftwareRC(&w2, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			w1v := binary.LittleEndian.Uint64(w1[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][i:i+8])
			w2v := binary.LittleEndian.Uint64(w2[lane][i:i+8]) ^ binary.LittleEndian.Uint64(keys[lane][64+i:64+i+8])
			binary.LittleEndian.PutUint64(w1[lane][i:i+8], w1v)
			binary.LittleEndian.PutUint64(w2[lane][i:i+8], w2v)
			binary.LittleEndian.PutUint64(states[lane][i:i+8], binary.LittleEndian.Uint64(ct[lane][i:i+8])^w1v^w2v)
		}
	}
	areion512InversePermutex4SoftwareRC(&states, &roundConstantsP2)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(w2[lane][i:i+8])
			binary.LittleEndian.PutUint64(states[lane][i:i+8], v)
		}
	}
	areion512InversePermutex4SoftwareRC(&states, &roundConstantsP1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 64; i += 8 {
			v := binary.LittleEndian.Uint64(states[lane][i:i+8]) ^ binary.LittleEndian.Uint64(w1[lane][i:i+8])
			binary.LittleEndian.PutUint64(out[lane][i:i+8], v)
		}
	}
	clear(w1[:])
	clear(w2[:])
	clear(states[:])
	runtime.KeepAlive(&w1)
	runtime.KeepAlive(&w2)
	runtime.KeepAlive(&states)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

package areion

import "encoding/binary"

func xorBlock16(dst, a, b []byte) {
	lo := binary.LittleEndian.Uint64(a[0:8]) ^ binary.LittleEndian.Uint64(b[0:8])
	hi := binary.LittleEndian.Uint64(a[8:16]) ^ binary.LittleEndian.Uint64(b[8:16])
	binary.LittleEndian.PutUint64(dst[0:8], lo)
	binary.LittleEndian.PutUint64(dst[8:16], hi)
}

func xorBlock16_3(dst, a, b, c []byte) {
	lo := binary.LittleEndian.Uint64(a[0:8]) ^ binary.LittleEndian.Uint64(b[0:8]) ^ binary.LittleEndian.Uint64(c[0:8])
	hi := binary.LittleEndian.Uint64(a[8:16]) ^ binary.LittleEndian.Uint64(b[8:16]) ^ binary.LittleEndian.Uint64(c[8:16])
	binary.LittleEndian.PutUint64(dst[0:8], lo)
	binary.LittleEndian.PutUint64(dst[8:16], hi)
}

func xorInto16(dst, a []byte) {
	lo := binary.LittleEndian.Uint64(dst[0:8]) ^ binary.LittleEndian.Uint64(a[0:8])
	hi := binary.LittleEndian.Uint64(dst[8:16]) ^ binary.LittleEndian.Uint64(a[8:16])
	binary.LittleEndian.PutUint64(dst[0:8], lo)
	binary.LittleEndian.PutUint64(dst[8:16], hi)
}

func unpack256x4SoA(b0, b1 *Block4, states *[4][32]byte) {
	for i := 0; i < 4; i++ {
		copy(states[i][0:16], b0[i*16:(i+1)*16])
		copy(states[i][16:32], b1[i*16:(i+1)*16])
	}
}

func unpack512x4SoA(b0, b1, b2, b3 *Block4, states *[4][64]byte) {
	for i := 0; i < 4; i++ {
		copy(states[i][0:16], b0[i*16:(i+1)*16])
		copy(states[i][16:32], b1[i*16:(i+1)*16])
		copy(states[i][32:48], b2[i*16:(i+1)*16])
		copy(states[i][48:64], b3[i*16:(i+1)*16])
	}
}

// pack256x4SoAInto packs four 256-bit states into caller-owned SoA blocks so
// the packed state never passes through a by-value result or a compiler
// temporary that the caller cannot zero.
func pack256x4SoAInto(states *[4][32]byte, b0, b1 *Block4) {
	for i := 0; i < 4; i++ {
		copy(b0[i*16:(i+1)*16], states[i][0:16])
		copy(b1[i*16:(i+1)*16], states[i][16:32])
	}
}

// pack512x4SoAInto packs four 512-bit states into caller-owned SoA blocks so
// the packed state never passes through a by-value result or a compiler
// temporary that the caller cannot zero.
func pack512x4SoAInto(states *[4][64]byte, b0, b1, b2, b3 *Block4) {
	for i := 0; i < 4; i++ {
		copy(b0[i*16:(i+1)*16], states[i][0:16])
		copy(b1[i*16:(i+1)*16], states[i][16:32])
		copy(b2[i*16:(i+1)*16], states[i][32:48])
		copy(b3[i*16:(i+1)*16], states[i][48:64])
	}
}

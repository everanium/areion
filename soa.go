//go:build (amd64 || arm64) && !purego

package areion

func pack256x4SoA(states *[4][32]byte) (b0, b1 Block4) {
	for i := 0; i < 4; i++ {
		copy(b0[i*16:(i+1)*16], states[i][0:16])
		copy(b1[i*16:(i+1)*16], states[i][16:32])
	}
	return
}

func unpack256x4SoA(b0, b1 *Block4, states *[4][32]byte) {
	for i := 0; i < 4; i++ {
		copy(states[i][0:16], b0[i*16:(i+1)*16])
		copy(states[i][16:32], b1[i*16:(i+1)*16])
	}
}

func pack512x4SoA(states *[4][64]byte) (b0, b1, b2, b3 Block4) {
	for i := 0; i < 4; i++ {
		copy(b0[i*16:(i+1)*16], states[i][0:16])
		copy(b1[i*16:(i+1)*16], states[i][16:32])
		copy(b2[i*16:(i+1)*16], states[i][32:48])
		copy(b3[i*16:(i+1)*16], states[i][48:64])
	}
	return
}

func unpack512x4SoA(b0, b1, b2, b3 *Block4, states *[4][64]byte) {
	for i := 0; i < 4; i++ {
		copy(states[i][0:16], b0[i*16:(i+1)*16])
		copy(states[i][16:32], b1[i*16:(i+1)*16])
		copy(states[i][32:48], b2[i*16:(i+1)*16])
		copy(states[i][48:64], b3[i*16:(i+1)*16])
	}
}

// pack256x4SoAInto is pack256x4SoA writing into caller-owned blocks, so the
// packed state never passes through a by-value result or a compiler
// temporary that the caller cannot zero.
func pack256x4SoAInto(states *[4][32]byte, b0, b1 *Block4) {
	for i := 0; i < 4; i++ {
		copy(b0[i*16:(i+1)*16], states[i][0:16])
		copy(b1[i*16:(i+1)*16], states[i][16:32])
	}
}

// pack512x4SoAInto is pack512x4SoA writing into caller-owned blocks, so the
// packed state never passes through a by-value result or a compiler
// temporary that the caller cannot zero.
func pack512x4SoAInto(states *[4][64]byte, b0, b1, b2, b3 *Block4) {
	for i := 0; i < 4; i++ {
		copy(b0[i*16:(i+1)*16], states[i][0:16])
		copy(b1[i*16:(i+1)*16], states[i][16:32])
		copy(b2[i*16:(i+1)*16], states[i][32:48])
		copy(b3[i*16:(i+1)*16], states[i][48:64])
	}
}

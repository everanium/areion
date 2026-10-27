//go:build amd64 && !purego

package areion

import (
	"runtime/debug"
	"testing"
	"unsafe"
)

//go:noescape
func dumpSIMDRegs(dst *[96]uint64, hasAVX512 bool)

//go:noescape
func dirtySIMDRegForTest(masked uint64)

const (
	areionResidueGap      = 1 << 10
	areionResiduePad      = 2 << 10
	areionResidueWindow   = 16 << 10
	areionResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
	areionSIMDWords       = 96
	areionStackWords      = areionResidueWindow / 8
	areionTotalWords      = areionStackWords + areionSIMDWords
)

//go:noinline
func areionResidueGrow(i int) byte {
	var pad [4 * areionResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
//go:nocheckptr
func areionResidueProbe(fn func(), res []uint64, regs *[areionSIMDWords]uint64, avx512 bool) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -areionResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = areionResidueSentinel
	}
	areionResidueDeep(fn, 0, regs, avx512)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func areionResidueDeep(fn func(), i int, regs *[areionSIMDWords]uint64, avx512 bool) byte {
	var pad [areionResiduePad]byte
	pad[i] = 1
	dumpSIMDRegs(regs, avx512)
	fn()
	dumpSIMDRegs(regs, avx512)
	return pad[(i+7)%len(pad)]
}

//go:noinline
func captureAreionFrameAndRegResidue(call func(), dst *[areionTotalWords]uint64) int {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	avx512 := hasAVX512 && TierCode() >= TierAVX512
	done := make(chan struct{})
	go func() {
		defer close(done)
		areionResidueGrow(0)
		var simd [areionSIMDWords]uint64
		areionResidueProbe(call, dst[:areionStackWords], &simd, avx512)
		copy(dst[areionStackWords:], simd[:])
	}()
	<-done
	written := 0
	for i := 0; i < areionStackWords; i++ {
		if dst[i] != areionResidueSentinel {
			written++
		}
	}
	return written
}

func testAreionArchAsmKernels(t *testing.T, tier string, res *[areionTotalWords]uint64) {
	b256 := new([4][32]byte)
	orig256 := new([4][32]byte)
	b512 := new([4][64]byte)
	orig512 := new([4][64]byte)
	for l := 0; l < 4; l++ {
		for i := 0; i < 32; i++ {
			orig256[l][i] = byte(0x13 + l*29 + i*3)
		}
		for i := 0; i < 64; i++ {
			orig512[l][i] = byte(0x29 + l*31 + i*5)
		}
	}

	run256x4 := func(name string, fn func(*[32]byte, *[32]byte, *[32]byte, *[32]byte, *[15 * 64]byte)) {
		*b256 = *orig256
		if w := captureAreionFrameAndRegResidue(func() {
			fn(&b256[0], &b256[1], &b256[2], &b256[3], &areionRC4x)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		var targets []uint64
		for l := 0; l < 4; l++ {
			targets = append(targets, bytesToNonZeroWords(orig256[l][:], b256[l][:])...)
		}
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	run512x4 := func(name string, fn func(*[64]byte, *[64]byte, *[64]byte, *[64]byte, *[15 * 64]byte)) {
		*b512 = *orig512
		if w := captureAreionFrameAndRegResidue(func() {
			fn(&b512[0], &b512[1], &b512[2], &b512[3], &areionRC4x)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		var targets []uint64
		for l := 0; l < 4; l++ {
			targets = append(targets, bytesToNonZeroWords(orig512[l][:], b512[l][:])...)
		}
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runSoEM256x4 := func(name string, fn func(*[4][32]byte, *[4][32]byte, *[4][64]byte)) {
		m := new([4][32]byte)
		k := new([4][64]byte)
		out := new([4][32]byte)
		for l := 0; l < 4; l++ {
			for i := 0; i < 32; i++ {
				m[l][i] = byte(0x31 + l*19 + i*5)
			}
			for i := 0; i < 64; i++ {
				k[l][i] = byte(0x53 + l*23 + i*3)
			}
		}
		if w := captureAreionFrameAndRegResidue(func() {
			fn(out, m, k)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		var targets []uint64
		for l := 0; l < 4; l++ {
			targets = append(targets, bytesToNonZeroWords(m[l][:], k[l][:], out[l][:])...)
		}
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runSoEM512x4 := func(name string, fn func(*[4][64]byte, *[4][64]byte, *[4][128]byte)) {
		m := new([4][64]byte)
		k := new([4][128]byte)
		out := new([4][64]byte)
		for l := 0; l < 4; l++ {
			for i := 0; i < 64; i++ {
				m[l][i] = byte(0x37 + l*17 + i*5)
			}
			for i := 0; i < 128; i++ {
				k[l][i] = byte(0x59 + l*29 + i*3)
			}
		}
		if w := captureAreionFrameAndRegResidue(func() {
			fn(out, m, k)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		var targets []uint64
		for l := 0; l < 4; l++ {
			targets = append(targets, bytesToNonZeroWords(m[l][:], k[l][:], out[l][:])...)
		}
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runTEM256x4 := func(name string, fn func(*[4][32]byte, *[4][32]byte, *[4][64]byte, *[4][32]byte)) {
		m := new([4][32]byte)
		k := new([4][64]byte)
		tw := new([4][32]byte)
		out := new([4][32]byte)
		for l := 0; l < 4; l++ {
			for i := 0; i < 32; i++ {
				m[l][i] = byte(0x41 + l*19 + i*5)
				tw[l][i] = byte(0x73 + l*13 + i*7)
			}
			for i := 0; i < 64; i++ {
				k[l][i] = byte(0x61 + l*23 + i*3)
			}
		}
		if w := captureAreionFrameAndRegResidue(func() {
			fn(out, m, k, tw)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		var targets []uint64
		for l := 0; l < 4; l++ {
			targets = append(targets, bytesToNonZeroWords(m[l][:], k[l][:], tw[l][:], out[l][:])...)
		}
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runTEM512x4 := func(name string, fn func(*[4][64]byte, *[4][64]byte, *[4][128]byte, *[4][64]byte)) {
		m := new([4][64]byte)
		k := new([4][128]byte)
		tw := new([4][64]byte)
		out := new([4][64]byte)
		for l := 0; l < 4; l++ {
			for i := 0; i < 64; i++ {
				m[l][i] = byte(0x43 + l*19 + i*5)
				tw[l][i] = byte(0x79 + l*13 + i*7)
			}
			for i := 0; i < 128; i++ {
				k[l][i] = byte(0x67 + l*23 + i*3)
			}
		}
		if w := captureAreionFrameAndRegResidue(func() {
			fn(out, m, k, tw)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		var targets []uint64
		for l := 0; l < 4; l++ {
			targets = append(targets, bytesToNonZeroWords(m[l][:], k[l][:], tw[l][:], out[l][:])...)
		}
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runEM256 := func(name string, fn func(*[32]byte, *[32]byte, *[64]byte)) {
		m := new([32]byte)
		k := new([64]byte)
		out := new([32]byte)
		for i := range m {
			m[i] = byte(0x31 + i*5)
		}
		for i := range k {
			k[i] = byte(0x53 + i*3)
		}
		if w := captureAreionFrameAndRegResidue(func() {
			fn(out, m, k)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(m[:], k[:], out[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runEM512 := func(name string, fn func(*[64]byte, *[64]byte, *[128]byte)) {
		m := new([64]byte)
		k := new([128]byte)
		out := new([64]byte)
		for i := range m {
			m[i] = byte(0x37 + i*5)
		}
		for i := range k {
			k[i] = byte(0x59 + i*3)
		}
		if w := captureAreionFrameAndRegResidue(func() {
			fn(out, m, k)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(m[:], k[:], out[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runTEM256 := func(name string, fn func(*[32]byte, *[32]byte, *[64]byte, *[32]byte)) {
		m := new([32]byte)
		k := new([64]byte)
		tw := new([32]byte)
		out := new([32]byte)
		for i := range m {
			m[i] = byte(0x41 + i*5)
			tw[i] = byte(0x73 + i*7)
		}
		for i := range k {
			k[i] = byte(0x61 + i*3)
		}
		if w := captureAreionFrameAndRegResidue(func() {
			fn(out, m, k, tw)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(m[:], k[:], tw[:], out[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runTEM512 := func(name string, fn func(*[64]byte, *[64]byte, *[128]byte, *[64]byte)) {
		m := new([64]byte)
		k := new([128]byte)
		tw := new([64]byte)
		out := new([64]byte)
		for i := range m {
			m[i] = byte(0x43 + i*5)
			tw[i] = byte(0x79 + i*7)
		}
		for i := range k {
			k[i] = byte(0x67 + i*3)
		}
		if w := captureAreionFrameAndRegResidue(func() {
			fn(out, m, k, tw)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(m[:], k[:], tw[:], out[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runR256Block := func(name string, fn func(*[15][32]byte, *[32]byte, *[32]byte)) {
		rk := new([15][32]byte)
		in := new([32]byte)
		out := new([32]byte)
		for r := 0; r < 15; r++ {
			for i := 0; i < 32; i++ {
				rk[r][i] = byte(0x27 + r*19 + i*7)
			}
		}
		for i := range in {
			in[i] = byte(0x89 + i*13)
		}
		if w := captureAreionFrameAndRegResidue(func() {
			fn(rk, out, in)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		var targets []uint64
		for r := 0; r < 15; r++ {
			targets = append(targets, bytesToNonZeroWords(rk[r][:])...)
		}
		targets = append(targets, bytesToNonZeroWords(in[:], out[:])...)
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runR256Block4 := func(name string, fn func(*[15][32]byte, *[4][32]byte, *[4][32]byte)) {
		rk := new([15][32]byte)
		in4 := new([4][32]byte)
		out4 := new([4][32]byte)
		for r := 0; r < 15; r++ {
			for i := 0; i < 32; i++ {
				rk[r][i] = byte(0x27 + r*19 + i*7)
			}
		}
		for l := 0; l < 4; l++ {
			for i := 0; i < 32; i++ {
				in4[l][i] = byte(0x3B + l*29 + i*11)
			}
		}
		if w := captureAreionFrameAndRegResidue(func() {
			fn(rk, out4, in4)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		var targets []uint64
		for r := 0; r < 15; r++ {
			targets = append(targets, bytesToNonZeroWords(rk[r][:])...)
		}
		for l := 0; l < 4; l++ {
			targets = append(targets, bytesToNonZeroWords(in4[l][:], out4[l][:])...)
		}
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runV256Block := func(name string, fn func(*[32]byte, *[32]byte, *[32]byte, int)) {
		key := new([32]byte)
		in := new([32]byte)
		out := new([32]byte)
		for i := 0; i < 32; i++ {
			key[i] = byte(0x31 + i*7)
			in[i] = byte(0x93 + i*13)
		}
		for _, r := range []int{10, 14} {
			if w := captureAreionFrameAndRegResidue(func() {
				fn(out, in, key, r)
			}, res); w == 0 {
				t.Fatalf("[%s] %s(%d): probe missed stack window", tier, name, r)
			}
			targets := bytesToNonZeroWords(key[:], in[:], out[:])
			if word, off, found := scanForAreionWords(res, targets); found {
				t.Fatalf("[%s] %s(%d) leaked word %#016x at offset %d (window=%d)", tier, name, r, word, off, areionResidueWindow)
			}
		}
	}

	runV256Block4 := func(name string, fn func(*[4][32]byte, *[4][32]byte, *[32]byte, int)) {
		key := new([32]byte)
		in4 := new([4][32]byte)
		out4 := new([4][32]byte)
		for i := 0; i < 32; i++ {
			key[i] = byte(0x31 + i*7)
		}
		for l := 0; l < 4; l++ {
			for i := 0; i < 32; i++ {
				in4[l][i] = byte(0x47 + l*29 + i*11)
			}
		}
		for _, r := range []int{10, 14} {
			if w := captureAreionFrameAndRegResidue(func() {
				fn(out4, in4, key, r)
			}, res); w == 0 {
				t.Fatalf("[%s] %s(%d): probe missed stack window", tier, name, r)
			}
			targets := bytesToNonZeroWords(key[:])
			for l := 0; l < 4; l++ {
				targets = append(targets, bytesToNonZeroWords(in4[l][:], out4[l][:])...)
			}
			if word, off, found := scanForAreionWords(res, targets); found {
				t.Fatalf("[%s] %s(%d) leaked word %#016x at offset %d (window=%d)", tier, name, r, word, off, areionResidueWindow)
			}
		}
	}

	runV512Block256 := func(name string, fn func(*[64]byte, *[64]byte, *[32]byte, int)) {
		key := new([32]byte)
		in := new([64]byte)
		out := new([64]byte)
		for i := 0; i < 32; i++ {
			key[i] = byte(0x53 + i*7)
		}
		for i := 0; i < 64; i++ {
			in[i] = byte(0x89 + i*5)
		}
		for _, r := range []int{10, 12, 14, 18} {
			if w := captureAreionFrameAndRegResidue(func() {
				fn(out, in, key, r)
			}, res); w == 0 {
				t.Fatalf("[%s] %s(%d): probe missed stack window", tier, name, r)
			}
			targets := bytesToNonZeroWords(key[:], in[:], out[:])
			if word, off, found := scanForAreionWords(res, targets); found {
				t.Fatalf("[%s] %s(%d) leaked word %#016x at offset %d (window=%d)", tier, name, r, word, off, areionResidueWindow)
			}
		}
	}

	runV512Block512 := func(name string, fn func(*[64]byte, *[64]byte, *[64]byte, int)) {
		key := new([64]byte)
		in := new([64]byte)
		out := new([64]byte)
		for i := 0; i < 64; i++ {
			key[i] = byte(0x59 + i*3)
			in[i] = byte(0x89 + i*5)
		}
		for _, r := range []int{10, 12, 14, 18} {
			if w := captureAreionFrameAndRegResidue(func() {
				fn(out, in, key, r)
			}, res); w == 0 {
				t.Fatalf("[%s] %s(%d): probe missed stack window", tier, name, r)
			}
			targets := bytesToNonZeroWords(key[:], in[:], out[:])
			if word, off, found := scanForAreionWords(res, targets); found {
				t.Fatalf("[%s] %s(%d) leaked word %#016x at offset %d (window=%d)", tier, name, r, word, off, areionResidueWindow)
			}
		}
	}

	runV512Block4_256 := func(name string, fn func(*[4][64]byte, *[4][64]byte, *[32]byte, int)) {
		key := new([32]byte)
		in4 := new([4][64]byte)
		out4 := new([4][64]byte)
		for i := 0; i < 32; i++ {
			key[i] = byte(0x53 + i*7)
		}
		for l := 0; l < 4; l++ {
			for i := 0; i < 64; i++ {
				in4[l][i] = byte(0x3B + l*23 + i*5)
			}
		}
		for _, r := range []int{10, 12, 14, 18} {
			if w := captureAreionFrameAndRegResidue(func() {
				fn(out4, in4, key, r)
			}, res); w == 0 {
				t.Fatalf("[%s] %s(%d): probe missed stack window", tier, name, r)
			}
			targets := bytesToNonZeroWords(key[:])
			for l := 0; l < 4; l++ {
				targets = append(targets, bytesToNonZeroWords(in4[l][:], out4[l][:])...)
			}
			if word, off, found := scanForAreionWords(res, targets); found {
				t.Fatalf("[%s] %s(%d) leaked word %#016x at offset %d (window=%d)", tier, name, r, word, off, areionResidueWindow)
			}
		}
	}

	runV512Block4_512 := func(name string, fn func(*[4][64]byte, *[4][64]byte, *[64]byte, int)) {
		key := new([64]byte)
		in4 := new([4][64]byte)
		out4 := new([4][64]byte)
		for i := 0; i < 64; i++ {
			key[i] = byte(0x59 + i*3)
		}
		for l := 0; l < 4; l++ {
			for i := 0; i < 64; i++ {
				in4[l][i] = byte(0x3B + l*23 + i*5)
			}
		}
		for _, r := range []int{10, 12, 14, 18} {
			if w := captureAreionFrameAndRegResidue(func() {
				fn(out4, in4, key, r)
			}, res); w == 0 {
				t.Fatalf("[%s] %s(%d): probe missed stack window", tier, name, r)
			}
			targets := bytesToNonZeroWords(key[:])
			for l := 0; l < 4; l++ {
				targets = append(targets, bytesToNonZeroWords(in4[l][:], out4[l][:])...)
			}
			if word, off, found := scanForAreionWords(res, targets); found {
				t.Fatalf("[%s] %s(%d) leaked word %#016x at offset %d (window=%d)", tier, name, r, word, off, areionResidueWindow)
			}
		}
	}

	switch tier {
	case "aesni":
		runR256Block("rijndael256EncryptBlockAsm", rijndael256EncryptBlockAsm)
		runR256Block4("rijndael256Encrypt4BlocksAesNiAsm", rijndael256Encrypt4BlocksAesNiAsm)
		runV256Block("vistrutah256EncryptBlockAsm", vistrutah256EncryptBlockAsm)
		runV256Block4("vistrutah256Encrypt4BlocksAesNiAsm", vistrutah256Encrypt4BlocksAesNiAsm)
		runV512Block256("vistrutah512EncryptBlock256Asm", vistrutah512EncryptBlock256Asm)
		runV512Block512("vistrutah512EncryptBlock512Asm", vistrutah512EncryptBlock512Asm)
		runV512Block4_256("vistrutah512Encrypt4Blocks256AesNiAsm", vistrutah512Encrypt4Blocks256AesNiAsm)
		runV512Block4_512("vistrutah512Encrypt4Blocks512AesNiAsm", vistrutah512Encrypt4Blocks512AesNiAsm)
		run256x4("areion256Permutex4AesNiRC", areion256Permutex4AesNiRC)
		run256x4("areion256InversePermutex4AesNiRC", areion256InversePermutex4AesNiRC)
		run512x4("areion512Permutex4AesNiRC", areion512Permutex4AesNiRC)
		run512x4("areion512InversePermutex4AesNiRC", areion512InversePermutex4AesNiRC)
		runSoEM256x4("areion256SoEMPermutex4AesNi", areion256SoEMPermutex4AesNi)
		runSoEM512x4("areion512SoEMPermutex4AesNi", areion512SoEMPermutex4AesNi)
		runEM256("areion256EMEncryptAESNI", areion256EMEncryptAESNI)
		runEM256("areion256EMDecryptAESNI", areion256EMDecryptAESNI)
		runEM512("areion512EMEncryptAESNI", areion512EMEncryptAESNI)
		runEM512("areion512EMDecryptAESNI", areion512EMDecryptAESNI)
		runEM256("areion256EM2EncryptAESNI", areion256EM2EncryptAESNI)
		runEM256("areion256EM2DecryptAESNI", areion256EM2DecryptAESNI)
		runEM512("areion512EM2EncryptAESNI", areion512EM2EncryptAESNI)
		runEM512("areion512EM2DecryptAESNI", areion512EM2DecryptAESNI)
		runTEM256("areion256TEMEncryptAESNI", areion256TEMEncryptAESNI)
		runTEM256("areion256TEMDecryptAESNI", areion256TEMDecryptAESNI)
		runTEM512("areion512TEMEncryptAESNI", areion512TEMEncryptAESNI)
		runTEM512("areion512TEMDecryptAESNI", areion512TEMDecryptAESNI)
		runTEM256("areion256TEM2EncryptAESNI", areion256TEM2EncryptAESNI)
		runTEM256("areion256TEM2DecryptAESNI", areion256TEM2DecryptAESNI)
		runTEM512("areion512TEM2EncryptAESNI", areion512TEM2EncryptAESNI)
		runTEM512("areion512TEM2DecryptAESNI", areion512TEM2DecryptAESNI)
		runSoEM256x4("areion256EMEncryptx4AESNI", areion256EMEncryptx4AESNI)
		runSoEM256x4("areion256EMDecryptx4AESNI", areion256EMDecryptx4AESNI)
		runSoEM512x4("areion512EMEncryptx4AESNI", areion512EMEncryptx4AESNI)
		runSoEM512x4("areion512EMDecryptx4AESNI", areion512EMDecryptx4AESNI)
		runSoEM256x4("areion256EM2Encryptx4AESNI", areion256EM2Encryptx4AESNI)
		runSoEM256x4("areion256EM2Decryptx4AESNI", areion256EM2Decryptx4AESNI)
		runSoEM512x4("areion512EM2Encryptx4AESNI", areion512EM2Encryptx4AESNI)
		runSoEM512x4("areion512EM2Decryptx4AESNI", areion512EM2Decryptx4AESNI)
		runTEM256x4("areion256TEMEncryptx4AESNI", areion256TEMEncryptx4AESNI)
		runTEM256x4("areion256TEMDecryptx4AESNI", areion256TEMDecryptx4AESNI)
		runTEM512x4("areion512TEMEncryptx4AESNI", areion512TEMEncryptx4AESNI)
		runTEM512x4("areion512TEMDecryptx4AESNI", areion512TEMDecryptx4AESNI)
		runTEM256x4("areion256TEM2Encryptx4AESNI", areion256TEM2Encryptx4AESNI)
		runTEM256x4("areion256TEM2Decryptx4AESNI", areion256TEM2Decryptx4AESNI)
		runTEM512x4("areion512TEM2Encryptx4AESNI", areion512TEM2Encryptx4AESNI)
		runTEM512x4("areion512TEM2Decryptx4AESNI", areion512TEM2Decryptx4AESNI)
	case "vex":
		runR256Block("rijndael256EncryptBlockVexAsm", rijndael256EncryptBlockVexAsm)
		runR256Block4("rijndael256Encrypt4BlocksVexAsm", rijndael256Encrypt4BlocksVexAsm)
		runV256Block("vistrutah256EncryptBlockVexAsm", vistrutah256EncryptBlockVexAsm)
		runV256Block4("vistrutah256Encrypt4BlocksVexAsm", vistrutah256Encrypt4BlocksVexAsm)
		runV512Block256("vistrutah512EncryptBlock256VexAsm", vistrutah512EncryptBlock256VexAsm)
		runV512Block512("vistrutah512EncryptBlock512VexAsm", vistrutah512EncryptBlock512VexAsm)
		runV512Block4_256("vistrutah512Encrypt4Blocks256VexAsm", vistrutah512Encrypt4Blocks256VexAsm)
		runV512Block4_512("vistrutah512Encrypt4Blocks512VexAsm", vistrutah512Encrypt4Blocks512VexAsm)
		run256x4("areion256Permutex4VexRC", areion256Permutex4VexRC)
		run256x4("areion256InversePermutex4VexRC", areion256InversePermutex4VexRC)
		run512x4("areion512Permutex4VexRC", areion512Permutex4VexRC)
		run512x4("areion512InversePermutex4VexRC", areion512InversePermutex4VexRC)
		runSoEM256x4("areion256SoEMPermutex4Vex", areion256SoEMPermutex4Vex)
		runSoEM512x4("areion512SoEMPermutex4Vex", areion512SoEMPermutex4Vex)
		runEM256("areion256EMEncryptVEX", areion256EMEncryptVEX)
		runEM256("areion256EMDecryptVEX", areion256EMDecryptVEX)
		runEM512("areion512EMEncryptVEX", areion512EMEncryptVEX)
		runEM512("areion512EMDecryptVEX", areion512EMDecryptVEX)
		runEM256("areion256EM2EncryptVEX", areion256EM2EncryptVEX)
		runEM256("areion256EM2DecryptVEX", areion256EM2DecryptVEX)
		runEM512("areion512EM2EncryptVEX", areion512EM2EncryptVEX)
		runEM512("areion512EM2DecryptVEX", areion512EM2DecryptVEX)
		runTEM256("areion256TEMEncryptVEX", areion256TEMEncryptVEX)
		runTEM256("areion256TEMDecryptVEX", areion256TEMDecryptVEX)
		runTEM512("areion512TEMEncryptVEX", areion512TEMEncryptVEX)
		runTEM512("areion512TEMDecryptVEX", areion512TEMDecryptVEX)
		runTEM256("areion256TEM2EncryptVEX", areion256TEM2EncryptVEX)
		runTEM256("areion256TEM2DecryptVEX", areion256TEM2DecryptVEX)
		runTEM512("areion512TEM2EncryptVEX", areion512TEM2EncryptVEX)
		runTEM512("areion512TEM2DecryptVEX", areion512TEM2DecryptVEX)
		runSoEM256x4("areion256EMEncryptx4VEX", areion256EMEncryptx4VEX)
		runSoEM256x4("areion256EMDecryptx4VEX", areion256EMDecryptx4VEX)
		runSoEM512x4("areion512EMEncryptx4VEX", areion512EMEncryptx4VEX)
		runSoEM512x4("areion512EMDecryptx4VEX", areion512EMDecryptx4VEX)
		runSoEM256x4("areion256EM2Encryptx4VEX", areion256EM2Encryptx4VEX)
		runSoEM256x4("areion256EM2Decryptx4VEX", areion256EM2Decryptx4VEX)
		runSoEM512x4("areion512EM2Encryptx4VEX", areion512EM2Encryptx4VEX)
		runSoEM512x4("areion512EM2Decryptx4VEX", areion512EM2Decryptx4VEX)
		runTEM256x4("areion256TEMEncryptx4VEX", areion256TEMEncryptx4VEX)
		runTEM256x4("areion256TEMDecryptx4VEX", areion256TEMDecryptx4VEX)
		runTEM512x4("areion512TEMEncryptx4VEX", areion512TEMEncryptx4VEX)
		runTEM512x4("areion512TEMDecryptx4VEX", areion512TEMDecryptx4VEX)
		runTEM256x4("areion256TEM2Encryptx4VEX", areion256TEM2Encryptx4VEX)
		runTEM256x4("areion256TEM2Decryptx4VEX", areion256TEM2Decryptx4VEX)
		runTEM512x4("areion512TEM2Encryptx4VEX", areion512TEM2Encryptx4VEX)
		runTEM512x4("areion512TEM2Decryptx4VEX", areion512TEM2Decryptx4VEX)
	case "vaesavx2":
		runR256Block("rijndael256EncryptBlockVexAsm", rijndael256EncryptBlockVexAsm)
		runR256Block4("rijndael256Encrypt4BlocksYmmAsm", rijndael256Encrypt4BlocksYmmAsm)
		runV256Block("vistrutah256EncryptBlockYmmAsm", vistrutah256EncryptBlockYmmAsm)
		runV256Block4("vistrutah256Encrypt4BlocksYmmAsm", vistrutah256Encrypt4BlocksYmmAsm)
		runV512Block256("vistrutah512EncryptBlock256YmmAsm", vistrutah512EncryptBlock256YmmAsm)
		runV512Block512("vistrutah512EncryptBlock512YmmAsm", vistrutah512EncryptBlock512YmmAsm)
		runV512Block4_256("vistrutah512Encrypt4Blocks256YmmAsm", vistrutah512Encrypt4Blocks256YmmAsm)
		runV512Block4_512("vistrutah512Encrypt4Blocks512YmmAsm", vistrutah512Encrypt4Blocks512YmmAsm)
		run256x4("areion256Permutex4Avx2RC", areion256Permutex4Avx2RC)
		run256x4("areion256InversePermutex4Avx2RC", areion256InversePermutex4Avx2RC)
		run512x4("areion512Permutex4Avx2RC", areion512Permutex4Avx2RC)
		run512x4("areion512InversePermutex4Avx2RC", areion512InversePermutex4Avx2RC)
		runSoEM256x4("areion256SoEMPermutex4VaesAvx2", areion256SoEMPermutex4VaesAvx2)
		runSoEM512x4("areion512SoEMPermutex4VaesAvx2", areion512SoEMPermutex4VaesAvx2)
		runEM256("areion256EMEncryptVEX", areion256EMEncryptVEX)
		runEM256("areion256EMDecryptVEX", areion256EMDecryptVEX)
		runEM512("areion512EMEncryptVEX", areion512EMEncryptVEX)
		runEM512("areion512EMDecryptVEX", areion512EMDecryptVEX)
		runEM256("areion256EM2EncryptVEX", areion256EM2EncryptVEX)
		runEM256("areion256EM2DecryptVEX", areion256EM2DecryptVEX)
		runEM512("areion512EM2EncryptVEX", areion512EM2EncryptVEX)
		runEM512("areion512EM2DecryptVEX", areion512EM2DecryptVEX)
		runTEM256("areion256TEMEncryptVEX", areion256TEMEncryptVEX)
		runTEM256("areion256TEMDecryptVEX", areion256TEMDecryptVEX)
		runTEM512("areion512TEMEncryptVEX", areion512TEMEncryptVEX)
		runTEM512("areion512TEMDecryptVEX", areion512TEMDecryptVEX)
		runTEM256("areion256TEM2EncryptVEX", areion256TEM2EncryptVEX)
		runTEM256("areion256TEM2DecryptVEX", areion256TEM2DecryptVEX)
		runTEM512("areion512TEM2EncryptVEX", areion512TEM2EncryptVEX)
		runTEM512("areion512TEM2DecryptVEX", areion512TEM2DecryptVEX)
		runSoEM256x4("areion256EMEncryptx4VAESAVX2", areion256EMEncryptx4VAESAVX2)
		runSoEM256x4("areion256EMDecryptx4VAESAVX2", areion256EMDecryptx4VAESAVX2)
		runSoEM512x4("areion512EMEncryptx4VAESAVX2", areion512EMEncryptx4VAESAVX2)
		runSoEM512x4("areion512EMDecryptx4VAESAVX2", areion512EMDecryptx4VAESAVX2)
		runSoEM256x4("areion256EM2Encryptx4VAESAVX2", areion256EM2Encryptx4VAESAVX2)
		runSoEM256x4("areion256EM2Decryptx4VAESAVX2", areion256EM2Decryptx4VAESAVX2)
		runSoEM512x4("areion512EM2Encryptx4VAESAVX2", areion512EM2Encryptx4VAESAVX2)
		runSoEM512x4("areion512EM2Decryptx4VAESAVX2", areion512EM2Decryptx4VAESAVX2)
		runTEM256x4("areion256TEMEncryptx4VAESAVX2", areion256TEMEncryptx4VAESAVX2)
		runTEM256x4("areion256TEMDecryptx4VAESAVX2", areion256TEMDecryptx4VAESAVX2)
		runTEM512x4("areion512TEMEncryptx4VAESAVX2", areion512TEMEncryptx4VAESAVX2)
		runTEM512x4("areion512TEMDecryptx4VAESAVX2", areion512TEMDecryptx4VAESAVX2)
		runTEM256x4("areion256TEM2Encryptx4VAESAVX2", areion256TEM2Encryptx4VAESAVX2)
		runTEM256x4("areion256TEM2Decryptx4VAESAVX2", areion256TEM2Decryptx4VAESAVX2)
		runTEM512x4("areion512TEM2Encryptx4VAESAVX2", areion512TEM2Encryptx4VAESAVX2)
		runTEM512x4("areion512TEM2Decryptx4VAESAVX2", areion512TEM2Decryptx4VAESAVX2)
	case "avx512":
		runR256Block("rijndael256EncryptBlockVexAsm", rijndael256EncryptBlockVexAsm)
		runR256Block4("rijndael256Encrypt4BlocksZmmAsm", rijndael256Encrypt4BlocksZmmAsm)
		runV256Block("vistrutah256EncryptBlockYmmAsm", vistrutah256EncryptBlockYmmAsm)
		runV256Block4("vistrutah256Encrypt4BlocksZmmAsm", vistrutah256Encrypt4BlocksZmmAsm)
		runV512Block256("vistrutah512EncryptBlock256ZmmAsm", vistrutah512EncryptBlock256ZmmAsm)
		runV512Block512("vistrutah512EncryptBlock512ZmmAsm", vistrutah512EncryptBlock512ZmmAsm)
		runV512Block4_256("vistrutah512Encrypt4Blocks256ZmmAsm", vistrutah512Encrypt4Blocks256ZmmAsm)
		runV512Block4_512("vistrutah512Encrypt4Blocks512ZmmAsm", vistrutah512Encrypt4Blocks512ZmmAsm)
		run256x4("areion256Permutex4RC", areion256Permutex4RC)
		run256x4("areion256InversePermutex4RC", areion256InversePermutex4RC)
		run512x4("areion512Permutex4RC", areion512Permutex4RC)
		run512x4("areion512InversePermutex4RC", areion512InversePermutex4RC)
		runSoEM256x4("areion256SoEMPermutex4Interleaved", areion256SoEMPermutex4Interleaved)
		runSoEM512x4("areion512SoEMPermutex4Interleaved", areion512SoEMPermutex4Interleaved)
		runEM256("areion256EMEncryptVEX", areion256EMEncryptVEX)
		runEM256("areion256EMDecryptVEX", areion256EMDecryptVEX)
		runEM512("areion512EMEncryptVEX", areion512EMEncryptVEX)
		runEM512("areion512EMDecryptVEX", areion512EMDecryptVEX)
		runEM256("areion256EM2EncryptVEX", areion256EM2EncryptVEX)
		runEM256("areion256EM2DecryptVEX", areion256EM2DecryptVEX)
		runEM512("areion512EM2EncryptVEX", areion512EM2EncryptVEX)
		runEM512("areion512EM2DecryptVEX", areion512EM2DecryptVEX)
		runTEM256("areion256TEMEncryptVEX", areion256TEMEncryptVEX)
		runTEM256("areion256TEMDecryptVEX", areion256TEMDecryptVEX)
		runTEM512("areion512TEMEncryptVEX", areion512TEMEncryptVEX)
		runTEM512("areion512TEMDecryptVEX", areion512TEMDecryptVEX)
		runTEM256("areion256TEM2EncryptVEX", areion256TEM2EncryptVEX)
		runTEM256("areion256TEM2DecryptVEX", areion256TEM2DecryptVEX)
		runTEM512("areion512TEM2EncryptVEX", areion512TEM2EncryptVEX)
		runTEM512("areion512TEM2DecryptVEX", areion512TEM2DecryptVEX)
		runSoEM256x4("areion256EMEncryptx4AVX512", areion256EMEncryptx4AVX512)
		runSoEM256x4("areion256EMDecryptx4AVX512", areion256EMDecryptx4AVX512)
		runSoEM512x4("areion512EMEncryptx4AVX512", areion512EMEncryptx4AVX512)
		runSoEM512x4("areion512EMDecryptx4AVX512", areion512EMDecryptx4AVX512)
		runSoEM256x4("areion256EM2Encryptx4AVX512", areion256EM2Encryptx4AVX512)
		runSoEM256x4("areion256EM2Decryptx4AVX512", areion256EM2Decryptx4AVX512)
		runSoEM512x4("areion512EM2Encryptx4AVX512", areion512EM2Encryptx4AVX512)
		runSoEM512x4("areion512EM2Decryptx4AVX512", areion512EM2Decryptx4AVX512)
		runTEM256x4("areion256TEMEncryptx4AVX512", areion256TEMEncryptx4AVX512)
		runTEM256x4("areion256TEMDecryptx4AVX512", areion256TEMDecryptx4AVX512)
		runTEM512x4("areion512TEMEncryptx4AVX512", areion512TEMEncryptx4AVX512)
		runTEM512x4("areion512TEMDecryptx4AVX512", areion512TEMDecryptx4AVX512)
		runTEM256x4("areion256TEM2Encryptx4AVX512", areion256TEM2Encryptx4AVX512)
		runTEM256x4("areion256TEM2Decryptx4AVX512", areion256TEM2Decryptx4AVX512)
		runTEM512x4("areion512TEM2Encryptx4AVX512", areion512TEM2Encryptx4AVX512)
		runTEM512x4("areion512TEM2Decryptx4AVX512", areion512TEM2Decryptx4AVX512)
	}
}

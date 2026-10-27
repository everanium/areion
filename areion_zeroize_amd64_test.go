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
	b0 := new(Block4)
	b1 := new(Block4)
	b2 := new(Block4)
	b3 := new(Block4)
	c0 := new(Block4)
	c1 := new(Block4)
	c2 := new(Block4)
	c3 := new(Block4)
	orig0 := new(Block4)
	orig1 := new(Block4)
	orig2 := new(Block4)
	orig3 := new(Block4)
	for i := 0; i < 64; i++ {
		orig0[i] = byte(0x13 + i*3)
		orig1[i] = byte(0x29 + i*5)
		orig2[i] = byte(0x47 + i*7)
		orig3[i] = byte(0x61 + i*11)
	}

	run256x4 := func(name string, fn func(*Block4, *Block4, *[15 * 64]byte)) {
		*b0, *b1 = *orig0, *orig1
		if w := captureAreionFrameAndRegResidue(func() {
			fn(b0, b1, &areionRC4x)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(orig0[:], orig1[:], b0[:], b1[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	run512x4 := func(name string, fn func(*Block4, *Block4, *Block4, *Block4, *[15 * 64]byte)) {
		*b0, *b1, *b2, *b3 = *orig0, *orig1, *orig2, *orig3
		if w := captureAreionFrameAndRegResidue(func() {
			fn(b0, b1, b2, b3, &areionRC4x)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(orig0[:], orig1[:], orig2[:], orig3[:], b0[:], b1[:], b2[:], b3[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runSoEM256x4 := func(name string, fn func(*Block4, *Block4, *Block4, *Block4)) {
		*b0, *b1, *b2, *b3 = *orig0, *orig1, *orig2, *orig3
		if w := captureAreionFrameAndRegResidue(func() {
			fn(b0, b1, b2, b3)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(orig0[:], orig1[:], orig2[:], orig3[:], b0[:], b1[:], b2[:], b3[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	runSoEM512x4 := func(name string, fn func(*Block4, *Block4, *Block4, *Block4, *Block4, *Block4, *Block4, *Block4)) {
		*b0, *b1, *b2, *b3 = *orig0, *orig1, *orig2, *orig3
		*c0, *c1, *c2, *c3 = *orig3, *orig2, *orig1, *orig0
		if w := captureAreionFrameAndRegResidue(func() {
			fn(b0, b1, b2, b3, c0, c1, c2, c3)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(orig0[:], orig1[:], orig2[:], orig3[:], b0[:], b1[:], b2[:], b3[:], c0[:], c1[:], c2[:], c3[:])
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

	switch tier {
	case "aesni":
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
	case "vex":
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
	case "vaesavx2":
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
	case "avx512":
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
	}
}

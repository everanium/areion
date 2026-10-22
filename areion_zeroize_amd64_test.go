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

	switch tier {
	case "aesni":
		run256x4("areion256Permutex4AesNiRC", areion256Permutex4AesNiRC)
		run256x4("areion256InversePermutex4AesNiRC", areion256InversePermutex4AesNiRC)
		run512x4("areion512Permutex4AesNiRC", areion512Permutex4AesNiRC)
		run512x4("areion512InversePermutex4AesNiRC", areion512InversePermutex4AesNiRC)
		runSoEM256x4("areion256SoEMPermutex4AesNi", areion256SoEMPermutex4AesNi)
		runSoEM512x4("areion512SoEMPermutex4AesNi", areion512SoEMPermutex4AesNi)
	case "vex":
		run256x4("areion256Permutex4VexRC", areion256Permutex4VexRC)
		run256x4("areion256InversePermutex4VexRC", areion256InversePermutex4VexRC)
		run512x4("areion512Permutex4VexRC", areion512Permutex4VexRC)
		run512x4("areion512InversePermutex4VexRC", areion512InversePermutex4VexRC)
		runSoEM256x4("areion256SoEMPermutex4Vex", areion256SoEMPermutex4Vex)
		runSoEM512x4("areion512SoEMPermutex4Vex", areion512SoEMPermutex4Vex)
	case "vaesavx2":
		run256x4("areion256Permutex4Avx2RC", areion256Permutex4Avx2RC)
		run256x4("areion256InversePermutex4Avx2RC", areion256InversePermutex4Avx2RC)
		run512x4("areion512Permutex4Avx2RC", areion512Permutex4Avx2RC)
		run512x4("areion512InversePermutex4Avx2RC", areion512InversePermutex4Avx2RC)
		runSoEM256x4("areion256SoEMPermutex4VaesAvx2", areion256SoEMPermutex4VaesAvx2)
		runSoEM512x4("areion512SoEMPermutex4VaesAvx2", areion512SoEMPermutex4VaesAvx2)
	case "avx512":
		run256x4("areion256Permutex4RC", areion256Permutex4RC)
		run256x4("areion256InversePermutex4RC", areion256InversePermutex4RC)
		run512x4("areion512Permutex4RC", areion512Permutex4RC)
		run512x4("areion512InversePermutex4RC", areion512InversePermutex4RC)
		runSoEM256x4("areion256SoEMPermutex4Interleaved", areion256SoEMPermutex4Interleaved)
		runSoEM512x4("areion512SoEMPermutex4Interleaved", areion512SoEMPermutex4Interleaved)
	}
}

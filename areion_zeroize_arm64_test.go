//go:build arm64 && !purego

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
func areionResidueProbe(fn func(), res []uint64, regs *[areionSIMDWords]uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -areionResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = areionResidueSentinel
	}
	areionResidueDeep(fn, 0, regs)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func areionResidueDeep(fn func(), i int, regs *[areionSIMDWords]uint64) byte {
	var pad [areionResiduePad]byte
	pad[i] = 1
	dumpSIMDRegs(regs, false)
	fn()
	dumpSIMDRegs(regs, false)
	return pad[(i+7)%len(pad)]
}

//go:noinline
func captureAreionFrameAndRegResidue(call func(), dst *[areionTotalWords]uint64) int {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	done := make(chan struct{})
	go func() {
		defer close(done)
		areionResidueGrow(0)
		var simd [areionSIMDWords]uint64
		areionResidueProbe(call, dst[:areionStackWords], &simd)
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

	run256x4 := func(name string, fn func(*Block4, *Block4, *[15][16]byte)) {
		*b0, *b1 = *orig0, *orig1
		if w := captureAreionFrameAndRegResidue(func() {
			fn(b0, b1, &roundConstantsP1)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(orig0[:], orig1[:], b0[:], b1[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	run512x4 := func(name string, fn func(*Block4, *Block4, *Block4, *Block4, *[15][16]byte)) {
		*b0, *b1, *b2, *b3 = *orig0, *orig1, *orig2, *orig3
		if w := captureAreionFrameAndRegResidue(func() {
			fn(b0, b1, b2, b3, &roundConstantsP1)
		}, res); w == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(orig0[:], orig1[:], orig2[:], orig3[:], b0[:], b1[:], b2[:], b3[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, name, word, off, areionResidueWindow)
		}
	}

	run256x4("areion256Permutex4RC", areion256Permutex4RC)
	run256x4("areion256InversePermutex4RC", areion256InversePermutex4RC)
	run512x4("areion512Permutex4RC", areion512Permutex4RC)
	run512x4("areion512InversePermutex4RC", areion512InversePermutex4RC)

	*b0, *b1, *b2, *b3 = *orig0, *orig1, *orig2, *orig3
	if w := captureAreionFrameAndRegResidue(func() {
		areion256SoEMPermutex4NEON(b0, b1, b2, b3)
	}, res); w == 0 {
		t.Fatalf("[%s] areion256SoEMPermutex4NEON: probe missed stack window", tier)
	}
	if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(orig0[:], orig1[:], orig2[:], orig3[:], b0[:], b1[:], b2[:], b3[:])); found {
		t.Fatalf("[%s] areion256SoEMPermutex4NEON leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
	}

	*b0, *b1, *b2, *b3 = *orig0, *orig1, *orig2, *orig3
	*c0, *c1, *c2, *c3 = *orig3, *orig2, *orig1, *orig0
	if w := captureAreionFrameAndRegResidue(func() {
		areion512SoEMPermutex4NEON(b0, b1, b2, b3, c0, c1, c2, c3)
	}, res); w == 0 {
		t.Fatalf("[%s] areion512SoEMPermutex4NEON: probe missed stack window", tier)
	}
	if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(orig0[:], orig1[:], orig2[:], orig3[:], b0[:], b1[:], b2[:], b3[:], c0[:], c1[:], c2[:], c3[:])); found {
		t.Fatalf("[%s] areion512SoEMPermutex4NEON leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
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

	runEM256("areion256EMEncryptAsm", areion256EMEncryptAsm)
	runEM256("areion256EMDecryptAsm", areion256EMDecryptAsm)
	runEM512("areion512EMEncryptAsm", areion512EMEncryptAsm)
	runEM512("areion512EMDecryptAsm", areion512EMDecryptAsm)
	runEM256("areion256EM2EncryptAsm", areion256EM2EncryptAsm)
	runEM256("areion256EM2DecryptAsm", areion256EM2DecryptAsm)
	runEM512("areion512EM2EncryptAsm", areion512EM2EncryptAsm)
	runEM512("areion512EM2DecryptAsm", areion512EM2DecryptAsm)
	runTEM256("areion256TEMEncryptAsm", areion256TEMEncryptAsm)
	runTEM256("areion256TEMDecryptAsm", areion256TEMDecryptAsm)
	runTEM512("areion512TEMEncryptAsm", areion512TEMEncryptAsm)
	runTEM512("areion512TEMDecryptAsm", areion512TEMDecryptAsm)
	runTEM256("areion256TEM2EncryptAsm", areion256TEM2EncryptAsm)
	runTEM256("areion256TEM2DecryptAsm", areion256TEM2DecryptAsm)
	runTEM512("areion512TEM2EncryptAsm", areion512TEM2EncryptAsm)
	runTEM512("areion512TEM2DecryptAsm", areion512TEM2DecryptAsm)
}

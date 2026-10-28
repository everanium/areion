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
	hasSIMDRegProbe       = true
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

	run256x4 := func(name string, fn func(*[32]byte, *[32]byte, *[32]byte, *[32]byte, *[15][16]byte)) {
		*b256 = *orig256
		if w := captureAreionFrameAndRegResidue(func() {
			fn(&b256[0], &b256[1], &b256[2], &b256[3], &roundConstantsP1)
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

	run512x4 := func(name string, fn func(*[64]byte, *[64]byte, *[64]byte, *[64]byte, *[15][16]byte)) {
		*b512 = *orig512
		if w := captureAreionFrameAndRegResidue(func() {
			fn(&b512[0], &b512[1], &b512[2], &b512[3], &roundConstantsP1)
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

	run256x4("areion256Permutex4RC", areion256Permutex4RC)
	run256x4("areion256InversePermutex4RC", areion256InversePermutex4RC)
	run512x4("areion512Permutex4RC", areion512Permutex4RC)
	run512x4("areion512InversePermutex4RC", areion512InversePermutex4RC)
	runSoEM256x4("areion256SoEMPermutex4NEON", areion256SoEMPermutex4NEON)
	runSoEM512x4("areion512SoEMPermutex4NEON", areion512SoEMPermutex4NEON)
	runSoEM256x4("areion256EMEncryptx4Asm", areion256EMEncryptx4Asm)
	runSoEM256x4("areion256EMDecryptx4Asm", areion256EMDecryptx4Asm)
	runSoEM512x4("areion512EMEncryptx4Asm", areion512EMEncryptx4Asm)
	runSoEM512x4("areion512EMDecryptx4Asm", areion512EMDecryptx4Asm)
	runSoEM256x4("areion256EM2Encryptx4Asm", areion256EM2Encryptx4Asm)
	runSoEM256x4("areion256EM2Decryptx4Asm", areion256EM2Decryptx4Asm)
	runSoEM512x4("areion512EM2Encryptx4Asm", areion512EM2Encryptx4Asm)
	runSoEM512x4("areion512EM2Decryptx4Asm", areion512EM2Decryptx4Asm)
	runTEM256x4("areion256TEMEncryptx4Asm", areion256TEMEncryptx4Asm)
	runTEM256x4("areion256TEMDecryptx4Asm", areion256TEMDecryptx4Asm)
	runTEM512x4("areion512TEMEncryptx4Asm", areion512TEMEncryptx4Asm)
	runTEM512x4("areion512TEMDecryptx4Asm", areion512TEMDecryptx4Asm)
	runTEM256x4("areion256TEM2Encryptx4Asm", areion256TEM2Encryptx4Asm)
	runTEM256x4("areion256TEM2Decryptx4Asm", areion256TEM2Decryptx4Asm)
	runTEM512x4("areion512TEM2Encryptx4Asm", areion512TEM2Encryptx4Asm)
	runTEM512x4("areion512TEM2Decryptx4Asm", areion512TEM2Decryptx4Asm)

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

	dm256M := new([32]byte)
	dm256Out := new([32]byte)
	for i := range dm256M {
		dm256M[i] = byte(0x37 + i*11)
	}
	if w := captureAreionFrameAndRegResidue(func() {
		areion256DMAsm(dm256Out, dm256M)
	}, res); w == 0 {
		t.Fatalf("[%s] areion256DMAsm: probe missed stack window", tier)
	}
	if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(dm256M[:], dm256Out[:])); found {
		t.Fatalf("[%s] areion256DMAsm leaked word %#016x at offset %d", tier, word, off)
	}

	dm512M := new([64]byte)
	dm512Out := new([32]byte)
	for i := range dm512M {
		dm512M[i] = byte(0x41 + i*7)
	}
	if w := captureAreionFrameAndRegResidue(func() {
		areion512DMAsm(dm512Out, dm512M)
	}, res); w == 0 {
		t.Fatalf("[%s] areion512DMAsm: probe missed stack window", tier)
	}
	if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(dm512M[:], dm512Out[:])); found {
		t.Fatalf("[%s] areion512DMAsm leaked word %#016x at offset %d", tier, word, off)
	}

	ekKey := new([16]byte)
	ekRK := new([11][16]byte)
	for i := range ekKey {
		ekKey[i] = byte(0x53 + i*13)
	}
	if w := captureAreionFrameAndRegResidue(func() {
		aes128ExpandKeyAsm(ekRK, ekKey)
	}, res); w == 0 {
		t.Fatalf("[%s] aes128ExpandKeyAsm: probe missed stack window", tier)
	}
	ekTargets := bytesToNonZeroWords(ekKey[:])
	for r := range ekRK {
		ekTargets = append(ekTargets, bytesToNonZeroWords(ekRK[r][:])...)
	}
	if word, off, found := scanForAreionWords(res, ekTargets); found {
		t.Fatalf("[%s] aes128ExpandKeyAsm leaked word %#016x at offset %d", tier, word, off)
	}

	r256RK := new([15][32]byte)
	r256In := new([32]byte)
	r256Out := new([32]byte)
	r256In4 := new([4][32]byte)
	r256Out4 := new([4][32]byte)
	for r := 0; r < 15; r++ {
		for i := 0; i < 32; i++ {
			r256RK[r][i] = byte(0x27 + r*19 + i*7)
		}
	}
	for i := range r256In {
		r256In[i] = byte(0x89 + i*13)
	}
	for l := 0; l < 4; l++ {
		for i := 0; i < 32; i++ {
			r256In4[l][i] = byte(0x3B + l*29 + i*11)
		}
	}
	var r256RKTargets []uint64
	for r := 0; r < 15; r++ {
		r256RKTargets = append(r256RKTargets, bytesToNonZeroWords(r256RK[r][:])...)
	}
	if w := captureAreionFrameAndRegResidue(func() {
		rijndael256EncryptBlockAsm(r256RK, r256Out, r256In)
	}, res); w == 0 {
		t.Fatalf("[%s] rijndael256EncryptBlockAsm: probe missed stack window", tier)
	}
	if word, off, found := scanForAreionWords(res, append(append([]uint64{}, r256RKTargets...), bytesToNonZeroWords(r256In[:], r256Out[:])...)); found {
		t.Fatalf("[%s] rijndael256EncryptBlockAsm leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
	}

	if w := captureAreionFrameAndRegResidue(func() {
		rijndael256Encrypt4BlocksAsm(r256RK, r256Out4, r256In4)
	}, res); w == 0 {
		t.Fatalf("[%s] rijndael256Encrypt4BlocksAsm: probe missed stack window", tier)
	}
	r256Targets4 := append([]uint64{}, r256RKTargets...)
	for l := 0; l < 4; l++ {
		r256Targets4 = append(r256Targets4, bytesToNonZeroWords(r256In4[l][:], r256Out4[l][:])...)
	}
	if word, off, found := scanForAreionWords(res, r256Targets4); found {
		t.Fatalf("[%s] rijndael256Encrypt4BlocksAsm leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
	}

	vKey256 := new([32]byte)
	vKey512 := new([64]byte)
	vIn256 := new([32]byte)
	vOut256 := new([32]byte)
	vIn256x4 := new([4][32]byte)
	vOut256x4 := new([4][32]byte)
	vIn512 := new([64]byte)
	vOut512 := new([64]byte)
	vIn512x4 := new([4][64]byte)
	vOut512x4 := new([4][64]byte)
	for i := 0; i < 32; i++ {
		vKey256[i] = byte(0x31 + i*7)
		vIn256[i] = byte(0x93 + i*13)
	}
	for i := 0; i < 64; i++ {
		vKey512[i] = byte(0x59 + i*3)
		vIn512[i] = byte(0x89 + i*5)
	}
	for l := 0; l < 4; l++ {
		for i := 0; i < 32; i++ {
			vIn256x4[l][i] = byte(0x47 + l*29 + i*11)
		}
		for i := 0; i < 64; i++ {
			vIn512x4[l][i] = byte(0x3B + l*23 + i*5)
		}
	}
	for _, r := range []int{10, 14} {
		if w := captureAreionFrameAndRegResidue(func() {
			vistrutah256EncryptBlockAsm(vOut256, vIn256, vKey256, r)
		}, res); w == 0 {
			t.Fatalf("[%s] vistrutah256EncryptBlockAsm(%d): probe missed stack window", tier, r)
		}
		if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(vKey256[:], vIn256[:], vOut256[:])); found {
			t.Fatalf("[%s] vistrutah256EncryptBlockAsm(%d) leaked word %#016x at offset %d", tier, r, word, off)
		}
		if w := captureAreionFrameAndRegResidue(func() {
			vistrutah256Encrypt4BlocksAsm(vOut256x4, vIn256x4, vKey256, r)
		}, res); w == 0 {
			t.Fatalf("[%s] vistrutah256Encrypt4BlocksAsm(%d): probe missed stack window", tier, r)
		}
		vTargets := bytesToNonZeroWords(vKey256[:])
		for l := 0; l < 4; l++ {
			vTargets = append(vTargets, bytesToNonZeroWords(vIn256x4[l][:], vOut256x4[l][:])...)
		}
		if word, off, found := scanForAreionWords(res, vTargets); found {
			t.Fatalf("[%s] vistrutah256Encrypt4BlocksAsm(%d) leaked word %#016x at offset %d", tier, r, word, off)
		}
	}
	for _, r := range []int{10, 12, 14, 18} {
		if w := captureAreionFrameAndRegResidue(func() {
			vistrutah512EncryptBlock256Asm(vOut512, vIn512, vKey256, r)
		}, res); w == 0 {
			t.Fatalf("[%s] vistrutah512EncryptBlock256Asm(%d): probe missed stack window", tier, r)
		}
		if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(vKey256[:], vIn512[:], vOut512[:])); found {
			t.Fatalf("[%s] vistrutah512EncryptBlock256Asm(%d) leaked word %#016x at offset %d", tier, r, word, off)
		}
		if w := captureAreionFrameAndRegResidue(func() {
			vistrutah512EncryptBlock512Asm(vOut512, vIn512, vKey512, r)
		}, res); w == 0 {
			t.Fatalf("[%s] vistrutah512EncryptBlock512Asm(%d): probe missed stack window", tier, r)
		}
		if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(vKey512[:], vIn512[:], vOut512[:])); found {
			t.Fatalf("[%s] vistrutah512EncryptBlock512Asm(%d) leaked word %#016x at offset %d", tier, r, word, off)
		}
		if w := captureAreionFrameAndRegResidue(func() {
			vistrutah512Encrypt4Blocks256Asm(vOut512x4, vIn512x4, vKey256, r)
		}, res); w == 0 {
			t.Fatalf("[%s] vistrutah512Encrypt4Blocks256Asm(%d): probe missed stack window", tier, r)
		}
		vTargets256 := bytesToNonZeroWords(vKey256[:])
		for l := 0; l < 4; l++ {
			vTargets256 = append(vTargets256, bytesToNonZeroWords(vIn512x4[l][:], vOut512x4[l][:])...)
		}
		if word, off, found := scanForAreionWords(res, vTargets256); found {
			t.Fatalf("[%s] vistrutah512Encrypt4Blocks256Asm(%d) leaked word %#016x at offset %d", tier, r, word, off)
		}
		if w := captureAreionFrameAndRegResidue(func() {
			vistrutah512Encrypt4Blocks512Asm(vOut512x4, vIn512x4, vKey512, r)
		}, res); w == 0 {
			t.Fatalf("[%s] vistrutah512Encrypt4Blocks512Asm(%d): probe missed stack window", tier, r)
		}
		vTargets512 := bytesToNonZeroWords(vKey512[:])
		for l := 0; l < 4; l++ {
			vTargets512 = append(vTargets512, bytesToNonZeroWords(vIn512x4[l][:], vOut512x4[l][:])...)
		}
		if word, off, found := scanForAreionWords(res, vTargets512); found {
			t.Fatalf("[%s] vistrutah512Encrypt4Blocks512Asm(%d) leaked word %#016x at offset %d", tier, r, word, off)
		}
	}
}

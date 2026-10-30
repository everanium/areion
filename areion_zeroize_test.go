package areion

import (
	"encoding/binary"
	"runtime"
	"testing"
)

var areionSink uint64

//go:noinline
func leakyAreionFrame(secret uint64, i int) {
	var frame [64]uint64
	for j := range frame {
		frame[j] = secret
	}
	areionSink = frame[(i+1)%len(frame)]
}

func bytesToNonZeroWords(bufs ...[]byte) []uint64 {
	var out []uint64
	for _, b := range bufs {
		for i := 0; i+8 <= len(b); i += 8 {
			wLE := binary.LittleEndian.Uint64(b[i : i+8])
			if wLE != 0 {
				out = append(out, wLE)
			}
			wBE := binary.BigEndian.Uint64(b[i : i+8])
			if wBE != 0 && wBE != wLE {
				out = append(out, wBE)
			}
		}
	}
	return out
}

func matchAreionTarget(w uint64, targets []uint64) (uint64, bool) {
	if w == 0 || w == areionResidueSentinel {
		return 0, false
	}
	for _, t := range targets {
		if t != 0 && w == t {
			return t, true
		}
	}
	return 0, false
}

func scanForAreionWords(window *[areionTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	if t, off, ok := scanForAreionWordsInStack(window, targets); ok {
		return t, off, true
	}
	return scanForAreionWordsInRegs(window, targets)
}

func scanForAreionWordsInStack(window *[areionTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i := 0; i < areionStackWords; i++ {
		w := window[i]
		if t, ok := matchAreionTarget(w, targets); ok {
			return t, i * 8, true
		}
		if ^uint(0)>>63 == 0 && i > 0 {
			prev := window[i-1]
			if t, ok := matchAreionTarget((w>>32)|(prev<<32), targets); ok {
				return t, i*8 - 4, true
			}
			if t, ok := matchAreionTarget((w<<32)|(prev>>32), targets); ok {
				return t, i*8 - 4, true
			}
		}
	}
	return 0, 0, false
}

func scanForAreionWordsInRegs(window *[areionTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i := areionStackWords; i < len(window); i++ {
		w := window[i]
		if w == 0 {
			continue
		}
		for _, t := range targets {
			if t != 0 && w == t {
				return t, i * 8, true
			}
		}
	}
	return 0, 0, false
}

// TestFusedKernelsLeaveNoSecretInFrame verifies that every hardware-accelerated
// Areion permutation, inverse permutation, SoEM22 construction, and AES round
// helper wipes its vector registers, scratch GPRs, and stack frame slots before
// returning across all available hardware tiers.
func TestFusedKernelsLeaveNoSecretInFrame(t *testing.T) {
	if raceEnabled {
		t.Skip("skipping raw stack/register frame inspection under -race instrumentation")
	}
	res := new([areionTotalWords]uint64)

	t.Run("NegativeControl_Stack", func(t *testing.T) {
		const canary = uint64(0xCAFEBABE13579BDF)
		idx := 3
		written := captureAreionFrameAndRegResidue(func() {
			leakyAreionFrame(canary, idx)
		}, res)
		runtime.KeepAlive(areionSink)
		if written == 0 {
			t.Fatal("negative control failed: no stack words were written inside the probe window")
		}
		if _, _, found := scanForAreionWordsInStack(res, []uint64{canary}); !found {
			t.Fatal("negative control failed: stack canary written to callee frame was not observed in stack window")
		}
	})

	t.Run("NegativeControl_SIMDAndGPR", func(t *testing.T) {
		if !hasSIMDRegProbe {
			t.Skip("SIMD/GPR register dump probe requires native amd64 or arm64 assembly")
		}
		const mask = uint64(0x5555555555555555)
		const secret = uint64(0xFEEDFACECAFEBEEF)
		masked := secret ^ mask
		written := captureAreionFrameAndRegResidue(func() {
			dirtySIMDRegForTest(masked)
		}, res)
		if written == 0 {
			t.Fatal("negative control failed: no stack words were written inside the probe window")
		}
		if _, _, found := scanForAreionWordsInRegs(res, []uint64{secret}); !found {
			t.Fatal("negative control failed: register canary left in X2/V2/R12 was not observed by post-RET register dump")
		}
	})

	origTier := Tier()
	defer func() { _ = SetTier(origTier) }()

	for _, tier := range availableTiers() {
		t.Run("tier="+tier, func(t *testing.T) {
			if err := SetTier(tier); err != nil {
				t.Fatalf("SetTier(%s): %v", tier, err)
			}

			// 1. Direct assembly x4 kernels (both stack and SIMD/GPR registers)
			if tier != "purego" {
				testAreionArchAsmKernels(t, tier, res)
			}

			scanFn := scanForAreionWords

			// 2. Single-block Permute256 / Permute256P2 / InversePermute256 / InversePermute256P2
			s256 := new(State256)
			orig256 := new(State256)
			for i := range orig256 {
				orig256[i] = byte(0xA1 + i*3)
			}
			for _, op := range []struct {
				name string
				fn   func(*State256)
			}{
				{"Permute256", Permute256},
				{"Permute256P2", Permute256P2},
				{"InversePermute256", InversePermute256},
				{"InversePermute256P2", InversePermute256P2},
			} {
				*s256 = *orig256
				if w := captureAreionFrameAndRegResidue(func() {
					op.fn(s256)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, op.name)
				}
				targets := bytesToNonZeroWords(orig256[:], s256[:])
				if word, off, found := scanFn(res, targets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, op.name, word, off, areionResidueWindow)
				}
			}

			// 3. Single-block Permute512 / Permute512P2 / InversePermute512 / InversePermute512P2
			s512 := new(State512)
			orig512 := new(State512)
			for i := range orig512 {
				orig512[i] = byte(0x53 + i*5)
			}
			for _, op := range []struct {
				name string
				fn   func(*State512)
			}{
				{"Permute512", Permute512},
				{"Permute512P2", Permute512P2},
				{"InversePermute512", InversePermute512},
				{"InversePermute512P2", InversePermute512P2},
			} {
				*s512 = *orig512
				if w := captureAreionFrameAndRegResidue(func() {
					op.fn(s512)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, op.name)
				}
				targets := bytesToNonZeroWords(orig512[:], s512[:])
				if word, off, found := scanFn(res, targets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d (window=%d)", tier, op.name, word, off, areionResidueWindow)
				}
			}

			// 4. 4-way Go wrappers (both stack and SIMD/GPR registers)
			s256x4 := new([4][32]byte)
			orig256x4 := new([4][32]byte)
			for l := 0; l < 4; l++ {
				for i := 0; i < 32; i++ {
					orig256x4[l][i] = byte(0x19 + l*37 + i*7)
				}
			}
			for _, op := range []struct {
				name string
				fn   func(*[4][32]byte)
			}{
				{"Permute256x4", Permute256x4},
				{"Permute256P2x4", Permute256P2x4},
				{"InversePermute256x4", InversePermute256x4},
				{"InversePermute256P2x4", InversePermute256P2x4},
			} {
				*s256x4 = *orig256x4
				if w := captureAreionFrameAndRegResidue(func() {
					op.fn(s256x4)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, op.name)
				}
				var targets []uint64
				for l := 0; l < 4; l++ {
					targets = append(targets, bytesToNonZeroWords(orig256x4[l][:], s256x4[l][:])...)
				}
				if word, off, found := scanFn(res, targets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, op.name, word, off)
				}
			}

			s512x4 := new([4][64]byte)
			orig512x4 := new([4][64]byte)
			for l := 0; l < 4; l++ {
				for i := 0; i < 64; i++ {
					orig512x4[l][i] = byte(0x2B + l*41 + i*3)
				}
			}
			for _, op := range []struct {
				name string
				fn   func(*[4][64]byte)
			}{
				{"Permute512x4", Permute512x4},
				{"Permute512P2x4", Permute512P2x4},
				{"InversePermute512x4", InversePermute512x4},
				{"InversePermute512P2x4", InversePermute512P2x4},
			} {
				*s512x4 = *orig512x4
				if w := captureAreionFrameAndRegResidue(func() {
					op.fn(s512x4)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, op.name)
				}
				var targets []uint64
				for l := 0; l < 4; l++ {
					targets = append(targets, bytesToNonZeroWords(orig512x4[l][:], s512x4[l][:])...)
				}
				if word, off, found := scanFn(res, targets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, op.name, word, off)
				}
			}

			// 5. DM256 / DM512 / SoEM256 / SoEM512 / SoEM256x4 / SoEM512x4
			k256 := new([64]byte)
			m256 := new([32]byte)
			out256 := new([32]byte)
			for i := range k256 {
				k256[i] = byte(0x71 + i*3)
			}
			for i := range m256 {
				m256[i] = byte(0x3D + i*5)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*out256 = DM256(m256)
			}, res); w == 0 {
				t.Fatalf("[%s] DM256: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(m256[:])); found {
				t.Fatalf("[%s] DM256 leaked msg word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out256 = SoEM256(k256, m256)
			}, res); w == 0 {
				t.Fatalf("[%s] SoEM256: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k256[:], m256[:])); found {
				t.Fatalf("[%s] SoEM256 leaked key/msg word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			k512 := new([128]byte)
			m512 := new([64]byte)
			out512 := new([64]byte)
			for i := range k512 {
				k512[i] = byte(0x83 + i*3)
			}
			for i := range m512 {
				m512[i] = byte(0x47 + i*5)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*out256 = DM512(m512)
			}, res); w == 0 {
				t.Fatalf("[%s] DM512: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(m512[:])); found {
				t.Fatalf("[%s] DM512 leaked msg word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out512 = SoEM512(k512, m512)
			}, res); w == 0 {
				t.Fatalf("[%s] SoEM512: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k512[:], m512[:])); found {
				t.Fatalf("[%s] SoEM512 leaked key/msg word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			k256x4 := new([4][64]byte)
			m256x4 := new([4][32]byte)
			out256x4 := new([4][32]byte)
			for l := 0; l < 4; l++ {
				for i := 0; i < 64; i++ {
					k256x4[l][i] = byte(0x91 + l*29 + i*3)
				}
				for i := 0; i < 32; i++ {
					m256x4[l][i] = byte(0x4B + l*31 + i*5)
				}
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*out256x4 = SoEM256x4(k256x4, m256x4)
			}, res); w == 0 {
				t.Fatalf("[%s] SoEM256x4: probe missed stack window", tier)
			}
			var soem256x4Targets []uint64
			for l := 0; l < 4; l++ {
				soem256x4Targets = append(soem256x4Targets, bytesToNonZeroWords(k256x4[l][:], m256x4[l][:])...)
			}
			if word, off, found := scanFn(res, soem256x4Targets); found {
				t.Fatalf("[%s] SoEM256x4 leaked key/msg word %#016x at offset %d", tier, word, off)
			}

			k512x4 := new([4][128]byte)
			m512x4 := new([4][64]byte)
			out512x4 := new([4][64]byte)
			for l := 0; l < 4; l++ {
				for i := 0; i < 128; i++ {
					k512x4[l][i] = byte(0xA7 + l*23 + i*3)
				}
				for i := 0; i < 64; i++ {
					m512x4[l][i] = byte(0x59 + l*19 + i*5)
				}
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*out512x4 = SoEM512x4(k512x4, m512x4)
			}, res); w == 0 {
				t.Fatalf("[%s] SoEM512x4: probe missed stack window", tier)
			}
			var soem512x4Targets []uint64
			for l := 0; l < 4; l++ {
				soem512x4Targets = append(soem512x4Targets, bytesToNonZeroWords(k512x4[l][:], m512x4[l][:])...)
			}
			if word, off, found := scanFn(res, soem512x4Targets); found {
				t.Fatalf("[%s] SoEM512x4 leaked key/msg word %#016x at offset %d", tier, word, off)
			}

			// 5b. Wide-block Even-Mansour and Tweakable Even-Mansour constructions (32 public APIs)
			t256 := new([32]byte)
			dec256 := new([32]byte)
			for i := range t256 {
				t256[i] = byte(0x9D + i*7)
			}
			t512 := new([64]byte)
			dec512 := new([64]byte)
			for i := range t512 {
				t512[i] = byte(0xB3 + i*7)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out256 = EMEncrypt256(k256, m256)
			}, res); w == 0 {
				t.Fatalf("[%s] EMEncrypt256: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k256[:], m256[:])); found {
				t.Fatalf("[%s] EMEncrypt256 leaked key/msg word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*dec256 = EMDecrypt256(k256, out256)
			}, res); w == 0 {
				t.Fatalf("[%s] EMDecrypt256: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k256[:], out256[:])); found {
				t.Fatalf("[%s] EMDecrypt256 leaked key/ct word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out512 = EMEncrypt512(k512, m512)
			}, res); w == 0 {
				t.Fatalf("[%s] EMEncrypt512: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k512[:], m512[:])); found {
				t.Fatalf("[%s] EMEncrypt512 leaked key/msg word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*dec512 = EMDecrypt512(k512, out512)
			}, res); w == 0 {
				t.Fatalf("[%s] EMDecrypt512: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k512[:], out512[:])); found {
				t.Fatalf("[%s] EMDecrypt512 leaked key/ct word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out256 = EM2Encrypt256(k256, m256)
			}, res); w == 0 {
				t.Fatalf("[%s] EM2Encrypt256: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k256[:], m256[:])); found {
				t.Fatalf("[%s] EM2Encrypt256 leaked key/msg word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*dec256 = EM2Decrypt256(k256, out256)
			}, res); w == 0 {
				t.Fatalf("[%s] EM2Decrypt256: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k256[:], out256[:])); found {
				t.Fatalf("[%s] EM2Decrypt256 leaked key/ct word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out512 = EM2Encrypt512(k512, m512)
			}, res); w == 0 {
				t.Fatalf("[%s] EM2Encrypt512: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k512[:], m512[:])); found {
				t.Fatalf("[%s] EM2Encrypt512 leaked key/msg word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*dec512 = EM2Decrypt512(k512, out512)
			}, res); w == 0 {
				t.Fatalf("[%s] EM2Decrypt512: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k512[:], out512[:])); found {
				t.Fatalf("[%s] EM2Decrypt512 leaked key/ct word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out256 = TEMEncrypt256(k256, t256, m256)
			}, res); w == 0 {
				t.Fatalf("[%s] TEMEncrypt256: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k256[:], m256[:], t256[:])); found {
				t.Fatalf("[%s] TEMEncrypt256 leaked key/msg/tweak word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*dec256 = TEMDecrypt256(k256, t256, out256)
			}, res); w == 0 {
				t.Fatalf("[%s] TEMDecrypt256: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k256[:], out256[:], t256[:])); found {
				t.Fatalf("[%s] TEMDecrypt256 leaked key/ct/tweak word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out512 = TEMEncrypt512(k512, t512, m512)
			}, res); w == 0 {
				t.Fatalf("[%s] TEMEncrypt512: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k512[:], m512[:], t512[:])); found {
				t.Fatalf("[%s] TEMEncrypt512 leaked key/msg/tweak word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*dec512 = TEMDecrypt512(k512, t512, out512)
			}, res); w == 0 {
				t.Fatalf("[%s] TEMDecrypt512: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k512[:], out512[:], t512[:])); found {
				t.Fatalf("[%s] TEMDecrypt512 leaked key/ct/tweak word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out256 = TEM2Encrypt256(k256, t256, m256)
			}, res); w == 0 {
				t.Fatalf("[%s] TEM2Encrypt256: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k256[:], m256[:], t256[:])); found {
				t.Fatalf("[%s] TEM2Encrypt256 leaked key/msg/tweak word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*dec256 = TEM2Decrypt256(k256, t256, out256)
			}, res); w == 0 {
				t.Fatalf("[%s] TEM2Decrypt256: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k256[:], out256[:], t256[:])); found {
				t.Fatalf("[%s] TEM2Decrypt256 leaked key/ct/tweak word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out512 = TEM2Encrypt512(k512, t512, m512)
			}, res); w == 0 {
				t.Fatalf("[%s] TEM2Encrypt512: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k512[:], m512[:], t512[:])); found {
				t.Fatalf("[%s] TEM2Encrypt512 leaked key/msg/tweak word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*dec512 = TEM2Decrypt512(k512, t512, out512)
			}, res); w == 0 {
				t.Fatalf("[%s] TEM2Decrypt512: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(k512[:], out512[:], t512[:])); found {
				t.Fatalf("[%s] TEM2Decrypt512 leaked key/ct/tweak word %#016x at offset %d", tier, word, off)
			}

			t256x4 := new([4][32]byte)
			dec256x4 := new([4][32]byte)
			t512x4 := new([4][64]byte)
			dec512x4 := new([4][64]byte)
			var t256x4Targets, t512x4Targets []uint64
			for l := 0; l < 4; l++ {
				for i := 0; i < 32; i++ {
					t256x4[l][i] = byte(0xC1 + l*17 + i*7)
				}
				for i := 0; i < 64; i++ {
					t512x4[l][i] = byte(0xD3 + l*13 + i*7)
				}
				t256x4Targets = append(t256x4Targets, bytesToNonZeroWords(t256x4[l][:])...)
				t512x4Targets = append(t512x4Targets, bytesToNonZeroWords(t512x4[l][:])...)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out256x4 = EMEncrypt256x4(k256x4, m256x4)
			}, res); w == 0 {
				t.Fatalf("[%s] EMEncrypt256x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, soem256x4Targets); found {
				t.Fatalf("[%s] EMEncrypt256x4 leaked key/msg word %#016x at offset %d", tier, word, off)
			}

			var ct256x4Targets []uint64
			for l := 0; l < 4; l++ {
				ct256x4Targets = append(ct256x4Targets, bytesToNonZeroWords(k256x4[l][:], out256x4[l][:])...)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*dec256x4 = EMDecrypt256x4(k256x4, out256x4)
			}, res); w == 0 {
				t.Fatalf("[%s] EMDecrypt256x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, ct256x4Targets); found {
				t.Fatalf("[%s] EMDecrypt256x4 leaked key/ct word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out512x4 = EMEncrypt512x4(k512x4, m512x4)
			}, res); w == 0 {
				t.Fatalf("[%s] EMEncrypt512x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, soem512x4Targets); found {
				t.Fatalf("[%s] EMEncrypt512x4 leaked key/msg word %#016x at offset %d", tier, word, off)
			}

			var ct512x4Targets []uint64
			for l := 0; l < 4; l++ {
				ct512x4Targets = append(ct512x4Targets, bytesToNonZeroWords(k512x4[l][:], out512x4[l][:])...)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*dec512x4 = EMDecrypt512x4(k512x4, out512x4)
			}, res); w == 0 {
				t.Fatalf("[%s] EMDecrypt512x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, ct512x4Targets); found {
				t.Fatalf("[%s] EMDecrypt512x4 leaked key/ct word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out256x4 = EM2Encrypt256x4(k256x4, m256x4)
			}, res); w == 0 {
				t.Fatalf("[%s] EM2Encrypt256x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, soem256x4Targets); found {
				t.Fatalf("[%s] EM2Encrypt256x4 leaked key/msg word %#016x at offset %d", tier, word, off)
			}

			ct256x4Targets = ct256x4Targets[:0]
			for l := 0; l < 4; l++ {
				ct256x4Targets = append(ct256x4Targets, bytesToNonZeroWords(k256x4[l][:], out256x4[l][:])...)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*dec256x4 = EM2Decrypt256x4(k256x4, out256x4)
			}, res); w == 0 {
				t.Fatalf("[%s] EM2Decrypt256x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, ct256x4Targets); found {
				t.Fatalf("[%s] EM2Decrypt256x4 leaked key/ct word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out512x4 = EM2Encrypt512x4(k512x4, m512x4)
			}, res); w == 0 {
				t.Fatalf("[%s] EM2Encrypt512x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, soem512x4Targets); found {
				t.Fatalf("[%s] EM2Encrypt512x4 leaked key/msg word %#016x at offset %d", tier, word, off)
			}

			ct512x4Targets = ct512x4Targets[:0]
			for l := 0; l < 4; l++ {
				ct512x4Targets = append(ct512x4Targets, bytesToNonZeroWords(k512x4[l][:], out512x4[l][:])...)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*dec512x4 = EM2Decrypt512x4(k512x4, out512x4)
			}, res); w == 0 {
				t.Fatalf("[%s] EM2Decrypt512x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, ct512x4Targets); found {
				t.Fatalf("[%s] EM2Decrypt512x4 leaked key/ct word %#016x at offset %d", tier, word, off)
			}

			tem256EncTargets := append(append([]uint64{}, soem256x4Targets...), t256x4Targets...)
			if w := captureAreionFrameAndRegResidue(func() {
				*out256x4 = TEMEncrypt256x4(k256x4, t256x4, m256x4)
			}, res); w == 0 {
				t.Fatalf("[%s] TEMEncrypt256x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, tem256EncTargets); found {
				t.Fatalf("[%s] TEMEncrypt256x4 leaked key/msg/tweak word %#016x at offset %d", tier, word, off)
			}

			ct256x4Targets = ct256x4Targets[:0]
			for l := 0; l < 4; l++ {
				ct256x4Targets = append(ct256x4Targets, bytesToNonZeroWords(k256x4[l][:], out256x4[l][:], t256x4[l][:])...)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*dec256x4 = TEMDecrypt256x4(k256x4, t256x4, out256x4)
			}, res); w == 0 {
				t.Fatalf("[%s] TEMDecrypt256x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, ct256x4Targets); found {
				t.Fatalf("[%s] TEMDecrypt256x4 leaked key/ct/tweak word %#016x at offset %d", tier, word, off)
			}

			tem512EncTargets := append(append([]uint64{}, soem512x4Targets...), t512x4Targets...)
			if w := captureAreionFrameAndRegResidue(func() {
				*out512x4 = TEMEncrypt512x4(k512x4, t512x4, m512x4)
			}, res); w == 0 {
				t.Fatalf("[%s] TEMEncrypt512x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, tem512EncTargets); found {
				t.Fatalf("[%s] TEMEncrypt512x4 leaked key/msg/tweak word %#016x at offset %d", tier, word, off)
			}

			ct512x4Targets = ct512x4Targets[:0]
			for l := 0; l < 4; l++ {
				ct512x4Targets = append(ct512x4Targets, bytesToNonZeroWords(k512x4[l][:], out512x4[l][:], t512x4[l][:])...)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*dec512x4 = TEMDecrypt512x4(k512x4, t512x4, out512x4)
			}, res); w == 0 {
				t.Fatalf("[%s] TEMDecrypt512x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, ct512x4Targets); found {
				t.Fatalf("[%s] TEMDecrypt512x4 leaked key/ct/tweak word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out256x4 = TEM2Encrypt256x4(k256x4, t256x4, m256x4)
			}, res); w == 0 {
				t.Fatalf("[%s] TEM2Encrypt256x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, tem256EncTargets); found {
				t.Fatalf("[%s] TEM2Encrypt256x4 leaked key/msg/tweak word %#016x at offset %d", tier, word, off)
			}

			ct256x4Targets = ct256x4Targets[:0]
			for l := 0; l < 4; l++ {
				ct256x4Targets = append(ct256x4Targets, bytesToNonZeroWords(k256x4[l][:], out256x4[l][:], t256x4[l][:])...)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*dec256x4 = TEM2Decrypt256x4(k256x4, t256x4, out256x4)
			}, res); w == 0 {
				t.Fatalf("[%s] TEM2Decrypt256x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, ct256x4Targets); found {
				t.Fatalf("[%s] TEM2Decrypt256x4 leaked key/ct/tweak word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				*out512x4 = TEM2Encrypt512x4(k512x4, t512x4, m512x4)
			}, res); w == 0 {
				t.Fatalf("[%s] TEM2Encrypt512x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, tem512EncTargets); found {
				t.Fatalf("[%s] TEM2Encrypt512x4 leaked key/msg/tweak word %#016x at offset %d", tier, word, off)
			}

			ct512x4Targets = ct512x4Targets[:0]
			for l := 0; l < 4; l++ {
				ct512x4Targets = append(ct512x4Targets, bytesToNonZeroWords(k512x4[l][:], out512x4[l][:], t512x4[l][:])...)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				*dec512x4 = TEM2Decrypt512x4(k512x4, t512x4, out512x4)
			}, res); w == 0 {
				t.Fatalf("[%s] TEM2Decrypt512x4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, ct512x4Targets); found {
				t.Fatalf("[%s] TEM2Decrypt512x4 leaked key/ct/tweak word %#016x at offset %d", tier, word, off)
			}

			// 6. AES-128 block and 4-block primitives
			rk := new([11]Block)
			aesKey := new(Block)
			aesIn := new(Block)
			aesOut := new(Block)
			for i := range aesKey {
				aesKey[i] = byte(0x61 + i*7)
				aesIn[i] = byte(0xC3 + i*11)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				ExpandKey128(aesKey, rk)
			}, res); w == 0 {
				t.Fatalf("[%s] ExpandKey128: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey[:])); found {
				t.Fatalf("[%s] ExpandKey128 leaked key word %#016x at offset %d", tier, word, off)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				AES128EncryptBlock(rk, aesOut, aesIn)
			}, res); w == 0 {
				t.Fatalf("[%s] AES128EncryptBlock: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey[:], aesIn[:], aesOut[:])); found {
				t.Fatalf("[%s] AES128EncryptBlock leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			aesIn4 := new(Block4)
			aesOut4 := new(Block4)
			aesKey4 := new(Key4)
			for i := range aesIn4 {
				aesIn4[i] = byte(0xD1 + i*3)
				aesKey4[i] = byte(0xE3 + i*5)
			}
			if w := captureAreionFrameAndRegResidue(func() {
				AES128Encrypt4Blocks(rk, aesOut4, aesIn4)
			}, res); w == 0 {
				t.Fatalf("[%s] AES128Encrypt4Blocks: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey[:], aesIn4[:], aesOut4[:])); found {
				t.Fatalf("[%s] AES128Encrypt4Blocks leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			*aesOut = *aesIn
			if w := captureAreionFrameAndRegResidue(func() {
				RoundHW(aesOut, aesKey)
			}, res); w == 0 {
				t.Fatalf("[%s] RoundHW: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey[:], aesIn[:], aesOut[:])); found {
				t.Fatalf("[%s] RoundHW leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			*aesOut = *aesIn
			if w := captureAreionFrameAndRegResidue(func() {
				FinalRoundHW(aesOut, aesKey)
			}, res); w == 0 {
				t.Fatalf("[%s] FinalRoundHW: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey[:], aesIn[:], aesOut[:])); found {
				t.Fatalf("[%s] FinalRoundHW leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			*aesOut4 = *aesIn4
			if w := captureAreionFrameAndRegResidue(func() {
				Round4HW(aesOut4, aesKey4)
			}, res); w == 0 {
				t.Fatalf("[%s] Round4HW: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey4[:], aesIn4[:], aesOut4[:])); found {
				t.Fatalf("[%s] Round4HW leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			*aesOut4 = *aesIn4
			if w := captureAreionFrameAndRegResidue(func() {
				FinalRound4HW(aesOut4, aesKey4)
			}, res); w == 0 {
				t.Fatalf("[%s] FinalRound4HW: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey4[:], aesIn4[:], aesOut4[:])); found {
				t.Fatalf("[%s] FinalRound4HW leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			*aesOut = *aesIn
			if w := captureAreionFrameAndRegResidue(func() {
				Round(aesOut, aesKey)
			}, res); w == 0 {
				t.Fatalf("[%s] Round: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey[:], aesIn[:], aesOut[:])); found {
				t.Fatalf("[%s] Round leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			*aesOut = *aesIn
			if w := captureAreionFrameAndRegResidue(func() {
				FinalRound(aesOut, aesKey)
			}, res); w == 0 {
				t.Fatalf("[%s] FinalRound: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey[:], aesIn[:], aesOut[:])); found {
				t.Fatalf("[%s] FinalRound leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			*aesOut = *aesIn
			if w := captureAreionFrameAndRegResidue(func() {
				roundNoKey(aesOut)
			}, res); w == 0 {
				t.Fatalf("[%s] roundNoKey: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesIn[:], aesOut[:])); found {
				t.Fatalf("[%s] roundNoKey leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			*aesOut = *aesIn
			if w := captureAreionFrameAndRegResidue(func() {
				finalRoundNoKey(aesOut)
			}, res); w == 0 {
				t.Fatalf("[%s] finalRoundNoKey: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesIn[:], aesOut[:])); found {
				t.Fatalf("[%s] finalRoundNoKey leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			*aesOut4 = *aesIn4
			if w := captureAreionFrameAndRegResidue(func() {
				aesRound4Software(aesOut4, aesKey4)
			}, res); w == 0 {
				t.Fatalf("[%s] aesRound4Software: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey4[:], aesIn4[:], aesOut4[:])); found {
				t.Fatalf("[%s] aesRound4Software leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			*aesOut4 = *aesIn4
			if w := captureAreionFrameAndRegResidue(func() {
				aesFinalRound4Software(aesOut4, aesKey4)
			}, res); w == 0 {
				t.Fatalf("[%s] aesFinalRound4Software: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey4[:], aesIn4[:], aesOut4[:])); found {
				t.Fatalf("[%s] aesFinalRound4Software leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				XorBlock(aesOut, aesIn, aesKey)
			}, res); w == 0 {
				t.Fatalf("[%s] XorBlock: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey[:], aesIn[:], aesOut[:])); found {
				t.Fatalf("[%s] XorBlock leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				XorBlock4(aesOut4, aesIn4, (*Block4)(aesKey4))
			}, res); w == 0 {
				t.Fatalf("[%s] XorBlock4: probe missed stack window", tier)
			}
			if word, off, found := scanFn(res, bytesToNonZeroWords(aesKey4[:], aesIn4[:], aesOut4[:])); found {
				t.Fatalf("[%s] XorBlock4 leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			// 7. Fused Drucker-Gueron Rijndael-256 block and 4-block primitives
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
				rijndael256EncryptBlockHW(r256RK, r256Out, r256In)
			}, res); w == 0 {
				t.Fatalf("[%s] rijndael256EncryptBlockHW: probe missed stack window", tier)
			}
			r256Targets1 := append(append([]uint64{}, r256RKTargets...), bytesToNonZeroWords(r256In[:], r256Out[:])...)
			if word, off, found := scanFn(res, r256Targets1); found {
				t.Fatalf("[%s] rijndael256EncryptBlockHW leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			if w := captureAreionFrameAndRegResidue(func() {
				rijndael256Encrypt4BlocksHW(r256RK, r256Out4, r256In4)
			}, res); w == 0 {
				t.Fatalf("[%s] rijndael256Encrypt4BlocksHW: probe missed stack window", tier)
			}
			r256Targets4 := append([]uint64{}, r256RKTargets...)
			for l := 0; l < 4; l++ {
				r256Targets4 = append(r256Targets4, bytesToNonZeroWords(r256In4[l][:], r256Out4[l][:])...)
			}
			if word, off, found := scanFn(res, r256Targets4); found {
				t.Fatalf("[%s] rijndael256Encrypt4BlocksHW leaked word %#016x at offset %d (window=%d)", tier, word, off, areionResidueWindow)
			}

			// 8. Vistrutah-256 and Vistrutah-512 block and 4-block primitives
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
			vDec256 := new([32]byte)
			vDec256x4 := new([4][32]byte)
			vDec512 := new([64]byte)
			vDec512x4 := new([4][64]byte)
			for _, r := range []int{10, 14} {
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah256EncryptBlockHW(vOut256, vIn256, vKey256, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah256EncryptBlockHW(%d): probe missed stack window", tier, r)
				}
				if word, off, found := scanFn(res, bytesToNonZeroWords(vKey256[:], vIn256[:], vOut256[:])); found {
					t.Fatalf("[%s] vistrutah256EncryptBlockHW(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah256DecryptBlockSoft(vDec256, vOut256, vKey256, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah256DecryptBlockSoft(%d): probe missed stack window", tier, r)
				}
				if word, off, found := scanFn(res, bytesToNonZeroWords(vKey256[:], vOut256[:], vDec256[:])); found {
					t.Fatalf("[%s] vistrutah256DecryptBlockSoft(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah256Encrypt4BlocksHW(vOut256x4, vIn256x4, vKey256, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah256Encrypt4BlocksHW(%d): probe missed stack window", tier, r)
				}
				vTargets := bytesToNonZeroWords(vKey256[:])
				for l := 0; l < 4; l++ {
					vTargets = append(vTargets, bytesToNonZeroWords(vIn256x4[l][:], vOut256x4[l][:])...)
				}
				if word, off, found := scanFn(res, vTargets); found {
					t.Fatalf("[%s] vistrutah256Encrypt4BlocksHW(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah256Decrypt4BlocksSoft(vDec256x4, vOut256x4, vKey256, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah256Decrypt4BlocksSoft(%d): probe missed stack window", tier, r)
				}
				vDecTargets := bytesToNonZeroWords(vKey256[:])
				for l := 0; l < 4; l++ {
					vDecTargets = append(vDecTargets, bytesToNonZeroWords(vOut256x4[l][:], vDec256x4[l][:])...)
				}
				if word, off, found := scanFn(res, vDecTargets); found {
					t.Fatalf("[%s] vistrutah256Decrypt4BlocksSoft(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
			}
			for _, r := range []int{10, 12, 14, 18} {
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah512EncryptBlock256HW(vOut512, vIn512, vKey256, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah512EncryptBlock256HW(%d): probe missed stack window", tier, r)
				}
				if word, off, found := scanFn(res, bytesToNonZeroWords(vKey256[:], vIn512[:], vOut512[:])); found {
					t.Fatalf("[%s] vistrutah512EncryptBlock256HW(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah512DecryptBlock256Soft(vDec512, vOut512, vKey256, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah512DecryptBlock256Soft(%d): probe missed stack window", tier, r)
				}
				if word, off, found := scanFn(res, bytesToNonZeroWords(vKey256[:], vOut512[:], vDec512[:])); found {
					t.Fatalf("[%s] vistrutah512DecryptBlock256Soft(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah512EncryptBlock512HW(vOut512, vIn512, vKey512, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah512EncryptBlock512HW(%d): probe missed stack window", tier, r)
				}
				if word, off, found := scanFn(res, bytesToNonZeroWords(vKey512[:], vIn512[:], vOut512[:])); found {
					t.Fatalf("[%s] vistrutah512EncryptBlock512HW(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah512DecryptBlock512Soft(vDec512, vOut512, vKey512, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah512DecryptBlock512Soft(%d): probe missed stack window", tier, r)
				}
				if word, off, found := scanFn(res, bytesToNonZeroWords(vKey512[:], vOut512[:], vDec512[:])); found {
					t.Fatalf("[%s] vistrutah512DecryptBlock512Soft(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah512Encrypt4Blocks256HW(vOut512x4, vIn512x4, vKey256, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah512Encrypt4Blocks256HW(%d): probe missed stack window", tier, r)
				}
				vTargets256 := bytesToNonZeroWords(vKey256[:])
				for l := 0; l < 4; l++ {
					vTargets256 = append(vTargets256, bytesToNonZeroWords(vIn512x4[l][:], vOut512x4[l][:])...)
				}
				if word, off, found := scanFn(res, vTargets256); found {
					t.Fatalf("[%s] vistrutah512Encrypt4Blocks256HW(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah512Decrypt4Blocks256Soft(vDec512x4, vOut512x4, vKey256, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah512Decrypt4Blocks256Soft(%d): probe missed stack window", tier, r)
				}
				vDecTargets256 := bytesToNonZeroWords(vKey256[:])
				for l := 0; l < 4; l++ {
					vDecTargets256 = append(vDecTargets256, bytesToNonZeroWords(vOut512x4[l][:], vDec512x4[l][:])...)
				}
				if word, off, found := scanFn(res, vDecTargets256); found {
					t.Fatalf("[%s] vistrutah512Decrypt4Blocks256Soft(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah512Encrypt4Blocks512HW(vOut512x4, vIn512x4, vKey512, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah512Encrypt4Blocks512HW(%d): probe missed stack window", tier, r)
				}
				vTargets512 := bytesToNonZeroWords(vKey512[:])
				for l := 0; l < 4; l++ {
					vTargets512 = append(vTargets512, bytesToNonZeroWords(vIn512x4[l][:], vOut512x4[l][:])...)
				}
				if word, off, found := scanFn(res, vTargets512); found {
					t.Fatalf("[%s] vistrutah512Encrypt4Blocks512HW(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
				if w := captureAreionFrameAndRegResidue(func() {
					vistrutah512Decrypt4Blocks512Soft(vDec512x4, vOut512x4, vKey512, r)
				}, res); w == 0 {
					t.Fatalf("[%s] vistrutah512Decrypt4Blocks512Soft(%d): probe missed stack window", tier, r)
				}
				vDecTargets512 := bytesToNonZeroWords(vKey512[:])
				for l := 0; l < 4; l++ {
					vDecTargets512 = append(vDecTargets512, bytesToNonZeroWords(vOut512x4[l][:], vDec512x4[l][:])...)
				}
				if word, off, found := scanFn(res, vDecTargets512); found {
					t.Fatalf("[%s] vistrutah512Decrypt4Blocks512Soft(%d) leaked word %#016x at offset %d", tier, r, word, off)
				}
			}

			// 9. ASURA 256-bit tweakable block cipher primitives (*HW, *Soft, and exported APIs)
			aRTK := new([13][32]byte)
			aRK := new([13][32]byte)
			aKey := new([32]byte)
			aTweak := new([16]byte)
			aTweaks4 := new([4][16]byte)
			aIn := new([32]byte)
			aOut := new([32]byte)
			aDec := new([32]byte)
			aIn4 := new([4][32]byte)
			aOut4 := new([4][32]byte)
			aDec4 := new([4][32]byte)
			for i := 0; i < 32; i++ {
				aKey[i] = byte(0x37 + i*7)
				aIn[i] = byte(0x53 + i*11)
			}
			for i := 0; i < 16; i++ {
				aTweak[i] = byte(0x9b + i*13)
			}
			for l := 0; l < 4; l++ {
				for i := 0; i < 16; i++ {
					aTweaks4[l][i] = byte(0x9b + l*31 + i*13)
				}
				for i := 0; i < 32; i++ {
					aIn4[l][i] = byte(0x6d + l*29 + i*5)
				}
			}

			for _, expandOp := range []struct {
				name string
				fn   func(*[13][32]byte, *[32]byte, *[16]byte)
			}{
				{"asuraExpandTweakeyHW", asuraExpandTweakeyHW},
				{"asuraExpandTweakeySoft", asuraExpandTweakeySoft},
				{"AsuraExpandTweakey", AsuraExpandTweakey},
			} {
				if w := captureAreionFrameAndRegResidue(func() {
					expandOp.fn(aRTK, aKey, aTweak)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, expandOp.name)
				}
				aExpandTargets := bytesToNonZeroWords(aKey[:], aTweak[:])
				for r := 0; r < 13; r++ {
					aExpandTargets = append(aExpandTargets, bytesToNonZeroWords(aRTK[r][:])...)
				}
				if word, off, found := scanFn(res, aExpandTargets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, expandOp.name, word, off)
				}
			}

			for _, expandKeyOp := range []struct {
				name string
				fn   func(*[13][32]byte, *[32]byte)
			}{
				{"asuraExpandKeyHW", asuraExpandKeyHW},
				{"asuraExpandKeySoft", asuraExpandKeySoft},
				{"AsuraExpandKey", AsuraExpandKey},
			} {
				if w := captureAreionFrameAndRegResidue(func() {
					expandKeyOp.fn(aRK, aKey)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, expandKeyOp.name)
				}
				aExpandKeyTargets := bytesToNonZeroWords(aKey[:])
				for r := 0; r < 13; r++ {
					aExpandKeyTargets = append(aExpandKeyTargets, bytesToNonZeroWords(aRK[r][:])...)
				}
				if word, off, found := scanFn(res, aExpandKeyTargets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, expandKeyOp.name, word, off)
				}
			}

			var aRTKTargets, aRKTargets []uint64
			for r := 0; r < 13; r++ {
				aRTKTargets = append(aRTKTargets, bytesToNonZeroWords(aRTK[r][:])...)
				aRKTargets = append(aRKTargets, bytesToNonZeroWords(aRK[r][:])...)
			}

			for _, blockOp := range []struct {
				name string
				fn   func(*[13][32]byte, *[32]byte, *[32]byte)
				in   *[32]byte
				out  *[32]byte
			}{
				{"asuraEncryptBlockHW", asuraEncryptBlockHW, aIn, aOut},
				{"asuraEncryptBlockSoft", asuraEncryptBlockSoft, aIn, aOut},
				{"AsuraEncrypt", AsuraEncrypt, aIn, aOut},
				{"asuraDecryptBlockHW", asuraDecryptBlockHW, aOut, aDec},
				{"asuraDecryptBlockSoft", asuraDecryptBlockSoft, aOut, aDec},
				{"AsuraDecrypt", AsuraDecrypt, aOut, aDec},
			} {
				if w := captureAreionFrameAndRegResidue(func() {
					blockOp.fn(aRTK, blockOp.out, blockOp.in)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, blockOp.name)
				}
				targets := append(append([]uint64{}, aRTKTargets...), bytesToNonZeroWords(blockOp.in[:], blockOp.out[:])...)
				if word, off, found := scanFn(res, targets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, blockOp.name, word, off)
				}
			}

			for _, block4Op := range []struct {
				name string
				fn   func(*[13][32]byte, *[4][32]byte, *[4][32]byte)
				in   *[4][32]byte
				out  *[4][32]byte
			}{
				{"asuraEncrypt4BlocksHW", asuraEncrypt4BlocksHW, aIn4, aOut4},
				{"asuraEncrypt4BlocksSoft", asuraEncrypt4BlocksSoft, aIn4, aOut4},
				{"AsuraEncryptx4", AsuraEncryptx4, aIn4, aOut4},
				{"asuraDecrypt4BlocksHW", asuraDecrypt4BlocksHW, aOut4, aDec4},
				{"asuraDecrypt4BlocksSoft", asuraDecrypt4BlocksSoft, aOut4, aDec4},
				{"AsuraDecryptx4", AsuraDecryptx4, aOut4, aDec4},
			} {
				if w := captureAreionFrameAndRegResidue(func() {
					block4Op.fn(aRTK, block4Op.out, block4Op.in)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, block4Op.name)
				}
				targets := append([]uint64{}, aRTKTargets...)
				for l := 0; l < 4; l++ {
					targets = append(targets, bytesToNonZeroWords(block4Op.in[l][:], block4Op.out[l][:])...)
				}
				if word, off, found := scanFn(res, targets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, block4Op.name, word, off)
				}
			}

			for _, otfOp := range []struct {
				name string
				fn   func(*[32]byte, *[32]byte, *[32]byte, *[16]byte)
				in   *[32]byte
				out  *[32]byte
			}{
				{"asuraEncryptBlockOTFHW", asuraEncryptBlockOTFHW, aIn, aOut},
				{"asuraEncryptBlockOTFSoft", asuraEncryptBlockOTFSoft, aIn, aOut},
				{"AsuraEncryptOTF", AsuraEncryptOTF, aIn, aOut},
				{"asuraDecryptBlockOTFHW", asuraDecryptBlockOTFHW, aOut, aDec},
				{"asuraDecryptBlockOTFSoft", asuraDecryptBlockOTFSoft, aOut, aDec},
				{"AsuraDecryptOTF", AsuraDecryptOTF, aOut, aDec},
			} {
				if w := captureAreionFrameAndRegResidue(func() {
					otfOp.fn(otfOp.out, otfOp.in, aKey, aTweak)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, otfOp.name)
				}
				targets := append(append([]uint64{}, aRTKTargets...), bytesToNonZeroWords(aKey[:], aTweak[:], otfOp.in[:], otfOp.out[:])...)
				if word, off, found := scanFn(res, targets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, otfOp.name, word, off)
				}
			}

			for _, otf4Op := range []struct {
				name string
				fn   func(*[4][32]byte, *[4][32]byte, *[32]byte, *[4][16]byte)
				in   *[4][32]byte
				out  *[4][32]byte
			}{
				{"asuraEncrypt4BlocksOTFHW", asuraEncrypt4BlocksOTFHW, aIn4, aOut4},
				{"asuraEncrypt4BlocksOTFSoft", asuraEncrypt4BlocksOTFSoft, aIn4, aOut4},
				{"AsuraEncryptx4OTF", AsuraEncryptx4OTF, aIn4, aOut4},
				{"asuraDecrypt4BlocksOTFHW", asuraDecrypt4BlocksOTFHW, aOut4, aDec4},
				{"asuraDecrypt4BlocksOTFSoft", asuraDecrypt4BlocksOTFSoft, aOut4, aDec4},
				{"AsuraDecryptx4OTF", AsuraDecryptx4OTF, aOut4, aDec4},
			} {
				if w := captureAreionFrameAndRegResidue(func() {
					otf4Op.fn(otf4Op.out, otf4Op.in, aKey, aTweaks4)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, otf4Op.name)
				}
				targets := append(append([]uint64{}, aRTKTargets...), bytesToNonZeroWords(aKey[:])...)
				for l := 0; l < 4; l++ {
					targets = append(targets, bytesToNonZeroWords(aTweaks4[l][:], otf4Op.in[l][:], otf4Op.out[l][:])...)
				}
				if word, off, found := scanFn(res, targets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, otf4Op.name, word, off)
				}
			}

			for _, rkOp := range []struct {
				name string
				fn   func(*[13][32]byte, *[32]byte, *[32]byte, *[16]byte)
				in   *[32]byte
				out  *[32]byte
			}{
				{"asuraEncryptBlockRKHW", asuraEncryptBlockRKHW, aIn, aOut},
				{"asuraEncryptBlockRKSoft", asuraEncryptBlockRKSoft, aIn, aOut},
				{"AsuraEncryptRK", AsuraEncryptRK, aIn, aOut},
				{"asuraDecryptBlockRKHW", asuraDecryptBlockRKHW, aOut, aDec},
				{"asuraDecryptBlockRKSoft", asuraDecryptBlockRKSoft, aOut, aDec},
				{"AsuraDecryptRK", AsuraDecryptRK, aOut, aDec},
			} {
				if w := captureAreionFrameAndRegResidue(func() {
					rkOp.fn(aRK, rkOp.out, rkOp.in, aTweak)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, rkOp.name)
				}
				targets := append(append([]uint64{}, aRKTargets...), aRTKTargets...)
				targets = append(targets, bytesToNonZeroWords(aTweak[:], rkOp.in[:], rkOp.out[:])...)
				if word, off, found := scanFn(res, targets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, rkOp.name, word, off)
				}
			}

			for _, rk4Op := range []struct {
				name string
				fn   func(*[13][32]byte, *[4][32]byte, *[4][32]byte, *[4][16]byte)
				in   *[4][32]byte
				out  *[4][32]byte
			}{
				{"asuraEncrypt4BlocksRKHW", asuraEncrypt4BlocksRKHW, aIn4, aOut4},
				{"asuraEncrypt4BlocksRKSoft", asuraEncrypt4BlocksRKSoft, aIn4, aOut4},
				{"AsuraEncryptx4RK", AsuraEncryptx4RK, aIn4, aOut4},
				{"asuraDecrypt4BlocksRKHW", asuraDecrypt4BlocksRKHW, aOut4, aDec4},
				{"asuraDecrypt4BlocksRKSoft", asuraDecrypt4BlocksRKSoft, aOut4, aDec4},
				{"AsuraDecryptx4RK", AsuraDecryptx4RK, aOut4, aDec4},
			} {
				if w := captureAreionFrameAndRegResidue(func() {
					rk4Op.fn(aRK, rk4Op.out, rk4Op.in, aTweaks4)
				}, res); w == 0 {
					t.Fatalf("[%s] %s: probe missed stack window", tier, rk4Op.name)
				}
				targets := append(append([]uint64{}, aRKTargets...), aRTKTargets...)
				for l := 0; l < 4; l++ {
					targets = append(targets, bytesToNonZeroWords(aTweaks4[l][:], rk4Op.in[l][:], rk4Op.out[l][:])...)
				}
				if word, off, found := scanFn(res, targets); found {
					t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, rk4Op.name, word, off)
				}
			}
		})
	}
}

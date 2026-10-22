//go:build (amd64 || arm64) && !purego

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
			w := binary.LittleEndian.Uint64(b[i : i+8])
			if w != 0 {
				out = append(out, w)
			}
		}
	}
	return out
}

func scanForAreionWords(window *[areionTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i, w := range window {
		if w == 0 || (i < areionStackWords && w == areionResidueSentinel) {
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

func scanForAreionWordsInStack(window *[areionTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i := 0; i < areionStackWords; i++ {
		w := window[i]
		if w == 0 || w == areionResidueSentinel {
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
		})
	}
}

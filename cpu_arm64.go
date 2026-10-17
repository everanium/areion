//go:build arm64 && !purego

package areion

import "golang.org/x/sys/cpu"

func probeCPU() (aesni, vex, armCrypto, vaesAVX2, avx512 bool) {
	armCrypto = cpu.ARM64.HasAES
	return
}

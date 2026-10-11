//go:build (!amd64 && !arm64) || purego

package areion

func probeCPU() (aesni, armCrypto, vaesAVX2, avx512 bool) {
	return false, false, false, false
}

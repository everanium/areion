//go:build (!amd64 && !arm64) || purego

package areion

func rijndael256EncryptBlockHW(rk *[15][32]byte, dst, src *[32]byte) {
	rijndael256EncryptBlockSoftware(rk, dst, src)
}

func rijndael256Encrypt4BlocksHW(rk *[15][32]byte, dst, src *[4][32]byte) {
	rijndael256Encrypt4BlocksSoftware(rk, dst, src)
}

//go:build amd64 && !purego

package areion

//go:noescape
func rijndael256EncryptBlockAsm(rk *[15][32]byte, dst, src *[32]byte)

//go:noescape
func rijndael256EncryptBlockVexAsm(rk *[15][32]byte, dst, src *[32]byte)

//go:noescape
func rijndael256Encrypt4BlocksZmmAsm(rk *[15][32]byte, dst, src *[4][32]byte)

//go:noescape
func rijndael256Encrypt4BlocksYmmAsm(rk *[15][32]byte, dst, src *[4][32]byte)

//go:noescape
func rijndael256Encrypt4BlocksVexAsm(rk *[15][32]byte, dst, src *[4][32]byte)

//go:noescape
func rijndael256Encrypt4BlocksAesNiAsm(rk *[15][32]byte, dst, src *[4][32]byte)

func rijndael256EncryptBlockHW(rk *[15][32]byte, dst, src *[32]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		rijndael256EncryptBlockVexAsm(rk, dst, src)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		rijndael256EncryptBlockAsm(rk, dst, src)
		return
	}
	rijndael256EncryptBlockSoftware(rk, dst, src)
}

func rijndael256Encrypt4BlocksHW(rk *[15][32]byte, dst, src *[4][32]byte) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		rijndael256Encrypt4BlocksZmmAsm(rk, dst, src)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		rijndael256Encrypt4BlocksYmmAsm(rk, dst, src)
	case hasVEX && tier >= TierVEX:
		rijndael256Encrypt4BlocksVexAsm(rk, dst, src)
	case hasAESNI && tier >= TierAESNI:
		rijndael256Encrypt4BlocksAesNiAsm(rk, dst, src)
	default:
		rijndael256Encrypt4BlocksSoftware(rk, dst, src)
	}
}

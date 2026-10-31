//go:build arm64 && !purego

package areion

//go:noescape
func rijndael256EncryptBlockAsm(rk *[15][32]byte, dst, src *[32]byte)

//go:noescape
func rijndael256DecryptBlockAsm(drk *[15][32]byte, dst, src *[32]byte)

//go:noescape
func rijndael256Encrypt4BlocksAsm(rk *[15][32]byte, dst, src *[4][32]byte)

//go:noescape
func rijndael256Decrypt4BlocksAsm(drk *[15][32]byte, dst, src *[4][32]byte)

func rijndael256EncryptBlockHW(rk *[15][32]byte, dst, src *[32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		rijndael256EncryptBlockAsm(rk, dst, src)
		return
	}
	rijndael256EncryptBlockSoftware(rk, dst, src)
}

func rijndael256DecryptBlockHW(drk *[15][32]byte, dst, src *[32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		rijndael256DecryptBlockAsm(drk, dst, src)
		return
	}
	rijndael256DecryptBlockSoftware(drk, dst, src)
}

func rijndael256Encrypt4BlocksHW(rk *[15][32]byte, dst, src *[4][32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		rijndael256Encrypt4BlocksAsm(rk, dst, src)
		return
	}
	rijndael256Encrypt4BlocksSoftware(rk, dst, src)
}

func rijndael256Decrypt4BlocksHW(drk *[15][32]byte, dst, src *[4][32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		rijndael256Decrypt4BlocksAsm(drk, dst, src)
		return
	}
	rijndael256Decrypt4BlocksSoftware(drk, dst, src)
}

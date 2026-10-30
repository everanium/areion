//go:build arm64 && !purego

package areion

//go:noescape
func asuraExpandTweakeyAsm(rtk *[13][32]byte, key *[32]byte, tweak *[16]byte)

//go:noescape
func asuraEncryptBlockAsm(rtk *[13][32]byte, dst, src *[32]byte)

//go:noescape
func asuraDecryptBlockAsm(rtk *[13][32]byte, dst, src *[32]byte)

//go:noescape
func asuraEncrypt4BlocksAsm(rtk *[13][32]byte, dst, src *[4][32]byte)

//go:noescape
func asuraDecrypt4BlocksAsm(rtk *[13][32]byte, dst, src *[4][32]byte)

//go:noescape
func asuraEncryptBlockOTFAsm(dst, src, key *[32]byte, tweak *[16]byte)

//go:noescape
func asuraDecryptBlockOTFAsm(dst, src, key *[32]byte, tweak *[16]byte)

//go:noescape
func asuraEncrypt4BlocksOTFAsm(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraDecrypt4BlocksOTFAsm(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraExpandKeyAsm(rk *[13][32]byte, key *[32]byte)

//go:noescape
func asuraEncryptBlockRKAsm(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte)

//go:noescape
func asuraDecryptBlockRKAsm(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte)

//go:noescape
func asuraEncrypt4BlocksRKAsm(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraDecrypt4BlocksRKAsm(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte)

func asuraExpandTweakeyHW(rtk *[13][32]byte, key *[32]byte, tweak *[16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraExpandTweakeyAsm(rtk, key, tweak)
		return
	}
	asuraExpandTweakeySoft(rtk, key, tweak)
}

func asuraEncryptBlockHW(rtk *[13][32]byte, dst, src *[32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraEncryptBlockAsm(rtk, dst, src)
		return
	}
	asuraEncryptBlockSoft(rtk, dst, src)
}

func asuraDecryptBlockHW(rtk *[13][32]byte, dst, src *[32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraDecryptBlockAsm(rtk, dst, src)
		return
	}
	asuraDecryptBlockSoft(rtk, dst, src)
}

func asuraEncrypt4BlocksHW(rtk *[13][32]byte, dst, src *[4][32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraEncrypt4BlocksAsm(rtk, dst, src)
		return
	}
	asuraEncrypt4BlocksSoft(rtk, dst, src)
}

func asuraDecrypt4BlocksHW(rtk *[13][32]byte, dst, src *[4][32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraDecrypt4BlocksAsm(rtk, dst, src)
		return
	}
	asuraDecrypt4BlocksSoft(rtk, dst, src)
}

func asuraEncryptBlockOTFHW(dst, src, key *[32]byte, tweak *[16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraEncryptBlockOTFAsm(dst, src, key, tweak)
		return
	}
	asuraEncryptBlockOTFSoft(dst, src, key, tweak)
}

func asuraDecryptBlockOTFHW(dst, src, key *[32]byte, tweak *[16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraDecryptBlockOTFAsm(dst, src, key, tweak)
		return
	}
	asuraDecryptBlockOTFSoft(dst, src, key, tweak)
}

func asuraEncrypt4BlocksOTFHW(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraEncrypt4BlocksOTFAsm(dst, src, key, tweaks)
		return
	}
	asuraEncrypt4BlocksOTFSoft(dst, src, key, tweaks)
}

func asuraDecrypt4BlocksOTFHW(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraDecrypt4BlocksOTFAsm(dst, src, key, tweaks)
		return
	}
	asuraDecrypt4BlocksOTFSoft(dst, src, key, tweaks)
}

func asuraExpandKeyHW(rk *[13][32]byte, key *[32]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraExpandKeyAsm(rk, key)
		return
	}
	asuraExpandKeySoft(rk, key)
}

func asuraEncryptBlockRKHW(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraEncryptBlockRKAsm(rk, dst, src, tweak)
		return
	}
	asuraEncryptBlockRKSoft(rk, dst, src, tweak)
}

func asuraDecryptBlockRKHW(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraDecryptBlockRKAsm(rk, dst, src, tweak)
		return
	}
	asuraDecryptBlockRKSoft(rk, dst, src, tweak)
}

func asuraEncrypt4BlocksRKHW(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraEncrypt4BlocksRKAsm(rk, dst, src, tweaks)
		return
	}
	asuraEncrypt4BlocksRKSoft(rk, dst, src, tweaks)
}

func asuraDecrypt4BlocksRKHW(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		asuraDecrypt4BlocksRKAsm(rk, dst, src, tweaks)
		return
	}
	asuraDecrypt4BlocksRKSoft(rk, dst, src, tweaks)
}

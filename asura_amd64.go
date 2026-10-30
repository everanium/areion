//go:build amd64 && !purego

package areion

//go:noescape
func asuraExpandTweakeyAsm(rtk *[13][32]byte, key *[32]byte, tweak *[16]byte)

//go:noescape
func asuraExpandTweakeyVexAsm(rtk *[13][32]byte, key *[32]byte, tweak *[16]byte)

//go:noescape
func asuraEncryptBlockAsm(rtk *[13][32]byte, dst, src *[32]byte)

//go:noescape
func asuraEncryptBlockVexAsm(rtk *[13][32]byte, dst, src *[32]byte)

//go:noescape
func asuraDecryptBlockAsm(rtk *[13][32]byte, dst, src *[32]byte)

//go:noescape
func asuraDecryptBlockVexAsm(rtk *[13][32]byte, dst, src *[32]byte)

//go:noescape
func asuraEncrypt4BlocksAsm(rtk *[13][32]byte, dst, src *[4][32]byte)

//go:noescape
func asuraEncrypt4BlocksVexAsm(rtk *[13][32]byte, dst, src *[4][32]byte)

//go:noescape
func asuraEncrypt4BlocksVAES256Asm(rtk *[13][32]byte, dst, src *[4][32]byte)

//go:noescape
func asuraEncrypt4BlocksVAES512Asm(rtk *[13][32]byte, dst, src *[4][32]byte)

//go:noescape
func asuraDecrypt4BlocksAsm(rtk *[13][32]byte, dst, src *[4][32]byte)

//go:noescape
func asuraDecrypt4BlocksVexAsm(rtk *[13][32]byte, dst, src *[4][32]byte)

//go:noescape
func asuraDecrypt4BlocksVAES256Asm(rtk *[13][32]byte, dst, src *[4][32]byte)

//go:noescape
func asuraDecrypt4BlocksVAES512Asm(rtk *[13][32]byte, dst, src *[4][32]byte)

//go:noescape
func asuraEncryptBlockOTFAsm(dst, src, key *[32]byte, tweak *[16]byte)

//go:noescape
func asuraEncryptBlockOTFVexAsm(dst, src, key *[32]byte, tweak *[16]byte)

//go:noescape
func asuraDecryptBlockOTFAsm(dst, src, key *[32]byte, tweak *[16]byte)

//go:noescape
func asuraDecryptBlockOTFVexAsm(dst, src, key *[32]byte, tweak *[16]byte)

//go:noescape
func asuraEncrypt4BlocksOTFAsm(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraEncrypt4BlocksOTFVexAsm(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraEncrypt4BlocksOTFVAES256Asm(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraEncrypt4BlocksOTFVAES512Asm(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraDecrypt4BlocksOTFAsm(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraDecrypt4BlocksOTFVexAsm(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraDecrypt4BlocksOTFVAES256Asm(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraDecrypt4BlocksOTFVAES512Asm(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraExpandKeyAESNIAsm(rk *[13][32]byte, key *[32]byte)

//go:noescape
func asuraExpandKeyVexAsm(rk *[13][32]byte, key *[32]byte)

//go:noescape
func asuraEncryptBlockRKAESNIAsm(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte)

//go:noescape
func asuraEncryptBlockRKVexAsm(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte)

//go:noescape
func asuraDecryptBlockRKAESNIAsm(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte)

//go:noescape
func asuraDecryptBlockRKVexAsm(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte)

//go:noescape
func asuraEncrypt4BlocksRKAESNIAsm(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraEncrypt4BlocksRKVexAsm(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraEncrypt4BlocksRKVAES256Asm(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraEncrypt4BlocksRKVAES512Asm(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraDecrypt4BlocksRKAESNIAsm(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraDecrypt4BlocksRKVexAsm(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraDecrypt4BlocksRKVAES256Asm(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte)

//go:noescape
func asuraDecrypt4BlocksRKVAES512Asm(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte)

func asuraExpandTweakeyHW(rtk *[13][32]byte, key *[32]byte, tweak *[16]byte) {
	tier := TierCode()
	switch {
	case hasVEX && tier >= TierVEX:
		asuraExpandTweakeyVexAsm(rtk, key, tweak)
	case hasAESNI && tier >= TierAESNI:
		asuraExpandTweakeyAsm(rtk, key, tweak)
	default:
		asuraExpandTweakeySoft(rtk, key, tweak)
	}
}

func asuraEncryptBlockHW(rtk *[13][32]byte, dst, src *[32]byte) {
	tier := TierCode()
	switch {
	case hasVEX && tier >= TierVEX:
		asuraEncryptBlockVexAsm(rtk, dst, src)
	case hasAESNI && tier >= TierAESNI:
		asuraEncryptBlockAsm(rtk, dst, src)
	default:
		asuraEncryptBlockSoft(rtk, dst, src)
	}
}

func asuraDecryptBlockHW(rtk *[13][32]byte, dst, src *[32]byte) {
	tier := TierCode()
	switch {
	case hasVEX && tier >= TierVEX:
		asuraDecryptBlockVexAsm(rtk, dst, src)
	case hasAESNI && tier >= TierAESNI:
		asuraDecryptBlockAsm(rtk, dst, src)
	default:
		asuraDecryptBlockSoft(rtk, dst, src)
	}
}

func asuraEncrypt4BlocksHW(rtk *[13][32]byte, dst, src *[4][32]byte) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		asuraEncrypt4BlocksVAES512Asm(rtk, dst, src)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		asuraEncrypt4BlocksVAES256Asm(rtk, dst, src)
	case hasVEX && tier >= TierVEX:
		asuraEncrypt4BlocksVexAsm(rtk, dst, src)
	case hasAESNI && tier >= TierAESNI:
		asuraEncrypt4BlocksAsm(rtk, dst, src)
	default:
		asuraEncrypt4BlocksSoft(rtk, dst, src)
	}
}

func asuraDecrypt4BlocksHW(rtk *[13][32]byte, dst, src *[4][32]byte) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		asuraDecrypt4BlocksVAES512Asm(rtk, dst, src)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		asuraDecrypt4BlocksVAES256Asm(rtk, dst, src)
	case hasVEX && tier >= TierVEX:
		asuraDecrypt4BlocksVexAsm(rtk, dst, src)
	case hasAESNI && tier >= TierAESNI:
		asuraDecrypt4BlocksAsm(rtk, dst, src)
	default:
		asuraDecrypt4BlocksSoft(rtk, dst, src)
	}
}

func asuraEncryptBlockOTFHW(dst, src, key *[32]byte, tweak *[16]byte) {
	tier := TierCode()
	switch {
	case hasVEX && tier >= TierVEX:
		asuraEncryptBlockOTFVexAsm(dst, src, key, tweak)
	case hasAESNI && tier >= TierAESNI:
		asuraEncryptBlockOTFAsm(dst, src, key, tweak)
	default:
		asuraEncryptBlockOTFSoft(dst, src, key, tweak)
	}
}

func asuraDecryptBlockOTFHW(dst, src, key *[32]byte, tweak *[16]byte) {
	tier := TierCode()
	switch {
	case hasVEX && tier >= TierVEX:
		asuraDecryptBlockOTFVexAsm(dst, src, key, tweak)
	case hasAESNI && tier >= TierAESNI:
		asuraDecryptBlockOTFAsm(dst, src, key, tweak)
	default:
		asuraDecryptBlockOTFSoft(dst, src, key, tweak)
	}
}

func asuraEncrypt4BlocksOTFHW(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		asuraEncrypt4BlocksOTFVAES512Asm(dst, src, key, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		asuraEncrypt4BlocksOTFVAES256Asm(dst, src, key, tweaks)
	case hasVEX && tier >= TierVEX:
		asuraEncrypt4BlocksOTFVexAsm(dst, src, key, tweaks)
	case hasAESNI && tier >= TierAESNI:
		asuraEncrypt4BlocksOTFAsm(dst, src, key, tweaks)
	default:
		asuraEncrypt4BlocksOTFSoft(dst, src, key, tweaks)
	}
}

func asuraDecrypt4BlocksOTFHW(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		asuraDecrypt4BlocksOTFVAES512Asm(dst, src, key, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		asuraDecrypt4BlocksOTFVAES256Asm(dst, src, key, tweaks)
	case hasVEX && tier >= TierVEX:
		asuraDecrypt4BlocksOTFVexAsm(dst, src, key, tweaks)
	case hasAESNI && tier >= TierAESNI:
		asuraDecrypt4BlocksOTFAsm(dst, src, key, tweaks)
	default:
		asuraDecrypt4BlocksOTFSoft(dst, src, key, tweaks)
	}
}

func asuraExpandKeyHW(rk *[13][32]byte, key *[32]byte) {
	tier := TierCode()
	switch {
	case hasVEX && tier >= TierVEX:
		asuraExpandKeyVexAsm(rk, key)
	case hasAESNI && tier >= TierAESNI:
		asuraExpandKeyAESNIAsm(rk, key)
	default:
		asuraExpandKeySoft(rk, key)
	}
}

func asuraEncryptBlockRKHW(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte) {
	tier := TierCode()
	switch {
	case hasVEX && tier >= TierVEX:
		asuraEncryptBlockRKVexAsm(rk, dst, src, tweak)
	case hasAESNI && tier >= TierAESNI:
		asuraEncryptBlockRKAESNIAsm(rk, dst, src, tweak)
	default:
		asuraEncryptBlockRKSoft(rk, dst, src, tweak)
	}
}

func asuraDecryptBlockRKHW(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte) {
	tier := TierCode()
	switch {
	case hasVEX && tier >= TierVEX:
		asuraDecryptBlockRKVexAsm(rk, dst, src, tweak)
	case hasAESNI && tier >= TierAESNI:
		asuraDecryptBlockRKAESNIAsm(rk, dst, src, tweak)
	default:
		asuraDecryptBlockRKSoft(rk, dst, src, tweak)
	}
}

func asuraEncrypt4BlocksRKHW(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		asuraEncrypt4BlocksRKVAES512Asm(rk, dst, src, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		asuraEncrypt4BlocksRKVAES256Asm(rk, dst, src, tweaks)
	case hasVEX && tier >= TierVEX:
		asuraEncrypt4BlocksRKVexAsm(rk, dst, src, tweaks)
	case hasAESNI && tier >= TierAESNI:
		asuraEncrypt4BlocksRKAESNIAsm(rk, dst, src, tweaks)
	default:
		asuraEncrypt4BlocksRKSoft(rk, dst, src, tweaks)
	}
}

func asuraDecrypt4BlocksRKHW(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		asuraDecrypt4BlocksRKVAES512Asm(rk, dst, src, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		asuraDecrypt4BlocksRKVAES256Asm(rk, dst, src, tweaks)
	case hasVEX && tier >= TierVEX:
		asuraDecrypt4BlocksRKVexAsm(rk, dst, src, tweaks)
	case hasAESNI && tier >= TierAESNI:
		asuraDecrypt4BlocksRKAESNIAsm(rk, dst, src, tweaks)
	default:
		asuraDecrypt4BlocksRKSoft(rk, dst, src, tweaks)
	}
}

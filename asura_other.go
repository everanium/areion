//go:build (!amd64 && !arm64) || purego

package areion

func asuraExpandTweakeyHW(rtk *[13][32]byte, key *[32]byte, tweak *[16]byte) {
	asuraExpandTweakeySoft(rtk, key, tweak)
}

func asuraEncryptBlockHW(rtk *[13][32]byte, dst, src *[32]byte) {
	asuraEncryptBlockSoft(rtk, dst, src)
}

func asuraDecryptBlockHW(rtk *[13][32]byte, dst, src *[32]byte) {
	asuraDecryptBlockSoft(rtk, dst, src)
}

func asuraEncrypt4BlocksHW(rtk *[13][32]byte, dst, src *[4][32]byte) {
	asuraEncrypt4BlocksSoft(rtk, dst, src)
}

func asuraDecrypt4BlocksHW(rtk *[13][32]byte, dst, src *[4][32]byte) {
	asuraDecrypt4BlocksSoft(rtk, dst, src)
}

func asuraEncryptBlockOTFHW(dst, src, key *[32]byte, tweak *[16]byte) {
	asuraEncryptBlockOTFSoft(dst, src, key, tweak)
}

func asuraDecryptBlockOTFHW(dst, src, key *[32]byte, tweak *[16]byte) {
	asuraDecryptBlockOTFSoft(dst, src, key, tweak)
}

func asuraEncrypt4BlocksOTFHW(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte) {
	asuraEncrypt4BlocksOTFSoft(dst, src, key, tweaks)
}

func asuraDecrypt4BlocksOTFHW(dst, src *[4][32]byte, key *[32]byte, tweaks *[4][16]byte) {
	asuraDecrypt4BlocksOTFSoft(dst, src, key, tweaks)
}

func asuraExpandKeyHW(rk *[13][32]byte, key *[32]byte) {
	asuraExpandKeySoft(rk, key)
}

func asuraEncryptBlockRKHW(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte) {
	asuraEncryptBlockRKSoft(rk, dst, src, tweak)
}

func asuraDecryptBlockRKHW(rk *[13][32]byte, dst, src *[32]byte, tweak *[16]byte) {
	asuraDecryptBlockRKSoft(rk, dst, src, tweak)
}

func asuraEncrypt4BlocksRKHW(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte) {
	asuraEncrypt4BlocksRKSoft(rk, dst, src, tweaks)
}

func asuraDecrypt4BlocksRKHW(rk *[13][32]byte, dst, src *[4][32]byte, tweaks *[4][16]byte) {
	asuraDecrypt4BlocksRKSoft(rk, dst, src, tweaks)
}

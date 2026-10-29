//go:build arm64 && !purego

package areion

//go:noescape
func vistrutah256EncryptBlockAsm(dst, src, key *[32]byte, rounds int)

//go:noescape
func vistrutah256Encrypt4BlocksAsm(dst, src *[4][32]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock256Asm(dst, src *[64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock512Asm(dst, src, key *[64]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks256Asm(dst, src *[4][64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks512Asm(dst, src *[4][64]byte, key *[64]byte, rounds int)

func vistrutah256EncryptBlockHW(dst, src, key *[32]byte, rounds int) {
	if (rounds == 10 || rounds == 14) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah256EncryptBlockAsm(dst, src, key, rounds)
		return
	}
	vistrutah256EncryptBlockSoft(dst, src, key, rounds)
}

func vistrutah256Encrypt4BlocksHW(dst, src *[4][32]byte, key *[32]byte, rounds int) {
	if (rounds == 10 || rounds == 14) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah256Encrypt4BlocksAsm(dst, src, key, rounds)
		return
	}
	vistrutah256Encrypt4BlocksSoft(dst, src, key, rounds)
}

func vistrutah512EncryptBlock256HW(dst, src *[64]byte, key *[32]byte, rounds int) {
	if (rounds == 10 || rounds == 12 || rounds == 14 || rounds == 18) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah512EncryptBlock256Asm(dst, src, key, rounds)
		return
	}
	vistrutah512EncryptBlock256Soft(dst, src, key, rounds)
}

func vistrutah512EncryptBlock512HW(dst, src, key *[64]byte, rounds int) {
	if (rounds == 10 || rounds == 12 || rounds == 14 || rounds == 18) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah512EncryptBlock512Asm(dst, src, key, rounds)
		return
	}
	vistrutah512EncryptBlock512Soft(dst, src, key, rounds)
}

func vistrutah512Encrypt4Blocks256HW(dst, src *[4][64]byte, key *[32]byte, rounds int) {
	if (rounds == 10 || rounds == 12 || rounds == 14 || rounds == 18) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah512Encrypt4Blocks256Asm(dst, src, key, rounds)
		return
	}
	vistrutah512Encrypt4Blocks256Soft(dst, src, key, rounds)
}

func vistrutah512Encrypt4Blocks512HW(dst, src *[4][64]byte, key *[64]byte, rounds int) {
	if (rounds == 10 || rounds == 12 || rounds == 14 || rounds == 18) && hasARMCrypto && TierCode() != TierPureGo {
		vistrutah512Encrypt4Blocks512Asm(dst, src, key, rounds)
		return
	}
	vistrutah512Encrypt4Blocks512Soft(dst, src, key, rounds)
}

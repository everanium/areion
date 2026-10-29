//go:build amd64 && !purego

package areion

//go:noescape
func vistrutah256EncryptBlockAsm(dst, src, key *[32]byte, rounds int)

//go:noescape
func vistrutah256EncryptBlockVexAsm(dst, src, key *[32]byte, rounds int)

//go:noescape
func vistrutah256EncryptBlockYmmAsm(dst, src, key *[32]byte, rounds int)

//go:noescape
func vistrutah256Encrypt4BlocksAesNiAsm(dst, src *[4][32]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah256Encrypt4BlocksVexAsm(dst, src *[4][32]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah256Encrypt4BlocksYmmAsm(dst, src *[4][32]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah256Encrypt4BlocksZmmAsm(dst, src *[4][32]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock256Asm(dst, src *[64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock256VexAsm(dst, src *[64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock256YmmAsm(dst, src *[64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock256ZmmAsm(dst, src *[64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock512Asm(dst, src, key *[64]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock512VexAsm(dst, src, key *[64]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock512YmmAsm(dst, src, key *[64]byte, rounds int)

//go:noescape
func vistrutah512EncryptBlock512ZmmAsm(dst, src, key *[64]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks256AesNiAsm(dst, src *[4][64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks256VexAsm(dst, src *[4][64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks256YmmAsm(dst, src *[4][64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks256ZmmAsm(dst, src *[4][64]byte, key *[32]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks512AesNiAsm(dst, src *[4][64]byte, key *[64]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks512VexAsm(dst, src *[4][64]byte, key *[64]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks512YmmAsm(dst, src *[4][64]byte, key *[64]byte, rounds int)

//go:noescape
func vistrutah512Encrypt4Blocks512ZmmAsm(dst, src *[4][64]byte, key *[64]byte, rounds int)

func vistrutah256EncryptBlockHW(dst, src, key *[32]byte, rounds int) {
	if rounds != 10 && rounds != 14 {
		vistrutah256EncryptBlockSoft(dst, src, key, rounds)
		return
	}
	tier := TierCode()
	switch {
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		vistrutah256EncryptBlockYmmAsm(dst, src, key, rounds)
	case hasVEX && tier >= TierVEX:
		vistrutah256EncryptBlockVexAsm(dst, src, key, rounds)
	case hasAESNI && tier >= TierAESNI:
		vistrutah256EncryptBlockAsm(dst, src, key, rounds)
	default:
		vistrutah256EncryptBlockSoft(dst, src, key, rounds)
	}
}

func vistrutah256Encrypt4BlocksHW(dst, src *[4][32]byte, key *[32]byte, rounds int) {
	if rounds != 10 && rounds != 14 {
		vistrutah256Encrypt4BlocksSoft(dst, src, key, rounds)
		return
	}
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		vistrutah256Encrypt4BlocksZmmAsm(dst, src, key, rounds)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		vistrutah256Encrypt4BlocksYmmAsm(dst, src, key, rounds)
	case hasVEX && tier >= TierVEX:
		vistrutah256Encrypt4BlocksVexAsm(dst, src, key, rounds)
	case hasAESNI && tier >= TierAESNI:
		vistrutah256Encrypt4BlocksAesNiAsm(dst, src, key, rounds)
	default:
		vistrutah256Encrypt4BlocksSoft(dst, src, key, rounds)
	}
}

func vistrutah512EncryptBlock256HW(dst, src *[64]byte, key *[32]byte, rounds int) {
	if rounds != 10 && rounds != 12 && rounds != 14 && rounds != 18 {
		vistrutah512EncryptBlock256Soft(dst, src, key, rounds)
		return
	}
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		vistrutah512EncryptBlock256ZmmAsm(dst, src, key, rounds)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		vistrutah512EncryptBlock256YmmAsm(dst, src, key, rounds)
	case hasVEX && tier >= TierVEX:
		vistrutah512EncryptBlock256VexAsm(dst, src, key, rounds)
	case hasAESNI && tier >= TierAESNI:
		vistrutah512EncryptBlock256Asm(dst, src, key, rounds)
	default:
		vistrutah512EncryptBlock256Soft(dst, src, key, rounds)
	}
}

func vistrutah512EncryptBlock512HW(dst, src, key *[64]byte, rounds int) {
	if rounds != 10 && rounds != 12 && rounds != 14 && rounds != 18 {
		vistrutah512EncryptBlock512Soft(dst, src, key, rounds)
		return
	}
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		vistrutah512EncryptBlock512ZmmAsm(dst, src, key, rounds)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		vistrutah512EncryptBlock512YmmAsm(dst, src, key, rounds)
	case hasVEX && tier >= TierVEX:
		vistrutah512EncryptBlock512VexAsm(dst, src, key, rounds)
	case hasAESNI && tier >= TierAESNI:
		vistrutah512EncryptBlock512Asm(dst, src, key, rounds)
	default:
		vistrutah512EncryptBlock512Soft(dst, src, key, rounds)
	}
}

func vistrutah512Encrypt4Blocks256HW(dst, src *[4][64]byte, key *[32]byte, rounds int) {
	if rounds != 10 && rounds != 12 && rounds != 14 && rounds != 18 {
		vistrutah512Encrypt4Blocks256Soft(dst, src, key, rounds)
		return
	}
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		vistrutah512Encrypt4Blocks256ZmmAsm(dst, src, key, rounds)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		vistrutah512Encrypt4Blocks256YmmAsm(dst, src, key, rounds)
	case hasVEX && tier >= TierVEX:
		vistrutah512Encrypt4Blocks256VexAsm(dst, src, key, rounds)
	case hasAESNI && tier >= TierAESNI:
		vistrutah512Encrypt4Blocks256AesNiAsm(dst, src, key, rounds)
	default:
		vistrutah512Encrypt4Blocks256Soft(dst, src, key, rounds)
	}
}

func vistrutah512Encrypt4Blocks512HW(dst, src *[4][64]byte, key *[64]byte, rounds int) {
	if rounds != 10 && rounds != 12 && rounds != 14 && rounds != 18 {
		vistrutah512Encrypt4Blocks512Soft(dst, src, key, rounds)
		return
	}
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		vistrutah512Encrypt4Blocks512ZmmAsm(dst, src, key, rounds)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		vistrutah512Encrypt4Blocks512YmmAsm(dst, src, key, rounds)
	case hasVEX && tier >= TierVEX:
		vistrutah512Encrypt4Blocks512VexAsm(dst, src, key, rounds)
	case hasAESNI && tier >= TierAESNI:
		vistrutah512Encrypt4Blocks512AesNiAsm(dst, src, key, rounds)
	default:
		vistrutah512Encrypt4Blocks512Soft(dst, src, key, rounds)
	}
}

//go:build (!amd64 && !arm64) || purego

package areion

func vistrutah256EncryptBlockHW(dst, src, key *[32]byte, rounds int) {
	vistrutah256EncryptBlockSoft(dst, src, key, rounds)
}

func vistrutah256Encrypt4BlocksHW(dst, src *[4][32]byte, key *[32]byte, rounds int) {
	vistrutah256Encrypt4BlocksSoft(dst, src, key, rounds)
}

func vistrutah512EncryptBlock256HW(dst, src *[64]byte, key *[32]byte, rounds int) {
	vistrutah512EncryptBlock256Soft(dst, src, key, rounds)
}

func vistrutah512EncryptBlock512HW(dst, src, key *[64]byte, rounds int) {
	vistrutah512EncryptBlock512Soft(dst, src, key, rounds)
}

func vistrutah512Encrypt4Blocks256HW(dst, src *[4][64]byte, key *[32]byte, rounds int) {
	vistrutah512Encrypt4Blocks256Soft(dst, src, key, rounds)
}

func vistrutah512Encrypt4Blocks512HW(dst, src *[4][64]byte, key *[64]byte, rounds int) {
	vistrutah512Encrypt4Blocks512Soft(dst, src, key, rounds)
}

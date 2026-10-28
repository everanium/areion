//go:build amd64 && !purego

package areion

//go:noescape
func aesRoundAsm(block, roundKey *Block)

//go:noescape
func aesRoundVexAsm(block, roundKey *Block)

//go:noescape
func aesFinalRoundAsm(block, roundKey *Block)

//go:noescape
func aesFinalRoundVexAsm(block, roundKey *Block)

//go:noescape
func aesRound4ZmmAsm(blocks, roundKeys *Block4)

//go:noescape
func aesFinalRound4ZmmAsm(blocks, roundKeys *Block4)

//go:noescape
func aesRound4YmmAsm(blocks, roundKeys *Block4)

//go:noescape
func aesFinalRound4YmmAsm(blocks, roundKeys *Block4)

//go:noescape
func aesRound4VexAsm(blocks, roundKeys *Block4)

//go:noescape
func aesFinalRound4VexAsm(blocks, roundKeys *Block4)

//go:noescape
func aesRound4AesNiAsm(blocks, roundKeys *Block4)

//go:noescape
func aesFinalRound4AesNiAsm(blocks, roundKeys *Block4)

//go:noescape
func aes128EncryptBlockAsm(rk *[11][16]byte, dst, src *[16]byte)

//go:noescape
func aes128EncryptBlockVexAsm(rk *[11][16]byte, dst, src *[16]byte)

//go:noescape
func aes128Encrypt4BlocksZmmAsm(rk *[11][16]byte, dst, src *[64]byte)

//go:noescape
func aes128Encrypt4BlocksYmmAsm(rk *[11][16]byte, dst, src *[64]byte)

//go:noescape
func aes128Encrypt4BlocksVexAsm(rk *[11][16]byte, dst, src *[64]byte)

//go:noescape
func aes128Encrypt4BlocksAesNiAsm(rk *[11][16]byte, dst, src *[64]byte)

//go:noescape
func aes128ExpandKeyAsm(rk *[11][16]byte, key *[16]byte)

//go:noescape
func aes128ExpandKeyVexAsm(rk *[11][16]byte, key *[16]byte)

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

//go:noescape
func areion256PermuteRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion256PermuteVexRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion512PermuteRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areion512PermuteVexRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areion256InversePermuteRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion256InversePermuteVexRCAsm(state *State256, rc *[15][16]byte)

//go:noescape
func areion512InversePermuteRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areion512InversePermuteVexRCAsm(state *State512, rc *[15][16]byte)

//go:noescape
func areionSoEM256Asm(out *[32]byte, key *[64]byte, m *[32]byte)

//go:noescape
func areionSoEM256VexAsm(out *[32]byte, key *[64]byte, m *[32]byte)

//go:noescape
func areionSoEM512Asm(out *[64]byte, key *[128]byte, m *[64]byte)

//go:noescape
func areionSoEM512VexAsm(out *[64]byte, key *[128]byte, m *[64]byte)

//go:noescape
func areion256DMAsm(out, m *[32]byte)

//go:noescape
func areion256DMVexAsm(out, m *[32]byte)

//go:noescape
func areion512DMAsm(out *[32]byte, m *[64]byte)

//go:noescape
func areion512DMVexAsm(out *[32]byte, m *[64]byte)

//go:noescape
func areion256Permutex4RC(b0, b1, b2, b3 *[32]byte, rc *[15 * 64]byte)

//go:noescape
func areion256InversePermutex4RC(b0, b1, b2, b3 *[32]byte, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4RC(b0, b1, b2, b3 *[64]byte, rc *[15 * 64]byte)

//go:noescape
func areion512InversePermutex4RC(b0, b1, b2, b3 *[64]byte, rc *[15 * 64]byte)

//go:noescape
func areion256Permutex4Avx2RC(b0, b1, b2, b3 *[32]byte, rc *[15 * 64]byte)

//go:noescape
func areion256InversePermutex4Avx2RC(b0, b1, b2, b3 *[32]byte, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4Avx2RC(b0, b1, b2, b3 *[64]byte, rc *[15 * 64]byte)

//go:noescape
func areion512InversePermutex4Avx2RC(b0, b1, b2, b3 *[64]byte, rc *[15 * 64]byte)

//go:noescape
func areion256Permutex4VexRC(b0, b1, b2, b3 *[32]byte, rc *[15 * 64]byte)

//go:noescape
func areion256InversePermutex4VexRC(b0, b1, b2, b3 *[32]byte, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4VexRC(b0, b1, b2, b3 *[64]byte, rc *[15 * 64]byte)

//go:noescape
func areion512InversePermutex4VexRC(b0, b1, b2, b3 *[64]byte, rc *[15 * 64]byte)

//go:noescape
func areion256Permutex4AesNiRC(b0, b1, b2, b3 *[32]byte, rc *[15 * 64]byte)

//go:noescape
func areion256InversePermutex4AesNiRC(b0, b1, b2, b3 *[32]byte, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4AesNiRC(b0, b1, b2, b3 *[64]byte, rc *[15 * 64]byte)

//go:noescape
func areion512InversePermutex4AesNiRC(b0, b1, b2, b3 *[64]byte, rc *[15 * 64]byte)

//go:noescape
func areion256SoEMPermutex4Interleaved(out, inputs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion512SoEMPermutex4Interleaved(out, inputs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion256SoEMPermutex4VaesAvx2(out, inputs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion512SoEMPermutex4VaesAvx2(out, inputs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion256SoEMPermutex4Vex(out, inputs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion512SoEMPermutex4Vex(out, inputs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion256SoEMPermutex4AesNi(out, inputs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion512SoEMPermutex4AesNi(out, inputs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion256EMEncryptx4AESNI(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EMEncryptx4VEX(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EMEncryptx4VAESAVX2(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EMEncryptx4AVX512(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EMDecryptx4AESNI(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EMDecryptx4VEX(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EMDecryptx4VAESAVX2(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EMDecryptx4AVX512(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion512EMEncryptx4AESNI(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EMEncryptx4VEX(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EMEncryptx4VAESAVX2(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EMEncryptx4AVX512(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EMDecryptx4AESNI(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EMDecryptx4VEX(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EMDecryptx4VAESAVX2(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EMDecryptx4AVX512(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion256EM2Encryptx4AESNI(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EM2Encryptx4VEX(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EM2Encryptx4VAESAVX2(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EM2Encryptx4AVX512(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EM2Decryptx4AESNI(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EM2Decryptx4VEX(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EM2Decryptx4VAESAVX2(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion256EM2Decryptx4AVX512(out, msgs *[4][32]byte, keys *[4][64]byte)

//go:noescape
func areion512EM2Encryptx4AESNI(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EM2Encryptx4VEX(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EM2Encryptx4VAESAVX2(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EM2Encryptx4AVX512(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EM2Decryptx4AESNI(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EM2Decryptx4VEX(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EM2Decryptx4VAESAVX2(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion512EM2Decryptx4AVX512(out, msgs *[4][64]byte, keys *[4][128]byte)

//go:noescape
func areion256TEMEncryptx4AESNI(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEMEncryptx4VEX(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEMEncryptx4VAESAVX2(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEMEncryptx4AVX512(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEMDecryptx4AESNI(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEMDecryptx4VEX(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEMDecryptx4VAESAVX2(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEMDecryptx4AVX512(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion512TEMEncryptx4AESNI(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEMEncryptx4VEX(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEMEncryptx4VAESAVX2(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEMEncryptx4AVX512(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEMDecryptx4AESNI(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEMDecryptx4VEX(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEMDecryptx4VAESAVX2(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEMDecryptx4AVX512(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion256TEM2Encryptx4AESNI(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEM2Encryptx4VEX(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEM2Encryptx4VAESAVX2(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEM2Encryptx4AVX512(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEM2Decryptx4AESNI(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEM2Decryptx4VEX(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEM2Decryptx4VAESAVX2(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion256TEM2Decryptx4AVX512(out, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte)

//go:noescape
func areion512TEM2Encryptx4AESNI(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEM2Encryptx4VEX(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEM2Encryptx4VAESAVX2(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEM2Encryptx4AVX512(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEM2Decryptx4AESNI(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEM2Decryptx4VEX(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEM2Decryptx4VAESAVX2(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion512TEM2Decryptx4AVX512(out, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte)

//go:noescape
func areion256EMEncryptAESNI(out *[32]byte, m *[32]byte, k *[64]byte)

//go:noescape
func areion256EMEncryptVEX(out *[32]byte, m *[32]byte, k *[64]byte)

//go:noescape
func areion256EMDecryptAESNI(out *[32]byte, c *[32]byte, k *[64]byte)

//go:noescape
func areion256EMDecryptVEX(out *[32]byte, c *[32]byte, k *[64]byte)

//go:noescape
func areion512EMEncryptAESNI(out *[64]byte, m *[64]byte, k *[128]byte)

//go:noescape
func areion512EMEncryptVEX(out *[64]byte, m *[64]byte, k *[128]byte)

//go:noescape
func areion512EMDecryptAESNI(out *[64]byte, c *[64]byte, k *[128]byte)

//go:noescape
func areion512EMDecryptVEX(out *[64]byte, c *[64]byte, k *[128]byte)

//go:noescape
func areion256EM2EncryptAESNI(out *[32]byte, m *[32]byte, k *[64]byte)

//go:noescape
func areion256EM2EncryptVEX(out *[32]byte, m *[32]byte, k *[64]byte)

//go:noescape
func areion256EM2DecryptAESNI(out *[32]byte, c *[32]byte, k *[64]byte)

//go:noescape
func areion256EM2DecryptVEX(out *[32]byte, c *[32]byte, k *[64]byte)

//go:noescape
func areion512EM2EncryptAESNI(out *[64]byte, m *[64]byte, k *[128]byte)

//go:noescape
func areion512EM2EncryptVEX(out *[64]byte, m *[64]byte, k *[128]byte)

//go:noescape
func areion512EM2DecryptAESNI(out *[64]byte, c *[64]byte, k *[128]byte)

//go:noescape
func areion512EM2DecryptVEX(out *[64]byte, c *[64]byte, k *[128]byte)

//go:noescape
func areion256TEMEncryptAESNI(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEMEncryptVEX(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEMDecryptAESNI(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEMDecryptVEX(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion512TEMEncryptAESNI(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEMEncryptVEX(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEMDecryptAESNI(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEMDecryptVEX(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion256TEM2EncryptAESNI(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEM2EncryptVEX(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEM2DecryptAESNI(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion256TEM2DecryptVEX(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte)

//go:noescape
func areion512TEM2EncryptAESNI(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEM2EncryptVEX(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEM2DecryptAESNI(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte)

//go:noescape
func areion512TEM2DecryptVEX(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte)

func aesRoundHW(block, roundKey *Block) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		aesRoundVexAsm(block, roundKey)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		aesRoundAsm(block, roundKey)
		return
	}
	Round(block, roundKey)
}

func aesFinalRoundHW(block, roundKey *Block) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		aesFinalRoundVexAsm(block, roundKey)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		aesFinalRoundAsm(block, roundKey)
		return
	}
	FinalRound(block, roundKey)
}

func aesRound4HW(blocks, roundKeys *Block4) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		aesRound4ZmmAsm(blocks, roundKeys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		aesRound4YmmAsm(blocks, roundKeys)
	case hasVEX && tier >= TierVEX:
		aesRound4VexAsm(blocks, roundKeys)
	case hasAESNI && tier >= TierAESNI:
		aesRound4AesNiAsm(blocks, roundKeys)
	default:
		aesRound4Software(blocks, roundKeys)
	}
}

func aesFinalRound4HW(blocks, roundKeys *Block4) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		aesFinalRound4ZmmAsm(blocks, roundKeys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		aesFinalRound4YmmAsm(blocks, roundKeys)
	case hasVEX && tier >= TierVEX:
		aesFinalRound4VexAsm(blocks, roundKeys)
	case hasAESNI && tier >= TierAESNI:
		aesFinalRound4AesNiAsm(blocks, roundKeys)
	default:
		aesFinalRound4Software(blocks, roundKeys)
	}
}

func aes128EncryptBlock(rk *[11][16]byte, dst, src *[16]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		aes128EncryptBlockVexAsm(rk, dst, src)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		aes128EncryptBlockAsm(rk, dst, src)
		return
	}
	aes128EncryptBlockSoftware(rk, dst, src)
}

func aes128Encrypt4Blocks(rk *[11][16]byte, dst, src *[64]byte) {
	tier := TierCode()
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		aes128Encrypt4BlocksZmmAsm(rk, dst, src)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		aes128Encrypt4BlocksYmmAsm(rk, dst, src)
	case hasVEX && tier >= TierVEX:
		aes128Encrypt4BlocksVexAsm(rk, dst, src)
	case hasAESNI && tier >= TierAESNI:
		aes128Encrypt4BlocksAesNiAsm(rk, dst, src)
	default:
		aes128Encrypt4BlocksSoftware(rk, dst, src)
	}
}

func expandKey128(key *[16]byte, rk *[11][16]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		aes128ExpandKeyVexAsm(rk, key)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		aes128ExpandKeyAsm(rk, key)
		return
	}
	expandKey128Software(key, rk)
}

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

func areion256Permute(state *State256) {
	areion256PermuteRC(state, &roundConstantsP1)
}

func areion256PermuteP2(state *State256) {
	areion256PermuteRC(state, &roundConstantsP2)
}

func areion256PermuteRC(state *State256, rc *[15][16]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		areion256PermuteVexRCAsm(state, rc)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		areion256PermuteRCAsm(state, rc)
		return
	}
	areion256PermuteSoftwareRC(state, rc)
}

func areion256InversePermute(state *State256) {
	areion256InversePermuteRC(state, &roundConstantsP1)
}

func areion256InversePermuteP2(state *State256) {
	areion256InversePermuteRC(state, &roundConstantsP2)
}

func areion256InversePermuteRC(state *State256, rc *[15][16]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		areion256InversePermuteVexRCAsm(state, rc)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		areion256InversePermuteRCAsm(state, rc)
		return
	}
	areion256InversePermuteSoftwareRC(state, rc)
}

func areion512Permute(state *State512) {
	areion512PermuteRC(state, &roundConstantsP1)
}

func areion512PermuteP2(state *State512) {
	areion512PermuteRC(state, &roundConstantsP2)
}

func areion512PermuteRC(state *State512, rc *[15][16]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		areion512PermuteVexRCAsm(state, rc)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		areion512PermuteRCAsm(state, rc)
		return
	}
	areion512PermuteSoftwareRC(state, rc)
}

func areion512InversePermute(state *State512) {
	areion512InversePermuteRC(state, &roundConstantsP1)
}

func areion512InversePermuteP2(state *State512) {
	areion512InversePermuteRC(state, &roundConstantsP2)
}

func areion512InversePermuteRC(state *State512, rc *[15][16]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		areion512InversePermuteVexRCAsm(state, rc)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		areion512InversePermuteRCAsm(state, rc)
		return
	}
	areion512InversePermuteSoftwareRC(state, rc)
}

//go:noescape
func clobberScratchGPRs()

func areionSoEM256(key *[64]byte, m *[32]byte) (out [32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		return soem256Software(key, m)
	}
	if hasVEX && tier >= TierVEX {
		areionSoEM256VexAsm(&out, key, m)
	} else {
		areionSoEM256Asm(&out, key, m)
	}
	return out
}

func areionSoEM512(key *[128]byte, m *[64]byte) (out [64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		return soem512Software(key, m)
	}
	if hasVEX && tier >= TierVEX {
		areionSoEM512VexAsm(&out, key, m)
	} else {
		areionSoEM512Asm(&out, key, m)
	}
	return out
}

func areionDM256(out, m *[32]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		areion256DMVexAsm(out, m)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		areion256DMAsm(out, m)
		return
	}
	dm256Software(out, m)
}

func areionDM512(out *[32]byte, m *[64]byte) {
	tier := TierCode()
	if hasVEX && tier >= TierVEX {
		areion512DMVexAsm(out, m)
		return
	}
	if hasAESNI && tier >= TierAESNI {
		areion512DMAsm(out, m)
		return
	}
	dm512Software(out, m)
}

func areion256Permutex4(states *[4][32]byte) {
	areion256Permutex4Tables(states, &roundConstantsP1, &areionRC4x)
}

func areion256PermuteP2x4(states *[4][32]byte) {
	areion256Permutex4Tables(states, &roundConstantsP2, &areionRC4x2)
}

func areion256Permutex4Tables(states *[4][32]byte, rc *[15][16]byte, rc4 *[15 * 64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		areion256Permutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	b0, b1, b2, b3 := &states[0], &states[1], &states[2], &states[3]
	if hasAVX512 && hasVAESAVX2 && tier >= TierAVX512 {
		areion256Permutex4RC(b0, b1, b2, b3, rc4)
	} else if hasVAESAVX2 && tier >= TierVAESAVX2 {
		areion256Permutex4Avx2RC(b0, b1, b2, b3, rc4)
	} else if hasVEX && tier >= TierVEX {
		areion256Permutex4VexRC(b0, b1, b2, b3, rc4)
	} else {
		areion256Permutex4AesNiRC(b0, b1, b2, b3, rc4)
	}
}

func areion256InversePermutex4(states *[4][32]byte) {
	areion256InversePermutex4Tables(states, &roundConstantsP1, &areionRC4x)
}

func areion256InversePermuteP2x4(states *[4][32]byte) {
	areion256InversePermutex4Tables(states, &roundConstantsP2, &areionRC4x2)
}

func areion256InversePermutex4Tables(states *[4][32]byte, rc *[15][16]byte, rc4 *[15 * 64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		areion256InversePermutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	b0, b1, b2, b3 := &states[0], &states[1], &states[2], &states[3]
	if hasAVX512 && hasVAESAVX2 && tier >= TierAVX512 {
		areion256InversePermutex4RC(b0, b1, b2, b3, rc4)
	} else if hasVAESAVX2 && tier >= TierVAESAVX2 {
		areion256InversePermutex4Avx2RC(b0, b1, b2, b3, rc4)
	} else if hasVEX && tier >= TierVEX {
		areion256InversePermutex4VexRC(b0, b1, b2, b3, rc4)
	} else {
		areion256InversePermutex4AesNiRC(b0, b1, b2, b3, rc4)
	}
}

func areion512Permutex4(states *[4][64]byte) {
	areion512Permutex4Tables(states, &roundConstantsP1, &areionRC4x)
}

func areion512PermuteP2x4(states *[4][64]byte) {
	areion512Permutex4Tables(states, &roundConstantsP2, &areionRC4x2)
}

func areion512Permutex4Tables(states *[4][64]byte, rc *[15][16]byte, rc4 *[15 * 64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		areion512Permutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	b0, b1, b2, b3 := &states[0], &states[1], &states[2], &states[3]
	if hasAVX512 && hasVAESAVX2 && tier >= TierAVX512 {
		areion512Permutex4RC(b0, b1, b2, b3, rc4)
	} else if hasVAESAVX2 && tier >= TierVAESAVX2 {
		areion512Permutex4Avx2RC(b0, b1, b2, b3, rc4)
	} else if hasVEX && tier >= TierVEX {
		areion512Permutex4VexRC(b0, b1, b2, b3, rc4)
	} else {
		areion512Permutex4AesNiRC(b0, b1, b2, b3, rc4)
	}
}

func areion512InversePermutex4(states *[4][64]byte) {
	areion512InversePermutex4Tables(states, &roundConstantsP1, &areionRC4x)
}

func areion512InversePermuteP2x4(states *[4][64]byte) {
	areion512InversePermutex4Tables(states, &roundConstantsP2, &areionRC4x2)
}

func areion512InversePermutex4Tables(states *[4][64]byte, rc *[15][16]byte, rc4 *[15 * 64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		areion512InversePermutex4SoftwareRC(states, rc)
		clobberScratchGPRs()
		return
	}
	b0, b1, b2, b3 := &states[0], &states[1], &states[2], &states[3]
	if hasAVX512 && hasVAESAVX2 && tier >= TierAVX512 {
		areion512InversePermutex4RC(b0, b1, b2, b3, rc4)
	} else if hasVAESAVX2 && tier >= TierVAESAVX2 {
		areion512InversePermutex4Avx2RC(b0, b1, b2, b3, rc4)
	} else if hasVEX && tier >= TierVEX {
		areion512InversePermutex4VexRC(b0, b1, b2, b3, rc4)
	} else {
		areion512InversePermutex4AesNiRC(b0, b1, b2, b3, rc4)
	}
}

func areionSoEM256x4(keys *[4][64]byte, inputs *[4][32]byte) (out [4][32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		return soem256x4Software(keys, inputs)
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256SoEMPermutex4Interleaved(&out, inputs, keys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256SoEMPermutex4VaesAvx2(&out, inputs, keys)
	case hasVEX && tier >= TierVEX:
		areion256SoEMPermutex4Vex(&out, inputs, keys)
	default:
		areion256SoEMPermutex4AesNi(&out, inputs, keys)
	}
	return out
}

func areionSoEM512x4(keys *[4][128]byte, inputs *[4][64]byte) (out [4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		return soem512x4Software(keys, inputs)
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512SoEMPermutex4Interleaved(&out, inputs, keys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512SoEMPermutex4VaesAvx2(&out, inputs, keys)
	case hasVEX && tier >= TierVEX:
		areion512SoEMPermutex4Vex(&out, inputs, keys)
	default:
		areion512SoEMPermutex4AesNi(&out, inputs, keys)
	}
	return out
}

func areionEMEncrypt256(out *[32]byte, m *[32]byte, k *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emEncrypt256Software(out, m, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256EMEncryptVEX(out, m, k)
	} else {
		areion256EMEncryptAESNI(out, m, k)
	}
}

func areionEMDecrypt256(out *[32]byte, c *[32]byte, k *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emDecrypt256Software(out, c, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256EMDecryptVEX(out, c, k)
	} else {
		areion256EMDecryptAESNI(out, c, k)
	}
}

func areionEMEncrypt512(out *[64]byte, m *[64]byte, k *[128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emEncrypt512Software(out, m, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512EMEncryptVEX(out, m, k)
	} else {
		areion512EMEncryptAESNI(out, m, k)
	}
}

func areionEMDecrypt512(out *[64]byte, c *[64]byte, k *[128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emDecrypt512Software(out, c, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512EMDecryptVEX(out, c, k)
	} else {
		areion512EMDecryptAESNI(out, c, k)
	}
}

func areionEM2Encrypt256(out *[32]byte, m *[32]byte, k *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Encrypt256Software(out, m, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256EM2EncryptVEX(out, m, k)
	} else {
		areion256EM2EncryptAESNI(out, m, k)
	}
}

func areionEM2Decrypt256(out *[32]byte, c *[32]byte, k *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Decrypt256Software(out, c, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256EM2DecryptVEX(out, c, k)
	} else {
		areion256EM2DecryptAESNI(out, c, k)
	}
}

func areionEM2Encrypt512(out *[64]byte, m *[64]byte, k *[128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Encrypt512Software(out, m, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512EM2EncryptVEX(out, m, k)
	} else {
		areion512EM2EncryptAESNI(out, m, k)
	}
}

func areionEM2Decrypt512(out *[64]byte, c *[64]byte, k *[128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Decrypt512Software(out, c, k)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512EM2DecryptVEX(out, c, k)
	} else {
		areion512EM2DecryptAESNI(out, c, k)
	}
}

func areionTEMEncrypt256(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temEncrypt256Software(out, m, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256TEMEncryptVEX(out, m, k, t)
	} else {
		areion256TEMEncryptAESNI(out, m, k, t)
	}
}

func areionTEMDecrypt256(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temDecrypt256Software(out, c, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256TEMDecryptVEX(out, c, k, t)
	} else {
		areion256TEMDecryptAESNI(out, c, k, t)
	}
}

func areionTEMEncrypt512(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temEncrypt512Software(out, m, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512TEMEncryptVEX(out, m, k, t)
	} else {
		areion512TEMEncryptAESNI(out, m, k, t)
	}
}

func areionTEMDecrypt512(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temDecrypt512Software(out, c, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512TEMDecryptVEX(out, c, k, t)
	} else {
		areion512TEMDecryptAESNI(out, c, k, t)
	}
}

func areionTEM2Encrypt256(out *[32]byte, m *[32]byte, k *[64]byte, t *[32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Encrypt256Software(out, m, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256TEM2EncryptVEX(out, m, k, t)
	} else {
		areion256TEM2EncryptAESNI(out, m, k, t)
	}
}

func areionTEM2Decrypt256(out *[32]byte, c *[32]byte, k *[64]byte, t *[32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Decrypt256Software(out, c, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion256TEM2DecryptVEX(out, c, k, t)
	} else {
		areion256TEM2DecryptAESNI(out, c, k, t)
	}
}

func areionTEM2Encrypt512(out *[64]byte, m *[64]byte, k *[128]byte, t *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Encrypt512Software(out, m, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512TEM2EncryptVEX(out, m, k, t)
	} else {
		areion512TEM2EncryptAESNI(out, m, k, t)
	}
}

func areionTEM2Decrypt512(out *[64]byte, c *[64]byte, k *[128]byte, t *[64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Decrypt512Software(out, c, k, t)
		return
	}
	if hasVEX && tier >= TierVEX {
		areion512TEM2DecryptVEX(out, c, k, t)
	} else {
		areion512TEM2DecryptAESNI(out, c, k, t)
	}
}

func areionEMEncrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emEncrypt256x4Software(out, msgs, keys)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256EMEncryptx4AVX512(out, msgs, keys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256EMEncryptx4VAESAVX2(out, msgs, keys)
	case hasVEX && tier >= TierVEX:
		areion256EMEncryptx4VEX(out, msgs, keys)
	default:
		areion256EMEncryptx4AESNI(out, msgs, keys)
	}
}

func areionEMDecrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emDecrypt256x4Software(out, ct, keys)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256EMDecryptx4AVX512(out, ct, keys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256EMDecryptx4VAESAVX2(out, ct, keys)
	case hasVEX && tier >= TierVEX:
		areion256EMDecryptx4VEX(out, ct, keys)
	default:
		areion256EMDecryptx4AESNI(out, ct, keys)
	}
}

func areionEMEncrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emEncrypt512x4Software(out, msgs, keys)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512EMEncryptx4AVX512(out, msgs, keys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512EMEncryptx4VAESAVX2(out, msgs, keys)
	case hasVEX && tier >= TierVEX:
		areion512EMEncryptx4VEX(out, msgs, keys)
	default:
		areion512EMEncryptx4AESNI(out, msgs, keys)
	}
}

func areionEMDecrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		emDecrypt512x4Software(out, ct, keys)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512EMDecryptx4AVX512(out, ct, keys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512EMDecryptx4VAESAVX2(out, ct, keys)
	case hasVEX && tier >= TierVEX:
		areion512EMDecryptx4VEX(out, ct, keys)
	default:
		areion512EMDecryptx4AESNI(out, ct, keys)
	}
}

func areionEM2Encrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Encrypt256x4Software(out, msgs, keys)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256EM2Encryptx4AVX512(out, msgs, keys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256EM2Encryptx4VAESAVX2(out, msgs, keys)
	case hasVEX && tier >= TierVEX:
		areion256EM2Encryptx4VEX(out, msgs, keys)
	default:
		areion256EM2Encryptx4AESNI(out, msgs, keys)
	}
}

func areionEM2Decrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Decrypt256x4Software(out, ct, keys)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256EM2Decryptx4AVX512(out, ct, keys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256EM2Decryptx4VAESAVX2(out, ct, keys)
	case hasVEX && tier >= TierVEX:
		areion256EM2Decryptx4VEX(out, ct, keys)
	default:
		areion256EM2Decryptx4AESNI(out, ct, keys)
	}
}

func areionEM2Encrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Encrypt512x4Software(out, msgs, keys)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512EM2Encryptx4AVX512(out, msgs, keys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512EM2Encryptx4VAESAVX2(out, msgs, keys)
	case hasVEX && tier >= TierVEX:
		areion512EM2Encryptx4VEX(out, msgs, keys)
	default:
		areion512EM2Encryptx4AESNI(out, msgs, keys)
	}
}

func areionEM2Decrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		em2Decrypt512x4Software(out, ct, keys)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512EM2Decryptx4AVX512(out, ct, keys)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512EM2Decryptx4VAESAVX2(out, ct, keys)
	case hasVEX && tier >= TierVEX:
		areion512EM2Decryptx4VEX(out, ct, keys)
	default:
		areion512EM2Decryptx4AESNI(out, ct, keys)
	}
}

func areionTEMEncrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temEncrypt256x4Software(out, msgs, keys, tweaks)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256TEMEncryptx4AVX512(out, msgs, keys, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256TEMEncryptx4VAESAVX2(out, msgs, keys, tweaks)
	case hasVEX && tier >= TierVEX:
		areion256TEMEncryptx4VEX(out, msgs, keys, tweaks)
	default:
		areion256TEMEncryptx4AESNI(out, msgs, keys, tweaks)
	}
}

func areionTEMDecrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temDecrypt256x4Software(out, ct, keys, tweaks)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256TEMDecryptx4AVX512(out, ct, keys, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256TEMDecryptx4VAESAVX2(out, ct, keys, tweaks)
	case hasVEX && tier >= TierVEX:
		areion256TEMDecryptx4VEX(out, ct, keys, tweaks)
	default:
		areion256TEMDecryptx4AESNI(out, ct, keys, tweaks)
	}
}

func areionTEMEncrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temEncrypt512x4Software(out, msgs, keys, tweaks)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512TEMEncryptx4AVX512(out, msgs, keys, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512TEMEncryptx4VAESAVX2(out, msgs, keys, tweaks)
	case hasVEX && tier >= TierVEX:
		areion512TEMEncryptx4VEX(out, msgs, keys, tweaks)
	default:
		areion512TEMEncryptx4AESNI(out, msgs, keys, tweaks)
	}
}

func areionTEMDecrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		temDecrypt512x4Software(out, ct, keys, tweaks)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512TEMDecryptx4AVX512(out, ct, keys, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512TEMDecryptx4VAESAVX2(out, ct, keys, tweaks)
	case hasVEX && tier >= TierVEX:
		areion512TEMDecryptx4VEX(out, ct, keys, tweaks)
	default:
		areion512TEMDecryptx4AESNI(out, ct, keys, tweaks)
	}
}

func areionTEM2Encrypt256x4(out *[4][32]byte, msgs *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Encrypt256x4Software(out, msgs, keys, tweaks)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256TEM2Encryptx4AVX512(out, msgs, keys, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256TEM2Encryptx4VAESAVX2(out, msgs, keys, tweaks)
	case hasVEX && tier >= TierVEX:
		areion256TEM2Encryptx4VEX(out, msgs, keys, tweaks)
	default:
		areion256TEM2Encryptx4AESNI(out, msgs, keys, tweaks)
	}
}

func areionTEM2Decrypt256x4(out *[4][32]byte, ct *[4][32]byte, keys *[4][64]byte, tweaks *[4][32]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Decrypt256x4Software(out, ct, keys, tweaks)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion256TEM2Decryptx4AVX512(out, ct, keys, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion256TEM2Decryptx4VAESAVX2(out, ct, keys, tweaks)
	case hasVEX && tier >= TierVEX:
		areion256TEM2Decryptx4VEX(out, ct, keys, tweaks)
	default:
		areion256TEM2Decryptx4AESNI(out, ct, keys, tweaks)
	}
}

func areionTEM2Encrypt512x4(out *[4][64]byte, msgs *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Encrypt512x4Software(out, msgs, keys, tweaks)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512TEM2Encryptx4AVX512(out, msgs, keys, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512TEM2Encryptx4VAESAVX2(out, msgs, keys, tweaks)
	case hasVEX && tier >= TierVEX:
		areion512TEM2Encryptx4VEX(out, msgs, keys, tweaks)
	default:
		areion512TEM2Encryptx4AESNI(out, msgs, keys, tweaks)
	}
}

func areionTEM2Decrypt512x4(out *[4][64]byte, ct *[4][64]byte, keys *[4][128]byte, tweaks *[4][64]byte) {
	tier := TierCode()
	if tier == TierPureGo || !hasAESNI {
		tem2Decrypt512x4Software(out, ct, keys, tweaks)
		return
	}
	switch {
	case hasAVX512 && hasVAESAVX2 && tier >= TierAVX512:
		areion512TEM2Decryptx4AVX512(out, ct, keys, tweaks)
	case hasVAESAVX2 && tier >= TierVAESAVX2:
		areion512TEM2Decryptx4VAESAVX2(out, ct, keys, tweaks)
	case hasVEX && tier >= TierVEX:
		areion512TEM2Decryptx4VEX(out, ct, keys, tweaks)
	default:
		areion512TEM2Decryptx4AESNI(out, ct, keys, tweaks)
	}
}

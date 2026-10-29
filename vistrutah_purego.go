package areion

import "runtime"

func vistrutah256StepRho(rk0, rk1 *Block) {
	var n0, n1 Block
	for i := 0; i < 16; i++ {
		n0[i] = rk0[vistrutahP4[i]]
		n1[i] = rk1[vistrutahP5[i]]
	}
	*rk0 = n0
	*rk1 = n1
	clear(n0[:])
	clear(n1[:])
	runtime.KeepAlive(&n0)
	runtime.KeepAlive(&n1)
}

func vistrutah256StepRhoInv(rk0, rk1 *Block) {
	var n0, n1 Block
	for i := 0; i < 16; i++ {
		n0[i] = rk0[vistrutahP4Inv[i]]
		n1[i] = rk1[vistrutahP5Inv[i]]
	}
	*rk0 = n0
	*rk1 = n1
	clear(n0[:])
	clear(n1[:])
	runtime.KeepAlive(&n0)
	runtime.KeepAlive(&n1)
}

func vistrutah256MixFwd(s0, s1 *Block) {
	var m0, m1 Block
	for i := 0; i < 8; i++ {
		m0[i] = s0[2*i]
		m0[8+i] = s1[2*i]
		m1[i] = s0[2*i+1]
		m1[8+i] = s1[2*i+1]
	}
	*s0 = m0
	*s1 = m1
	clear(m0[:])
	clear(m1[:])
	runtime.KeepAlive(&m0)
	runtime.KeepAlive(&m1)
}

func vistrutah256MixInv(s0, s1 *Block) {
	var m0, m1 Block
	for i := 0; i < 8; i++ {
		m0[2*i] = s0[i]
		m0[2*i+1] = s1[i]
		m1[2*i] = s0[8+i]
		m1[2*i+1] = s1[8+i]
	}
	*s0 = m0
	*s1 = m1
	clear(m0[:])
	clear(m1[:])
	runtime.KeepAlive(&m0)
	runtime.KeepAlive(&m1)
}

//go:noinline
func vistrutah256EncryptBlockSoftBody(dst, src, key *[32]byte, rounds int) {
	steps := rounds / 2
	if steps < 1 || steps > 16 {
		return
	}
	var s0, s1, fk0, fk1, rk0, rk1 Block
	copy(s0[:], src[0:16])
	copy(s1[:], src[16:32])
	copy(fk0[:], key[0:16])
	copy(fk1[:], key[16:32])
	rk0 = fk1
	rk1 = fk0

	var q, qFK bsState
	bsPack2(&qFK, &fk0, &fk1)

	for step := 0; step < steps; step++ {
		xorBlock(&s0, &s0, &rk0)
		xorBlock(&s1, &s1, &rk1)
		if step > 0 {
			xorBlock(&s0, &s0, (*Block)(&vistrutahRoundConstants[step-1]))
		}
		bsPack2(&q, &s0, &s1)
		bsRoundNoKey(&q)
		bsXor(&q, &qFK)
		if step < steps-1 {
			bsRoundNoKey(&q)
			bsUnpack2(&q, &s0, &s1)
			vistrutah256MixFwd(&s0, &s1)
			vistrutah256StepRho(&rk0, &rk1)
		} else {
			bsFinalRoundNoKey(&q)
			bsUnpack2(&q, &s0, &s1)
			vistrutah256StepRho(&rk0, &rk1)
			xorBlock((*Block)(dst[0:16]), &s0, &rk0)
			xorBlock((*Block)(dst[16:32]), &s1, &rk1)
		}
	}

	clear(s0[:])
	clear(s1[:])
	clear(fk0[:])
	clear(fk1[:])
	clear(rk0[:])
	clear(rk1[:])
	clear(q[:])
	clear(qFK[:])
	runtime.KeepAlive(&s0)
	runtime.KeepAlive(&s1)
	runtime.KeepAlive(&fk0)
	runtime.KeepAlive(&fk1)
	runtime.KeepAlive(&rk0)
	runtime.KeepAlive(&rk1)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&qFK)
}

func vistrutah256EncryptBlockSoft(dst, src, key *[32]byte, rounds int) {
	vistrutah256EncryptBlockSoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func vistrutah256DecryptBlockSoftBody(dst, src, key *[32]byte, rounds int) {
	steps := rounds / 2
	if steps < 1 || steps > 16 {
		return
	}
	var s0, s1, fk0, fk1, rk0, rk1 Block
	copy(s0[:], src[0:16])
	copy(s1[:], src[16:32])
	copy(fk0[:], key[0:16])
	copy(fk1[:], key[16:32])
	rk0 = fk1
	rk1 = fk0
	for step := 0; step < steps; step++ {
		vistrutah256StepRho(&rk0, &rk1)
	}

	var q, qFK bsState
	bsPack2(&qFK, &fk0, &fk1)

	for step := steps - 1; step >= 0; step-- {
		if step == steps-1 {
			xorBlock(&s0, &s0, &rk0)
			xorBlock(&s1, &s1, &rk1)
			bsPack2(&q, &s0, &s1)
			bsInvFinalRoundNoKey(&q)
		} else {
			vistrutah256MixInv(&s0, &s1)
			bsPack2(&q, &s0, &s1)
			bsInvMixColumns(&q)
			bsInvFinalRoundNoKey(&q)
		}
		vistrutah256StepRhoInv(&rk0, &rk1)
		bsXor(&q, &qFK)
		bsInvMixColumns(&q)
		bsInvFinalRoundNoKey(&q)
		bsUnpack2(&q, &s0, &s1)
		xorBlock(&s0, &s0, &rk0)
		xorBlock(&s1, &s1, &rk1)
		if step > 0 {
			xorBlock(&s0, &s0, (*Block)(&vistrutahRoundConstants[step-1]))
		}
	}

	copy(dst[0:16], s0[:])
	copy(dst[16:32], s1[:])
	clear(s0[:])
	clear(s1[:])
	clear(fk0[:])
	clear(fk1[:])
	clear(rk0[:])
	clear(rk1[:])
	clear(q[:])
	clear(qFK[:])
	runtime.KeepAlive(&s0)
	runtime.KeepAlive(&s1)
	runtime.KeepAlive(&fk0)
	runtime.KeepAlive(&fk1)
	runtime.KeepAlive(&rk0)
	runtime.KeepAlive(&rk1)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&qFK)
}

func vistrutah256DecryptBlockSoft(dst, src, key *[32]byte, rounds int) {
	vistrutah256DecryptBlockSoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func vistrutah256Encrypt4BlocksSoftBody(dst, src *[4][32]byte, key *[32]byte, rounds int) {
	steps := rounds / 2
	if steps < 1 || steps > 16 {
		return
	}
	var s0, s1 [4]Block
	for lane := 0; lane < 4; lane++ {
		copy(s0[lane][:], src[lane][0:16])
		copy(s1[lane][:], src[lane][16:32])
	}
	var fk0, fk1, rk0, rk1, rk0rc Block
	copy(fk0[:], key[0:16])
	copy(fk1[:], key[16:32])
	rk0 = fk1
	rk1 = fk0

	var q0, q1, qFK0, qFK1 bsState
	bsPackBroadcast(&qFK0, &fk0)
	bsPackBroadcast(&qFK1, &fk1)

	for step := 0; step < steps; step++ {
		rk0rc = rk0
		if step > 0 {
			xorBlock(&rk0rc, &rk0rc, (*Block)(&vistrutahRoundConstants[step-1]))
		}
		for lane := 0; lane < 4; lane++ {
			xorBlock(&s0[lane], &s0[lane], &rk0rc)
			xorBlock(&s1[lane], &s1[lane], &rk1)
		}
		bsPack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsPack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
		bsRoundNoKey(&q0)
		bsRoundNoKey(&q1)
		bsXor(&q0, &qFK0)
		bsXor(&q1, &qFK1)
		if step < steps-1 {
			bsRoundNoKey(&q0)
			bsRoundNoKey(&q1)
			bsUnpack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
			bsUnpack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
			for lane := 0; lane < 4; lane++ {
				vistrutah256MixFwd(&s0[lane], &s1[lane])
			}
			vistrutah256StepRho(&rk0, &rk1)
		} else {
			bsFinalRoundNoKey(&q0)
			bsFinalRoundNoKey(&q1)
			bsUnpack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
			bsUnpack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
			vistrutah256StepRho(&rk0, &rk1)
			for lane := 0; lane < 4; lane++ {
				xorBlock((*Block)(dst[lane][0:16]), &s0[lane], &rk0)
				xorBlock((*Block)(dst[lane][16:32]), &s1[lane], &rk1)
			}
		}
	}

	clear(s0[:])
	clear(s1[:])
	clear(fk0[:])
	clear(fk1[:])
	clear(rk0[:])
	clear(rk1[:])
	clear(rk0rc[:])
	clear(q0[:])
	clear(q1[:])
	clear(qFK0[:])
	clear(qFK1[:])
	runtime.KeepAlive(&s0)
	runtime.KeepAlive(&s1)
	runtime.KeepAlive(&fk0)
	runtime.KeepAlive(&fk1)
	runtime.KeepAlive(&rk0)
	runtime.KeepAlive(&rk1)
	runtime.KeepAlive(&rk0rc)
	runtime.KeepAlive(&q0)
	runtime.KeepAlive(&q1)
	runtime.KeepAlive(&qFK0)
	runtime.KeepAlive(&qFK1)
}

func vistrutah256Encrypt4BlocksSoft(dst, src *[4][32]byte, key *[32]byte, rounds int) {
	vistrutah256Encrypt4BlocksSoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func vistrutah256Decrypt4BlocksSoftBody(dst, src *[4][32]byte, key *[32]byte, rounds int) {
	steps := rounds / 2
	if steps < 1 || steps > 16 {
		return
	}
	var s0, s1 [4]Block
	for lane := 0; lane < 4; lane++ {
		copy(s0[lane][:], src[lane][0:16])
		copy(s1[lane][:], src[lane][16:32])
	}
	var fk0, fk1, rk0, rk1, rk0rc Block
	copy(fk0[:], key[0:16])
	copy(fk1[:], key[16:32])
	rk0 = fk1
	rk1 = fk0
	for step := 0; step < steps; step++ {
		vistrutah256StepRho(&rk0, &rk1)
	}

	var q0, q1, qFK0, qFK1 bsState
	bsPackBroadcast(&qFK0, &fk0)
	bsPackBroadcast(&qFK1, &fk1)

	for step := steps - 1; step >= 0; step-- {
		if step == steps-1 {
			for lane := 0; lane < 4; lane++ {
				xorBlock(&s0[lane], &s0[lane], &rk0)
				xorBlock(&s1[lane], &s1[lane], &rk1)
			}
			bsPack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
			bsPack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
			bsInvFinalRoundNoKey(&q0)
			bsInvFinalRoundNoKey(&q1)
		} else {
			for lane := 0; lane < 4; lane++ {
				vistrutah256MixInv(&s0[lane], &s1[lane])
			}
			bsPack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
			bsPack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
			bsInvMixColumns(&q0)
			bsInvMixColumns(&q1)
			bsInvFinalRoundNoKey(&q0)
			bsInvFinalRoundNoKey(&q1)
		}
		vistrutah256StepRhoInv(&rk0, &rk1)
		bsXor(&q0, &qFK0)
		bsXor(&q1, &qFK1)
		bsInvMixColumns(&q0)
		bsInvMixColumns(&q1)
		bsInvFinalRoundNoKey(&q0)
		bsInvFinalRoundNoKey(&q1)
		bsUnpack4(&q0, &s0[0], &s0[1], &s0[2], &s0[3])
		bsUnpack4(&q1, &s1[0], &s1[1], &s1[2], &s1[3])
		rk0rc = rk0
		if step > 0 {
			xorBlock(&rk0rc, &rk0rc, (*Block)(&vistrutahRoundConstants[step-1]))
		}
		for lane := 0; lane < 4; lane++ {
			xorBlock(&s0[lane], &s0[lane], &rk0rc)
			xorBlock(&s1[lane], &s1[lane], &rk1)
		}
	}

	for lane := 0; lane < 4; lane++ {
		copy(dst[lane][0:16], s0[lane][:])
		copy(dst[lane][16:32], s1[lane][:])
	}
	clear(s0[:])
	clear(s1[:])
	clear(fk0[:])
	clear(fk1[:])
	clear(rk0[:])
	clear(rk1[:])
	clear(rk0rc[:])
	clear(q0[:])
	clear(q1[:])
	clear(qFK0[:])
	clear(qFK1[:])
	runtime.KeepAlive(&s0)
	runtime.KeepAlive(&s1)
	runtime.KeepAlive(&fk0)
	runtime.KeepAlive(&fk1)
	runtime.KeepAlive(&rk0)
	runtime.KeepAlive(&rk1)
	runtime.KeepAlive(&rk0rc)
	runtime.KeepAlive(&q0)
	runtime.KeepAlive(&q1)
	runtime.KeepAlive(&qFK0)
	runtime.KeepAlive(&qFK1)
}

func vistrutah256Decrypt4BlocksSoft(dst, src *[4][32]byte, key *[32]byte, rounds int) {
	vistrutah256Decrypt4BlocksSoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func vistrutah512StepRho(rk *[4]Block) {
	var n [4]Block
	for i := 0; i < 16; i++ {
		n[0][i] = rk[0][(i+5)&15]
		n[1][i] = rk[1][(i+10)&15]
		n[2][i] = rk[2][(i+5)&15]
		n[3][i] = rk[3][(i+10)&15]
	}
	*rk = n
	clear(n[:])
	runtime.KeepAlive(&n)
}

func vistrutah512StepRhoInv(rk *[4]Block) {
	var n [4]Block
	for i := 0; i < 16; i++ {
		n[0][i] = rk[0][(i+11)&15]
		n[1][i] = rk[1][(i+6)&15]
		n[2][i] = rk[2][(i+11)&15]
		n[3][i] = rk[3][(i+6)&15]
	}
	*rk = n
	clear(n[:])
	runtime.KeepAlive(&n)
}

func vistrutah512MixFwd(s *[4]Block) {
	var flat, out [64]byte
	copy(flat[0:16], s[0][:])
	copy(flat[16:32], s[1][:])
	copy(flat[32:48], s[2][:])
	copy(flat[48:64], s[3][:])
	for i := 0; i < 64; i++ {
		out[i] = flat[vistrutahMix512[i]]
	}
	copy(s[0][:], out[0:16])
	copy(s[1][:], out[16:32])
	copy(s[2][:], out[32:48])
	copy(s[3][:], out[48:64])
	clear(flat[:])
	clear(out[:])
	runtime.KeepAlive(&flat)
	runtime.KeepAlive(&out)
}

func vistrutah512MixInv(s *[4]Block) {
	var flat, out [64]byte
	copy(flat[0:16], s[0][:])
	copy(flat[16:32], s[1][:])
	copy(flat[32:48], s[2][:])
	copy(flat[48:64], s[3][:])
	for i := 0; i < 64; i++ {
		out[i] = flat[vistrutahInvMix512[i]]
	}
	copy(s[0][:], out[0:16])
	copy(s[1][:], out[16:32])
	copy(s[2][:], out[32:48])
	copy(s[3][:], out[48:64])
	clear(flat[:])
	clear(out[:])
	runtime.KeepAlive(&flat)
	runtime.KeepAlive(&out)
}

//go:noinline
func vistrutah512EncryptBlockCore(dst, src *[64]byte, fk *[4]Block, rounds int) {
	steps := rounds / 2
	if steps < 1 || steps > 16 {
		return
	}
	var s, rk [4]Block
	for m := 0; m < 4; m++ {
		copy(s[m][:], src[m*16:m*16+16])
	}
	rk[0] = fk[1]
	rk[1] = fk[0]
	rk[2] = fk[3]
	rk[3] = fk[2]

	var q, qFK bsState
	bsPack4(&qFK, &fk[0], &fk[1], &fk[2], &fk[3])

	for step := 0; step < steps; step++ {
		for m := 0; m < 4; m++ {
			xorBlock(&s[m], &s[m], &rk[m])
		}
		if step > 0 {
			xorBlock(&s[0], &s[0], (*Block)(&vistrutahRoundConstants[step-1]))
		}
		bsPack4(&q, &s[0], &s[1], &s[2], &s[3])
		bsRoundNoKey(&q)
		bsXor(&q, &qFK)
		if step < steps-1 {
			bsRoundNoKey(&q)
			bsUnpack4(&q, &s[0], &s[1], &s[2], &s[3])
			vistrutah512MixFwd(&s)
			vistrutah512StepRho(&rk)
		} else {
			bsFinalRoundNoKey(&q)
			bsUnpack4(&q, &s[0], &s[1], &s[2], &s[3])
			vistrutah512StepRho(&rk)
			for m := 0; m < 4; m++ {
				xorBlock((*Block)(dst[m*16:m*16+16]), &s[m], &rk[m])
			}
		}
	}

	clear(s[:])
	clear(rk[:])
	clear(q[:])
	clear(qFK[:])
	runtime.KeepAlive(&s)
	runtime.KeepAlive(&rk)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&qFK)
}

//go:noinline
func vistrutah512DecryptBlockCore(dst, src *[64]byte, fk *[4]Block, rounds int) {
	steps := rounds / 2
	if steps < 1 || steps > 16 {
		return
	}
	var s, rk [4]Block
	for m := 0; m < 4; m++ {
		copy(s[m][:], src[m*16:m*16+16])
	}
	rk[0] = fk[1]
	rk[1] = fk[0]
	rk[2] = fk[3]
	rk[3] = fk[2]
	for step := 0; step < steps; step++ {
		vistrutah512StepRho(&rk)
	}

	var q, qFK bsState
	bsPack4(&qFK, &fk[0], &fk[1], &fk[2], &fk[3])

	for step := steps - 1; step >= 0; step-- {
		if step == steps-1 {
			for m := 0; m < 4; m++ {
				xorBlock(&s[m], &s[m], &rk[m])
			}
			bsPack4(&q, &s[0], &s[1], &s[2], &s[3])
			bsInvFinalRoundNoKey(&q)
		} else {
			vistrutah512MixInv(&s)
			bsPack4(&q, &s[0], &s[1], &s[2], &s[3])
			bsInvMixColumns(&q)
			bsInvFinalRoundNoKey(&q)
		}
		vistrutah512StepRhoInv(&rk)
		bsXor(&q, &qFK)
		bsInvMixColumns(&q)
		bsInvFinalRoundNoKey(&q)
		bsUnpack4(&q, &s[0], &s[1], &s[2], &s[3])
		for m := 0; m < 4; m++ {
			xorBlock(&s[m], &s[m], &rk[m])
		}
		if step > 0 {
			xorBlock(&s[0], &s[0], (*Block)(&vistrutahRoundConstants[step-1]))
		}
	}

	for m := 0; m < 4; m++ {
		copy(dst[m*16:m*16+16], s[m][:])
	}
	clear(s[:])
	clear(rk[:])
	clear(q[:])
	clear(qFK[:])
	runtime.KeepAlive(&s)
	runtime.KeepAlive(&rk)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&qFK)
}

func vistrutah512ExpandFixedKey256(key *[32]byte, fk *[4]Block) {
	copy(fk[0][:], key[0:16])
	copy(fk[1][:], key[16:32])
	for i := 0; i < 16; i++ {
		fk[2][i] = key[vistrutahPsi[i]]
		fk[3][i] = key[vistrutahPsi[16+i]]
	}
}

func vistrutah512ExpandFixedKey512(key *[64]byte, fk *[4]Block) {
	for m := 0; m < 4; m++ {
		copy(fk[m][:], key[m*16:m*16+16])
	}
}

//go:noinline
func vistrutah512EncryptBlock256SoftBody(dst, src *[64]byte, key *[32]byte, rounds int) {
	var fk [4]Block
	vistrutah512ExpandFixedKey256(key, &fk)
	vistrutah512EncryptBlockCore(dst, src, &fk, rounds)
	clear(fk[:])
	runtime.KeepAlive(&fk)
}

func vistrutah512EncryptBlock256Soft(dst, src *[64]byte, key *[32]byte, rounds int) {
	vistrutah512EncryptBlock256SoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func vistrutah512DecryptBlock256SoftBody(dst, src *[64]byte, key *[32]byte, rounds int) {
	var fk [4]Block
	vistrutah512ExpandFixedKey256(key, &fk)
	vistrutah512DecryptBlockCore(dst, src, &fk, rounds)
	clear(fk[:])
	runtime.KeepAlive(&fk)
}

func vistrutah512DecryptBlock256Soft(dst, src *[64]byte, key *[32]byte, rounds int) {
	vistrutah512DecryptBlock256SoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func vistrutah512EncryptBlock512SoftBody(dst, src, key *[64]byte, rounds int) {
	var fk [4]Block
	vistrutah512ExpandFixedKey512(key, &fk)
	vistrutah512EncryptBlockCore(dst, src, &fk, rounds)
	clear(fk[:])
	runtime.KeepAlive(&fk)
}

func vistrutah512EncryptBlock512Soft(dst, src, key *[64]byte, rounds int) {
	vistrutah512EncryptBlock512SoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func vistrutah512DecryptBlock512SoftBody(dst, src, key *[64]byte, rounds int) {
	var fk [4]Block
	vistrutah512ExpandFixedKey512(key, &fk)
	vistrutah512DecryptBlockCore(dst, src, &fk, rounds)
	clear(fk[:])
	runtime.KeepAlive(&fk)
}

func vistrutah512DecryptBlock512Soft(dst, src, key *[64]byte, rounds int) {
	vistrutah512DecryptBlock512SoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func vistrutah512Encrypt4Blocks256SoftBody(dst, src *[4][64]byte, key *[32]byte, rounds int) {
	var fk [4]Block
	vistrutah512ExpandFixedKey256(key, &fk)
	for lane := 0; lane < 4; lane++ {
		vistrutah512EncryptBlockCore(&dst[lane], &src[lane], &fk, rounds)
	}
	clear(fk[:])
	runtime.KeepAlive(&fk)
}

func vistrutah512Encrypt4Blocks256Soft(dst, src *[4][64]byte, key *[32]byte, rounds int) {
	vistrutah512Encrypt4Blocks256SoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func vistrutah512Decrypt4Blocks256SoftBody(dst, src *[4][64]byte, key *[32]byte, rounds int) {
	var fk [4]Block
	vistrutah512ExpandFixedKey256(key, &fk)
	for lane := 0; lane < 4; lane++ {
		vistrutah512DecryptBlockCore(&dst[lane], &src[lane], &fk, rounds)
	}
	clear(fk[:])
	runtime.KeepAlive(&fk)
}

func vistrutah512Decrypt4Blocks256Soft(dst, src *[4][64]byte, key *[32]byte, rounds int) {
	vistrutah512Decrypt4Blocks256SoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func vistrutah512Encrypt4Blocks512SoftBody(dst, src *[4][64]byte, key *[64]byte, rounds int) {
	var fk [4]Block
	vistrutah512ExpandFixedKey512(key, &fk)
	for lane := 0; lane < 4; lane++ {
		vistrutah512EncryptBlockCore(&dst[lane], &src[lane], &fk, rounds)
	}
	clear(fk[:])
	runtime.KeepAlive(&fk)
}

func vistrutah512Encrypt4Blocks512Soft(dst, src *[4][64]byte, key *[64]byte, rounds int) {
	vistrutah512Encrypt4Blocks512SoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func vistrutah512Decrypt4Blocks512SoftBody(dst, src *[4][64]byte, key *[64]byte, rounds int) {
	var fk [4]Block
	vistrutah512ExpandFixedKey512(key, &fk)
	for lane := 0; lane < 4; lane++ {
		vistrutah512DecryptBlockCore(&dst[lane], &src[lane], &fk, rounds)
	}
	clear(fk[:])
	runtime.KeepAlive(&fk)
}

func vistrutah512Decrypt4Blocks512Soft(dst, src *[4][64]byte, key *[64]byte, rounds int) {
	vistrutah512Decrypt4Blocks512SoftBody(dst, src, key, rounds)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

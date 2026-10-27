//go:build amd64 && !purego

package areion

import "golang.org/x/sys/cpu"

func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)

// hasVAESBit reads the VAES bit (CPUID leaf 7, ECX bit 9) directly.
// golang.org/x/sys/cpu only reports it when AVX-512 is enabled, but the
// YMM kernels need only AVX2, and CPUs such as AMD Zen 3 and Intel
// Alder Lake have VAES without AVX-512.
// HasAVX2 implies that leaf 7 exists and that the OS saves YMM registers.
func hasVAESBit() bool {
	if !cpu.X86.HasAVX2 {
		return false
	}
	_, _, ecx7, _ := cpuid(7, 0)
	return ecx7&(1<<9) != 0
}

func probeCPU() (aesni, vex, armCrypto, vaesAVX2, avx512 bool) {
	aesni = cpu.X86.HasAES
	vex = cpu.X86.HasAES && cpu.X86.HasAVX
	vaesAVX2 = hasVAESBit()
	avx512 = cpu.X86.HasAVX512F && cpu.X86.HasAVX512DQ && cpu.X86.HasAVX512BW && cpu.X86.HasAVX512VL && vaesAVX2
	return
}

package areion

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// Hardware acceleration tier constants.
const (
	TierPureGo    int32 = 0
	TierAESNI     int32 = 1
	TierVEX       int32 = 2
	TierVAESAVX2  int32 = 3
	TierAVX512    int32 = 4
	TierARMCrypto int32 = 5
)

// Hardware capability flags detected at initialization (read-only after init).
var (
	hasAESNI     bool
	hasVEX       bool // 128-bit VEX-encoded VAESENC on XMM (requires AVX + AES-NI)
	hasARMCrypto bool
	hasVAESAVX2  bool // VAES on 256-bit YMM (requires VAES + AVX2, independent of AVX-512)
	hasAVX512    bool // VAES on 512-bit ZMM (requires VAES + AVX-512F)
)

var (
	tierMu         sync.Mutex
	activeTierCode int32
)

func init() {
	hasAESNI, hasVEX, hasARMCrypto, hasVAESAVX2, hasAVX512 = probeCPU()
	_ = setTierLocked("auto")
	applyEnvTier()
}

func setTierLocked(tier string) error {
	normalized := strings.ToLower(strings.TrimSpace(tier))
	switch normalized {
	case "auto":
		if hasAVX512 {
			atomic.StoreInt32(&activeTierCode, TierAVX512)
		} else if hasVAESAVX2 {
			atomic.StoreInt32(&activeTierCode, TierVAESAVX2)
		} else if hasVEX {
			atomic.StoreInt32(&activeTierCode, TierVEX)
		} else if hasAESNI {
			atomic.StoreInt32(&activeTierCode, TierAESNI)
		} else if hasARMCrypto {
			atomic.StoreInt32(&activeTierCode, TierARMCrypto)
		} else {
			atomic.StoreInt32(&activeTierCode, TierPureGo)
		}
		return nil
	case "avx512":
		if !hasAVX512 {
			return fmt.Errorf("host CPU lacks AVX-512F + VAES")
		}
		atomic.StoreInt32(&activeTierCode, TierAVX512)
	case "vaesavx2":
		if !hasVAESAVX2 {
			return fmt.Errorf("host CPU lacks AVX2 + VAES")
		}
		atomic.StoreInt32(&activeTierCode, TierVAESAVX2)
	case "vex":
		if !hasVEX {
			return fmt.Errorf("host CPU lacks AVX + AES-NI")
		}
		atomic.StoreInt32(&activeTierCode, TierVEX)
	case "aesni":
		if !hasAESNI {
			return fmt.Errorf("host CPU lacks AES-NI")
		}
		atomic.StoreInt32(&activeTierCode, TierAESNI)
	case "arm64", "neon", "sve", "sve2":
		if !hasARMCrypto {
			return fmt.Errorf("host CPU lacks ARM Cryptographic Extension")
		}
		atomic.StoreInt32(&activeTierCode, TierARMCrypto)
	case "purego", "purec", "scalar", "gpr":
		atomic.StoreInt32(&activeTierCode, TierPureGo)
	default:
		return fmt.Errorf("unknown tier %q (want: avx512, vaesavx2, vex, aesni, arm64/neon/sve/sve2, purego/purec/scalar, auto)", tier)
	}
	return nil
}

func applyEnvTier() {
	env := os.Getenv("AREION_FORCE_TIER")
	envName := "AREION_FORCE_TIER"
	if env == "" {
		env = os.Getenv("ASURA_FORCE_TIER")
		envName = "ASURA_FORCE_TIER"
	}
	if env != "" {
		if err := SetTier(env); err != nil {
			fmt.Fprintf(os.Stderr, "areion: invalid %s=%q: %v\n", envName, env, err)
		}
	}
}

// Tier returns the currently active hardware acceleration tier name:
// "avx512", "vaesavx2", "vex", "aesni", "arm64", or "purego".
func Tier() string {
	switch TierCode() {
	case TierAVX512:
		return "avx512"
	case TierVAESAVX2:
		return "vaesavx2"
	case TierVEX:
		return "vex"
	case TierAESNI:
		return "aesni"
	case TierARMCrypto:
		return "arm64"
	default:
		return "purego"
	}
}

// TierCode returns the integer code of the active hardware tier:
// TierPureGo (0), TierAESNI (1), TierVEX (2), TierVAESAVX2 (3), TierAVX512 (4), TierARMCrypto (5).
func TierCode() int32 {
	return atomic.LoadInt32(&activeTierCode)
}

// SetTier forces the active acceleration tier. Valid values:
//   - "avx512": requires AVX-512F + VAES
//   - "vaesavx2": requires AVX2 + VAES (256-bit YMM)
//   - "vex": requires AVX + AES-NI (128-bit XMM 3-operand VEX)
//   - "aesni": requires AES-NI (x86-64 legacy 2-operand)
//   - "arm64", "neon", "sve", "sve2": requires ARMv8 Cryptographic Extension
//   - "purego", "purec", "scalar", "gpr": portable Go software fallback
//   - "auto": restores natural hardware detection
//
// The active tier can also be overridden at process startup via the
// AREION_FORCE_TIER or ASURA_FORCE_TIER environment variables.
func SetTier(tier string) error {
	tierMu.Lock()
	defer tierMu.Unlock()
	return setTierLocked(tier)
}

// UseHardwareAcceleration reports whether hardware AES acceleration is available
// and currently enabled (i.e. the active tier is not purego).
func UseHardwareAcceleration() bool {
	return (hasAESNI || hasARMCrypto) && TierCode() != TierPureGo
}

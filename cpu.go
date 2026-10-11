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
	TierARMCrypto int32 = 1
	TierVAESAVX2  int32 = 2
	TierAVX512    int32 = 3
)

// Hardware capability flags detected at initialization (read-only after init).
var (
	hasAESNI     bool
	hasARMCrypto bool
	hasVAESAVX2  bool // VAES on 256-bit YMM (requires VAES + AVX2, independent of AVX-512)
	hasAVX512    bool // VAES on 512-bit ZMM (requires VAES + AVX-512F)
)

var (
	tierMu         sync.Mutex
	activeTierName string
	activeTierCode int32
)

func init() {
	hasAESNI, hasARMCrypto, hasVAESAVX2, hasAVX512 = probeCPU()
	_ = setTierLocked("auto")
	applyEnvTier()
}

func setTierLocked(tier string) error {
	normalized := strings.ToLower(strings.TrimSpace(tier))
	switch normalized {
	case "auto":
		if hasAVX512 {
			activeTierName = "avx512"
			atomic.StoreInt32(&activeTierCode, TierAVX512)
		} else if hasVAESAVX2 {
			activeTierName = "vaesavx2"
			atomic.StoreInt32(&activeTierCode, TierVAESAVX2)
		} else if hasAESNI {
			activeTierName = "aesni"
			atomic.StoreInt32(&activeTierCode, TierAESNI)
		} else if hasARMCrypto {
			activeTierName = "arm64"
			atomic.StoreInt32(&activeTierCode, TierARMCrypto)
		} else {
			activeTierName = "purego"
			atomic.StoreInt32(&activeTierCode, TierPureGo)
		}
		return nil
	case "avx512":
		if !hasAVX512 {
			return fmt.Errorf("host CPU lacks AVX-512F + VAES")
		}
		activeTierName = "avx512"
		atomic.StoreInt32(&activeTierCode, TierAVX512)
	case "vaesavx2":
		if !hasVAESAVX2 {
			return fmt.Errorf("host CPU lacks AVX2 + VAES")
		}
		activeTierName = "vaesavx2"
		atomic.StoreInt32(&activeTierCode, TierVAESAVX2)
	case "aesni":
		if !hasAESNI {
			return fmt.Errorf("host CPU lacks AES-NI")
		}
		activeTierName = "aesni"
		atomic.StoreInt32(&activeTierCode, TierAESNI)
	case "arm64", "neon", "sve", "sve2":
		if !hasARMCrypto {
			return fmt.Errorf("host CPU lacks ARM Cryptographic Extension")
		}
		activeTierName = "arm64"
		atomic.StoreInt32(&activeTierCode, TierARMCrypto)
	case "purego", "scalar", "gpr":
		activeTierName = "purego"
		atomic.StoreInt32(&activeTierCode, TierPureGo)
	default:
		return fmt.Errorf("unknown tier %q (want: avx512, vaesavx2, aesni, arm64/neon/sve/sve2, purego/scalar, auto)", tier)
	}
	return nil
}

func applyEnvTier() {
	if val := os.Getenv("AREION_FORCE_TIER"); val != "" {
		if err := SetTier(val); err != nil {
			fmt.Fprintf(os.Stderr, "areion: invalid AREION_FORCE_TIER=%q: %v\n", val, err)
		}
	}
}

// Tier returns the currently active hardware acceleration tier name:
// "avx512", "vaesavx2", "aesni", "arm64", or "purego".
func Tier() string {
	tierMu.Lock()
	defer tierMu.Unlock()
	return activeTierName
}

// TierCode returns the integer code of the active hardware tier:
// TierPureGo (0), TierAESNI / TierARMCrypto (1), TierVAESAVX2 (2), TierAVX512 (3).
func TierCode() int32 {
	return atomic.LoadInt32(&activeTierCode)
}

// SetTier forces the active acceleration tier. Valid values:
//   - "avx512": requires AVX-512F + VAES
//   - "vaesavx2": requires AVX2 + VAES (256-bit YMM)
//   - "aesni": requires AES-NI (x86-64)
//   - "arm64", "neon", "sve", "sve2": requires ARMv8 Cryptographic Extension
//   - "purego", "scalar", "gpr": portable Go software fallback
//   - "auto": restores natural hardware detection
func SetTier(tier string) error {
	tierMu.Lock()
	defer tierMu.Unlock()
	return setTierLocked(tier)
}

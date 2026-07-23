package tls

// OS-family inference for QOSF.
//
// The OS signal in a QUIC flow is the kernel initial TTL / hop-limit on the UDP
// datagram (QOSF segment A) — NOT the transport parameters, which fingerprint the
// userspace library. So inferOS keys on the inferred initial TTL and reports an
// OS *family* with candidate OSes and a confidence, never a hard label:
//   - 128 → Windows (moderate; the Windows default, rare elsewhere)
//   - 64  → Unix-like: Linux / Android / macOS / iOS / BSD (low; TTL alone can't
//           separate them — they all default to 64)
//   - 255 → network gear / Unix server (low)
//   - 32  → legacy Windows / embedded (low)
//   - none observed (socket-only) → unknown
// The TTL is client-settable and hop count varies, so every result carries a
// spoofable caveat. This is a passive hint, not proof.

import (
	"fmt"
	"strings"

	"github.com/pagpeter/trackme/pkg/types"
)

// inferInitialTTL rounds an observed TTL/hop-limit up to the nearest common
// initial value {32,64,128,255}; 0 if unobservable.
func inferInitialTTL(ttl int) int {
	switch {
	case ttl <= 0:
		return 0
	case ttl <= 32:
		return 32
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	case ttl <= 255:
		return 255
	default:
		return 0
	}
}

// inferOS derives an OS-family guess from the observed kernel TTL (and, where a
// stack maps cleanly to an OS, the stack). kern == nil → unknown (no TTL seen).
func inferOS(kern *types.QOSFKernel, stack string) *types.QOSFOSGuess {
	if kern == nil {
		return &types.QOSFOSGuess{
			Family:     "unknown",
			Confidence: "none",
			Basis:      "No kernel TTL was observed (this QUIC flow was seen socket-only), so the OS cannot be inferred from the hop limit.",
		}
	}

	g := &types.QOSFOSGuess{}
	switch inferInitialTTL(kern.TTL) {
	case 128:
		g.Family = "Windows"
		g.Candidates = []string{"Windows"}
		g.Confidence = "moderate"
		g.Basis = fmt.Sprintf("Initial TTL 128 (observed %d) is the Windows default; few other clients use it.", kern.TTL)
	case 64:
		g.Family = "Unix-like"
		g.Candidates = []string{"Linux", "Android", "macOS", "iOS", "BSD"}
		g.Confidence = "low"
		g.Basis = fmt.Sprintf("Initial TTL 64 (observed %d) is shared by Linux, Android, macOS, iOS and BSD; the hop limit alone cannot separate them.", kern.TTL)
	case 255:
		g.Family = "Network gear / Unix server"
		g.Candidates = []string{"Solaris", "router/appliance", "some BSD"}
		g.Confidence = "low"
		g.Basis = fmt.Sprintf("Initial TTL 255 (observed %d) is typical of network appliances and some Unix servers.", kern.TTL)
	case 32:
		g.Family = "Legacy Windows / embedded"
		g.Candidates = []string{"legacy Windows", "embedded"}
		g.Confidence = "low"
		g.Basis = fmt.Sprintf("Initial TTL 32 (observed %d) points to legacy Windows or embedded stacks.", kern.TTL)
	default:
		g.Family = "unknown"
		g.Confidence = "none"
		g.Basis = fmt.Sprintf("Observed TTL %d does not map to a known initial value.", kern.TTL)
		return g
	}

	// Stack refinement: currently only Chromium is classified, and it is
	// cross-platform, so it does not narrow the OS. (When a stack that maps to an
	// OS is added — e.g. Apple's — narrow here.)
	if stack == "ch" {
		g.Basis += " The stack is Chromium (cross-platform), so it does not narrow the OS."
	}
	g.Basis += " Passive heuristic — the TTL is client-settable and hop count varies, so treat this as a hint, not proof."
	return g
}

// --- Cross-layer consistency: kernel OS (TTL) vs. User-Agent-claimed OS -------
//
// A userspace QUIC mimic (e.g. github.com/enetx/uquic) can forge the entire QUIC
// Initial — transport parameters, connection-ID lengths, GREASE, even Google's
// custom TPs — so segments B/C/D can be made byte-identical to a real browser.
// What it cannot forge is the kernel-written initial TTL (segment A). So if the
// User-Agent claims Windows (kernel would write TTL 128) but the observed kernel
// TTL is 64, the OS writing the packets is not the OS being presented. That is
// the signature of a userspace mimic — or a proxy / VPN, which also rewrites the
// hop limit; hence a signal, not proof.

// uaOSFamily parses the coarse OS family from a User-Agent, or "" if unknown.
// Order matters: Android/iOS UAs also contain "Linux"/"Mac OS X".
func uaOSFamily(ua string) string {
	u := strings.ToLower(ua)
	switch {
	case strings.Contains(u, "windows nt") || strings.Contains(u, "windows phone"):
		return "Windows"
	case strings.Contains(u, "cros "):
		return "ChromeOS"
	case strings.Contains(u, "android"):
		return "Android"
	case strings.Contains(u, "iphone") || strings.Contains(u, "ipad") || strings.Contains(u, "ipod"):
		return "iOS"
	case strings.Contains(u, "mac os x") || strings.Contains(u, "macintosh"):
		return "macOS"
	case strings.Contains(u, "linux") || strings.Contains(u, "x11"):
		return "Linux"
	default:
		return ""
	}
}

// expectedInitialTTL is the initial TTL/hop-limit the kernel of a claimed OS
// family writes: Windows = 128, every common Unix-like = 64.
func expectedInitialTTL(osFamily string) int {
	if osFamily == "Windows" {
		return 128
	}
	return 64 // macOS, iOS, Android, Linux, ChromeOS, BSD
}

// InferConsistency cross-checks the kernel-revealed OS (from the initial TTL)
// against the OS the User-Agent claims. QUIC is user-space, so a mimic can forge
// the whole QUIC fingerprint but not the kernel TTL — a mismatch flags a
// userspace QUIC mimic, a proxy, or a VPN.
func InferConsistency(kern *types.QOSFKernel, userAgent string) *types.QOSFConsistency {
	claimed := uaOSFamily(userAgent)
	if kern == nil || inferInitialTTL(kern.TTL) == 0 {
		return &types.QOSFConsistency{
			Verdict:   "unknown",
			ClaimedOS: claimed,
			Detail:    "No kernel TTL was observed (socket-only), so the OS writing the packets can't be cross-checked against the User-Agent.",
		}
	}
	kernelOS := inferOS(kern, "").Family
	if claimed == "" {
		return &types.QOSFConsistency{
			Verdict:  "unknown",
			KernelOS: kernelOS,
			Detail:   fmt.Sprintf("The kernel TTL points to %s, but the User-Agent has no recognizable OS to cross-check against.", kernelOS),
		}
	}
	got := inferInitialTTL(kern.TTL)
	if expectedInitialTTL(claimed) == got {
		return &types.QOSFConsistency{
			Verdict:   "consistent",
			ClaimedOS: claimed,
			KernelOS:  kernelOS,
			Detail:    fmt.Sprintf("The User-Agent claims %s and the kernel TTL (observed %d → initial %d) matches — no cross-layer mismatch.", claimed, kern.TTL, got),
		}
	}
	return &types.QOSFConsistency{
		Verdict:   "mismatch",
		ClaimedOS: claimed,
		KernelOS:  kernelOS,
		Detail: fmt.Sprintf(
			"The User-Agent claims %s (whose kernel writes an initial TTL of %d) but the observed kernel TTL is %d → initial %d (%s). QUIC runs in user space, so a mimic such as uQUIC can forge the whole QUIC fingerprint yet cannot forge the kernel TTL — this mismatch is consistent with a userspace QUIC mimic, a proxy, or a VPN.",
			claimed, expectedInitialTTL(claimed), kern.TTL, got, kernelOS),
	}
}

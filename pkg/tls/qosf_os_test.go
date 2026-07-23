package tls

import (
	"strings"
	"testing"

	"github.com/pagpeter/trackme/pkg/types"
)

func TestInferInitialTTL(t *testing.T) {
	cases := map[int]int{0: 0, 1: 32, 32: 32, 33: 64, 64: 64, 65: 128, 128: 128, 129: 255, 255: 255}
	for in, want := range cases {
		if got := inferInitialTTL(in); got != want {
			t.Errorf("inferInitialTTL(%d)=%d, want %d", in, got, want)
		}
	}
}

func TestInferOS(t *testing.T) {
	cases := []struct {
		name       string
		kern       *types.QOSFKernel
		stack      string
		family     string
		confidence string
		wantCand   string // one candidate that must be present ("" = none)
	}{
		{"windows", &types.QOSFKernel{TTL: 118}, "xx", "Windows", "moderate", "Windows"},
		{"unix64", &types.QOSFKernel{TTL: 50}, "ch", "Unix-like", "low", "macOS"},
		{"netgear", &types.QOSFKernel{TTL: 250}, "xx", "Network gear / Unix server", "low", "Solaris"},
		{"legacy32", &types.QOSFKernel{TTL: 30}, "xx", "Legacy Windows / embedded", "low", "embedded"},
		{"socket-only", nil, "xx", "unknown", "none", ""},
	}
	for _, c := range cases {
		got := inferOS(c.kern, c.stack)
		if got.Family != c.family {
			t.Errorf("%s: family=%q, want %q", c.name, got.Family, c.family)
		}
		if got.Confidence != c.confidence {
			t.Errorf("%s: confidence=%q, want %q", c.name, got.Confidence, c.confidence)
		}
		if got.Basis == "" {
			t.Errorf("%s: basis is empty", c.name)
		}
		if c.wantCand != "" {
			found := false
			for _, x := range got.Candidates {
				if x == c.wantCand {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: candidates %v missing %q", c.name, got.Candidates, c.wantCand)
			}
		}
	}
}

func TestInferOSChromiumNote(t *testing.T) {
	g := inferOS(&types.QOSFKernel{TTL: 50}, "ch")
	if !strings.Contains(g.Basis, "Chromium") {
		t.Errorf("Chromium stack should be noted in basis: %q", g.Basis)
	}
	// Every observed guess must carry the spoofable caveat.
	if !strings.Contains(g.Basis, "hint") {
		t.Errorf("basis should carry the spoofable caveat: %q", g.Basis)
	}
}

// TestQOSFCarriesOSGuess: the full pipeline attaches the OS guess. The golden
// (observed TTL 117 → initial 128) infers Windows.
func TestQOSFCarriesOSGuess(t *testing.T) {
	kern := &types.QOSFKernel{IPVersion: 4, TTL: 117, ECN: 2, DF: true, SCIDLen: 0}
	got := buildQOSF(goldenParams(), 0x00000001, "203.0.113.7:54321", kern, defaultStackTable)
	if got == nil || got.OS == nil {
		t.Fatal("QOSFDetails.OS not set")
	}
	if got.OS.Family != "Windows" {
		t.Errorf("golden (TTL 117) OS family = %q, want Windows", got.OS.Family)
	}
	// Socket-only → unknown.
	so := buildQOSF(goldenParams(), 0x00000001, "203.0.113.7:54321", nil, defaultStackTable)
	if so.OS == nil || so.OS.Family != "unknown" || so.OS.Confidence != "none" {
		t.Errorf("socket-only OS = %+v, want unknown/none", so.OS)
	}
}

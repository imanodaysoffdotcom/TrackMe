package tls

import (
	"strings"
	"testing"

	"github.com/pagpeter/trackme/pkg/types"
)

func TestUAOSFamily(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140":                  "Windows",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/150":            "macOS",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Safari/605":     "iOS",
		"Mozilla/5.0 (Linux; Android 13; Pixel) Chrome/140 Mobile":              "Android", // Android before Linux
		"Mozilla/5.0 (X11; Linux x86_64) Chrome/140":                           "Linux",
		"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) Chrome/140":                  "ChromeOS",
		"quic-go HTTP/3":                                                        "",
	}
	for ua, want := range cases {
		if got := uaOSFamily(ua); got != want {
			t.Errorf("uaOSFamily(%q)=%q, want %q", ua, got, want)
		}
	}
}

func TestInferConsistency(t *testing.T) {
	winUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140"
	macUA := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/150"
	androidUA := "Mozilla/5.0 (Linux; Android 13; Pixel) Chrome/140 Mobile"

	cases := []struct {
		name    string
		kern    *types.QOSFKernel
		ua      string
		verdict string
	}{
		{"windows-ua-ttl128-consistent", &types.QOSFKernel{TTL: 118}, winUA, "consistent"},
		{"windows-ua-ttl64-MISMATCH", &types.QOSFKernel{TTL: 50}, winUA, "mismatch"}, // uQUIC on Linux claiming Windows
		{"mac-ua-ttl64-consistent", &types.QOSFKernel{TTL: 50}, macUA, "consistent"},
		{"mac-ua-ttl128-MISMATCH", &types.QOSFKernel{TTL: 118}, macUA, "mismatch"},
		{"android-ua-ttl64-consistent", &types.QOSFKernel{TTL: 50}, androidUA, "consistent"},
		{"no-ua-unknown", &types.QOSFKernel{TTL: 50}, "quic-go HTTP/3", "unknown"},
		{"no-ttl-unknown", nil, winUA, "unknown"},
	}
	for _, c := range cases {
		got := InferConsistency(c.kern, c.ua)
		if got.Verdict != c.verdict {
			t.Errorf("%s: verdict=%q, want %q (detail: %s)", c.name, got.Verdict, c.verdict, got.Detail)
		}
		if got.Detail == "" {
			t.Errorf("%s: empty detail", c.name)
		}
	}
}

// TestConsistencyMismatchMentionsMimic ensures the mismatch detail names the
// userspace-mimic explanation (the uQUIC case this defends against).
func TestConsistencyMismatchMentionsMimic(t *testing.T) {
	got := InferConsistency(&types.QOSFKernel{TTL: 50}, "Mozilla/5.0 (Windows NT 10.0) Chrome/140")
	if got.Verdict != "mismatch" {
		t.Fatalf("verdict=%q, want mismatch", got.Verdict)
	}
	if !strings.Contains(got.Detail, "mimic") {
		t.Errorf("mismatch detail should explain the mimic case: %q", got.Detail)
	}
	if got.ClaimedOS != "Windows" || got.KernelOS != "Unix-like" {
		t.Errorf("claimed=%q kernel=%q, want Windows / Unix-like", got.ClaimedOS, got.KernelOS)
	}
}

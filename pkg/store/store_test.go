package store

import (
	"strings"
	"testing"

	"github.com/pagpeter/trackme/pkg/types"
)

func sampleRes() types.Response {
	return types.Response{
		IP: "1.2.3.4:55123", HTTPVersion: "h2", UserAgent: "UA/1", Path: "/api/all",
		TLS:   &types.TLSDetails{ClientRandom: "abcd1234", JA4: "t13d", PeetPrint: "pp", PeetPrintHash: "h"},
		Http2: &types.Http2Details{AkamaiFingerprint: "ak"},
		SPHBI: &types.SPHBIDetails{Kind: "ipv4", Hex: "00aa", Bits: "0101", Size: 12},
	}
}

func TestConnKeyUsesClientRandom(t *testing.T) {
	if got := ConnKey(sampleRes()); got != "abcd1234" {
		t.Fatalf("want abcd1234, got %s", got)
	}
}

func TestConnKeyFallbackWhenNoTLS(t *testing.T) {
	r := sampleRes()
	r.TLS = nil
	got := ConnKey(r)
	if got == "" || got == "abcd1234" {
		t.Fatalf("expected non-empty fallback hash, got %q", got)
	}
}

func TestClientKeyStableAndIgnoresIP(t *testing.T) {
	a := sampleRes()
	b := sampleRes()
	b.IP = "9.9.9.9:1"
	b.TLS.ClientRandom = "different"
	ka, kb := ClientKey(a), ClientKey(b)
	if ka != kb {
		t.Fatalf("clientKey must ignore IP/ClientRandom: %s != %s", ka, kb)
	}
	if len(ka) != 64 {
		t.Fatalf("clientKey must be sha256 hex (64 chars), got %d", len(ka))
	}
}

func TestClientKeyChangesWithFingerprint(t *testing.T) {
	a := sampleRes()
	b := sampleRes()
	b.TLS.JA4 = "t13d-OTHER"
	if ClientKey(a) == ClientKey(b) {
		t.Fatal("clientKey must change when JA4 changes")
	}
}

func TestPortAndHostOf(t *testing.T) {
	if p := PortOf("1.2.3.4:55123"); p != "55123" {
		t.Fatalf("PortOf want 55123 got %s", p)
	}
	if h := HostOf("1.2.3.4:55123"); h != "1.2.3.4" {
		t.Fatalf("HostOf want 1.2.3.4 got %s", h)
	}
	// IPv6 literal
	if h := HostOf("[2606:4700::1]:443"); h != "2606:4700::1" {
		t.Fatalf("HostOf v6 want 2606:4700::1 got %s", h)
	}
}

func TestSummaryJSONRoundTrips(t *testing.T) {
	s := SummaryJSON(sampleRes(), 7, 2, 1700000000, 1699990000)
	for _, want := range []string{`"ja4":"t13d"`, `"visit_count":7`, `"ip_count":2`, `"user_agent":"UA/1"`, `"sphbi"`, `"bits":"0101"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary missing %s in %s", want, s)
		}
	}
}

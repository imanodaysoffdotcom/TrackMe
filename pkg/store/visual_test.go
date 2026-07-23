package store

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pagpeter/trackme/pkg/types"
)

// vaNode mirrors the JSON shape SPHBIByJA4 emits per graph node.
type vaNode struct {
	Bits      string   `json:"bits"`
	Kind      string   `json:"kind"`
	Size      int      `json:"size"`
	Labels    []string `json:"labels"`
	Count     int      `json:"count"`
	UserAgent string   `json:"user_agent"`
	ClientKey string   `json:"client_key"`
	Device    string   `json:"device"`
	OS        string   `json:"os"`
	OSVersion string   `json:"os_version"`
}

type vaResp struct {
	JA4           string   `json:"ja4"`
	Left          []vaNode `json:"left"`
	Right         []vaNode `json:"right"`
	LeftTotal     int      `json:"left_total"`
	RightTotal    int      `json:"right_total"`
	LeftTruncated bool     `json:"left_truncated"`
	RightTruncated bool    `json:"right_truncated"`
}

func TestSPHBIByJA4(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// One writeVisit per client: clientKey varies by ja4·UA·sphbiHex, so distinct
	// UAs keep clients distinct even when they share an image (kind:bits), which is
	// exactly the "same image across multiple scrapers/devices" dedup case.
	visit := func(ua, ja4, ip, path, kind, bits, hex string) {
		r := types.Response{
			IP: ip + ":5555", HTTPVersion: "h2", Method: "GET", Path: path, UserAgent: ua,
			TLS: &types.TLSDetails{
				JA3: "ja3", JA3Hash: "ja3h", JA4: ja4, JA4_r: ja4 + "_r",
				PeetPrint: "pp", PeetPrintHash: "pph", ClientRandom: ua, // ClientRandom unique per client
			},
			Http2: &types.Http2Details{AkamaiFingerprint: "ak", AkamaiFingerprintHash: "akh"},
		}
		if bits != "" {
			r.SPHBI = &types.SPHBIDetails{Kind: kind, Bits: bits, Size: 12, Hex: hex}
		}
		if err := s.writeVisit(ctx, r); err != nil {
			t.Fatalf("writeVisit: %v", err)
		}
	}

	const T = "t13d_target"
	bs := "/?scraping-header=browserstack-device-sweep&os=android"
	// LEFT (scrapers)
	visit("u1", T, "1.0.0.1", "/?scraping-header=alpha", "ipv4", "AAA", "ha")
	visit("u2", T, "1.0.0.2", "/?scraping-header=beta", "ipv4", "BBB", "hb")
	visit("u3", T, "1.0.0.3", "/?scraping-header=alpha", "ipv4", "AAA", "ha") // dup image+scraper of u1
	visit("u4", T, "1.0.0.4", "/?scraping-header=gamma", "ipv4", "AAA", "ha") // image AAA, scraper gamma
	// RIGHT (browserstack devices)
	visit("u5", T, "1.0.0.5", bs+"&os_version=15.0&device=Pixel+9", "ipv4", "CCC", "hc")
	visit("u6", T, "1.0.0.6", bs+"&os_version=14.0&device=Galaxy+S24", "ipv4", "DDD", "hd")
	visit("u7", T, "1.0.0.7", bs+"&os_version=14.0&device=Pixel+8", "ipv4", "CCC", "hc") // image CCC shared with u5
	// IGNORED / EXCLUDED
	visit("u8", T, "1.0.0.8", "/", "ipv4", "EEE", "he")                                  // no scraping-header
	visit("u9", "t13d_other", "1.0.0.9", "/?scraping-header=alpha", "ipv4", "FFF", "hf") // different JA4
	visit("u10", T, "1.0.0.10", "/?scraping-header=delta", "", "", "")                   // no image

	out, err := s.SPHBIByJA4(ctx, T, 400)
	if err != nil {
		t.Fatalf("SPHBIByJA4: %v", err)
	}
	var r vaResp
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}

	if r.JA4 != T {
		t.Errorf("ja4 = %q, want %q", r.JA4, T)
	}
	if r.LeftTotal != 2 || len(r.Left) != 2 {
		t.Errorf("left: total=%d len=%d, want 2/2", r.LeftTotal, len(r.Left))
	}
	if r.RightTotal != 2 || len(r.Right) != 2 {
		t.Errorf("right: total=%d len=%d, want 2/2", r.RightTotal, len(r.Right))
	}
	if r.LeftTruncated || r.RightTruncated {
		t.Errorf("unexpected truncation: left=%v right=%v", r.LeftTruncated, r.RightTruncated)
	}

	// Helper: find a node by bits in a side.
	find := func(nodes []vaNode, bits string) *vaNode {
		for i := range nodes {
			if nodes[i].Bits == bits {
				return &nodes[i]
			}
		}
		return nil
	}
	labelSet := func(n *vaNode) map[string]bool {
		m := map[string]bool{}
		for _, l := range n.Labels {
			m[l] = true
		}
		return m
	}

	// LEFT image AAA: produced by scrapers alpha + gamma → 1 node, 2 distinct labels.
	if n := find(r.Left, "AAA"); n == nil {
		t.Error("left node AAA missing")
	} else {
		ls := labelSet(n)
		if !ls["alpha"] || !ls["gamma"] || len(n.Labels) != 2 {
			t.Errorf("AAA labels = %v, want {alpha,gamma}", n.Labels)
		}
		if n.Count != 2 {
			t.Errorf("AAA count = %d, want 2 (distinct scrapers)", n.Count)
		}
		if n.Kind != "ipv4" {
			t.Errorf("AAA kind = %q, want ipv4", n.Kind)
		}
	}
	// LEFT image BBB: only beta.
	if n := find(r.Left, "BBB"); n == nil || len(n.Labels) != 1 || n.Labels[0] != "beta" {
		t.Errorf("left node BBB wrong: %+v", n)
	}

	// RIGHT image CCC: produced by Pixel 9 + Pixel 8 → 1 node, 2 device labels.
	if n := find(r.Right, "CCC"); n == nil {
		t.Error("right node CCC missing")
	} else {
		ls := labelSet(n)
		if !ls["Pixel 9 · android 15.0"] || !ls["Pixel 8 · android 14.0"] {
			t.Errorf("CCC labels = %v, want the two device strings", n.Labels)
		}
		if n.Count != 2 {
			t.Errorf("CCC count = %d, want 2 devices", n.Count)
		}
	}
	// RIGHT image DDD: only Galaxy S24, and the representative device fields populate.
	if n := find(r.Right, "DDD"); n == nil {
		t.Error("right node DDD missing")
	} else if n.Device != "Galaxy S24" || n.OS != "android" || n.OSVersion != "14.0" {
		t.Errorf("DDD device fields = %q/%q/%q, want Galaxy S24/android/14.0", n.Device, n.OS, n.OSVersion)
	}

	// Excluded images never appear on either side.
	for _, bad := range []string{"EEE" /*no header*/, "FFF" /*other ja4*/} {
		if find(r.Left, bad) != nil || find(r.Right, bad) != nil {
			t.Errorf("excluded image %s leaked into output", bad)
		}
	}

	// A different JA4 yields empty sides (no error).
	out2, err := s.SPHBIByJA4(ctx, "t13d_other", 400)
	if err != nil {
		t.Fatal(err)
	}
	var r2 vaResp
	_ = json.Unmarshal(out2, &r2)
	if r2.LeftTotal != 1 || r2.RightTotal != 0 {
		t.Errorf("t13d_other: left=%d right=%d, want 1/0 (only the alpha scraper)", r2.LeftTotal, r2.RightTotal)
	}

	// Cap=1 truncates each side and flags it.
	out3, _ := s.SPHBIByJA4(ctx, T, 1)
	var r3 vaResp
	_ = json.Unmarshal(out3, &r3)
	if len(r3.Left) != 1 || !r3.LeftTruncated {
		t.Errorf("cap=1 left: len=%d trunc=%v, want 1/true", len(r3.Left), r3.LeftTruncated)
	}
	if len(r3.Right) != 1 || !r3.RightTruncated {
		t.Errorf("cap=1 right: len=%d trunc=%v, want 1/true", len(r3.Right), r3.RightTruncated)
	}
	// left_total/right_total report the TRUE distinct count even when truncated.
	if r3.LeftTotal != 2 || r3.RightTotal != 2 {
		t.Errorf("cap=1 totals: left=%d right=%d, want true 2/2", r3.LeftTotal, r3.RightTotal)
	}

	// cap is clamped to 400 max (honors the UI "capped at 400/side"); an absurd cap
	// must not un-cap and must not error.
	out4, err := s.SPHBIByJA4(ctx, T, 10_000_000)
	if err != nil {
		t.Fatalf("huge cap: %v", err)
	}
	var r4 vaResp
	_ = json.Unmarshal(out4, &r4)
	if r4.LeftTotal != 2 || r4.RightTotal != 2 || r4.LeftTruncated || r4.RightTruncated {
		t.Errorf("huge cap should behave like the 400 default, got left=%d/%v right=%d/%v",
			r4.LeftTotal, r4.LeftTruncated, r4.RightTotal, r4.RightTruncated)
	}
}

// TestJA4ImageSummary covers the Visual Analysis dropdown source: only JA4s that
// actually produce a non-empty graph (≥1 client with an SPHBI image AND a
// scraping-header label) appear, each with distinct-image counts per side, richest
// first. JA4s with no image, or images but no scraping-header, are excluded.
func TestJA4ImageSummary(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	visit := func(ua, ja4, ip, path, kind, bits, hex string) {
		r := types.Response{
			IP: ip + ":5555", HTTPVersion: "h2", Method: "GET", Path: path, UserAgent: ua,
			TLS: &types.TLSDetails{
				JA3: "ja3", JA3Hash: "ja3h", JA4: ja4, JA4_r: ja4 + "_r",
				PeetPrint: "pp", PeetPrintHash: "pph", ClientRandom: ua,
			},
			Http2: &types.Http2Details{AkamaiFingerprint: "ak", AkamaiFingerprintHash: "akh"},
		}
		if bits != "" {
			r.SPHBI = &types.SPHBIDetails{Kind: kind, Bits: bits, Size: 12, Hex: hex}
		}
		if err := s.writeVisit(ctx, r); err != nil {
			t.Fatalf("writeVisit: %v", err)
		}
	}
	bs := "/?scraping-header=browserstack-device-sweep&os=android"
	// "withboth": 1 scraper image + 2 distinct browserstack images → total 3.
	visit("w1", "withboth", "1.1.1.1", "/?scraping-header=alpha", "ipv4", "AAA", "ha")
	visit("w2", "withboth", "1.1.1.2", bs+"&os_version=15.0&device=Pixel+9", "ipv4", "BBB", "hb")
	visit("w3", "withboth", "1.1.1.3", bs+"&os_version=14.0&device=Galaxy+S24", "ipv4", "FFF", "hf")
	// "leftonly": 2 distinct scraper images → total 2.
	visit("l1", "leftonly", "2.2.2.1", "/?scraping-header=alpha", "ipv4", "CCC", "hc")
	visit("l2", "leftonly", "2.2.2.2", "/?scraping-header=beta", "ipv4", "DDD", "hd")
	// excluded: scraping-header but NO image.
	visit("n1", "noimage", "3.3.3.1", "/?scraping-header=alpha", "", "", "")
	// excluded: image but NO scraping-header.
	visit("u1", "nolabel", "4.4.4.1", "/", "ipv4", "EEE", "he")

	out, err := s.JA4ImageSummary(ctx)
	if err != nil {
		t.Fatalf("JA4ImageSummary: %v", err)
	}
	var list []struct {
		JA4   string `json:"ja4"`
		Left  int    `json:"left"`
		Right int    `json:"right"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if len(list) != 2 {
		t.Fatalf("got %d JA4s, want 2 (withboth + leftonly); excluded ones leaked: %s", len(list), out)
	}
	// Sorted richest-first: withboth(total 3) before leftonly(total 2).
	if list[0].JA4 != "withboth" || list[0].Left != 1 || list[0].Right != 2 {
		t.Errorf("list[0] = %+v, want {withboth 1 2}", list[0])
	}
	if list[1].JA4 != "leftonly" || list[1].Left != 2 || list[1].Right != 0 {
		t.Errorf("list[1] = %+v, want {leftonly 2 0}", list[1])
	}
	for _, e := range list {
		if e.JA4 == "noimage" || e.JA4 == "nolabel" {
			t.Errorf("excluded JA4 %q leaked into the dropdown source", e.JA4)
		}
	}
}

// TestSPHBIByJA4MultiDevicePerClient covers the case the main test misses: several
// BrowserStack devices that share UA+JA4+SPHBI collapse to ONE clientKey, so all their
// device paths sit in one :paths ZSET. Every distinct device must still get a label on
// the single (shared-image) right node — not just the first one.
func TestSPHBIByJA4MultiDevicePerClient(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	bs := "/?scraping-header=browserstack-device-sweep&os=android"
	// Same UA + JA4 + sphbi(hex) => one clientKey; distinct device paths => one :paths ZSET.
	mk := func(path string) {
		r := types.Response{
			IP: "5.5.5.5:5555", HTTPVersion: "h2", Method: "GET", Path: path, UserAgent: "shared-ua",
			TLS: &types.TLSDetails{
				JA3: "ja3", JA3Hash: "h", JA4: "t13d_multi", JA4_r: "r",
				PeetPrint: "pp", PeetPrintHash: "pph", ClientRandom: "shared-rnd",
			},
			Http2: &types.Http2Details{AkamaiFingerprint: "ak", AkamaiFingerprintHash: "akh"},
			SPHBI: &types.SPHBIDetails{Kind: "ipv4", Bits: "GGG", Size: 12, Hex: "hg"},
		}
		if err := s.writeVisit(ctx, r); err != nil {
			t.Fatalf("writeVisit: %v", err)
		}
	}
	mk(bs + "&os_version=15.0&device=Pixel+9")
	mk(bs + "&os_version=14.0&device=Galaxy+S24")
	mk(bs + "&os_version=15.0&device=Pixel+9") // duplicate device → still one label

	out, err := s.SPHBIByJA4(ctx, "t13d_multi", 400)
	if err != nil {
		t.Fatal(err)
	}
	var r vaResp
	_ = json.Unmarshal(out, &r)
	if r.RightTotal != 1 || len(r.Right) != 1 {
		t.Fatalf("right total=%d len=%d, want 1 (single shared image GGG)", r.RightTotal, len(r.Right))
	}
	n := r.Right[0]
	ls := map[string]bool{}
	for _, l := range n.Labels {
		ls[l] = true
	}
	if !ls["Pixel 9 · android 15.0"] || !ls["Galaxy S24 · android 14.0"] || len(n.Labels) != 2 {
		t.Errorf("multi-device node labels = %v, want both devices (deduped to 2)", n.Labels)
	}
	if n.Count != 2 {
		t.Errorf("multi-device node count = %d, want 2 distinct devices", n.Count)
	}
}

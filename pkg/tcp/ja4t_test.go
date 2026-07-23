package tcp

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Expected values are taken verbatim from FoxIO's reference implementation
// (github.com/FoxIO-LLC/ja4, rust/ja4/src/tcp.rs) and its snapshot test data
// (rust/ja4/src/snapshots/*.snap), cross-checked against the raw SYN headers
// with tshark (tcp.window_size_value / tcp.option_kind / tcp.options.mss_val /
// tcp.options.wscale.shift). These are the oracle: our output must match
// FoxIO byte-for-byte.
//
// Format: <window>_<option kinds, in order, dash-separated>_<mss>_<window scale>
// Absent MSS and absent window scale are both encoded as "0".
func TestCalculateJA4T(t *testing.T) {
	cases := []struct {
		name        string
		window      uint16
		optionKinds []uint8
		mss         int // -1 == MSS option absent
		windowScale int // -1 == window scale option absent
		want        string
	}{
		{
			// FoxIO doc/code example (rust/ja4/src/tcp.rs to_ja4t doc + latest.pcapng)
			name:        "linux_default",
			window:      64240,
			optionKinds: []uint8{2, 1, 3, 1, 1, 4},
			mss:         1460,
			windowScale: 8,
			want:        "64240_2-1-3-1-1-4_1460_8",
		},
		{
			// macos_tcp_flags.pcap: window 65535, EOL padding kinds 0,0 kept in order
			name:        "macos_with_eol_padding",
			window:      65535,
			optionKinds: []uint8{2, 1, 3, 1, 1, 8, 4, 0, 0},
			mss:         1460,
			windowScale: 6,
			want:        "65535_2-1-3-1-1-8-4-0-0_1460_6",
		},
		{
			// tls-alpn-h2.pcap: small MSS, EOL padding
			name:        "tls_alpn_h2",
			window:      65535,
			optionKinds: []uint8{2, 1, 3, 1, 1, 8, 4, 0, 0},
			mss:         1346,
			windowScale: 6,
			want:        "65535_2-1-3-1-1-8-4-0-0_1346_6",
		},
		{
			// gre-sample.pcap: window scale option present but its shift value is 0
			name:        "wscale_shift_zero",
			window:      5744,
			optionKinds: []uint8{2, 4, 8, 1, 3},
			mss:         1436,
			windowScale: 0,
			want:        "5744_2-4-8-1-3_1436_0",
		},
		{
			// https-connect.pcap
			name:        "https_connect",
			window:      29200,
			optionKinds: []uint8{2, 1, 1, 4, 1, 3},
			mss:         1460,
			windowScale: 7,
			want:        "29200_2-1-1-4-1-3_1460_7",
		},
		{
			// gre-erspan-vxlan.pcap: the absent-MSS / absent-window-scale / no-options
			// edge case. Empty options list -> empty middle field ("__"), MSS and
			// window scale both absent -> "0". Snapshot ja4t == "8192__0_0".
			name:        "no_options_absent_mss_and_wscale",
			window:      8192,
			optionKinds: []uint8{},
			mss:         -1,
			windowScale: -1,
			want:        "8192__0_0",
		},
		{
			// Absent window scale only (MSS present). Encodes wscale as "0".
			name:        "absent_wscale_only",
			window:      8192,
			optionKinds: []uint8{2, 1, 3, 1, 1, 8},
			mss:         1440,
			windowScale: -1,
			want:        "8192_2-1-3-1-1-8_1440_0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CalculateJA4T(tc.window, tc.optionKinds, tc.mss, tc.windowScale)
			if got != tc.want {
				t.Fatalf("CalculateJA4T(%d, %v, %d, %d) = %q, want %q",
					tc.window, tc.optionKinds, tc.mss, tc.windowScale, got, tc.want)
			}
		})
	}
}

// buildSYN assembles a minimal TCP SYN segment with the given window and raw
// option bytes so it can be parsed by gopacket exactly as a captured packet is.
func buildSYN(t *testing.T, window uint16, optBytes []byte) *layers.TCP {
	t.Helper()
	// Options must be padded to a 4-byte boundary for a valid data offset.
	for len(optBytes)%4 != 0 {
		optBytes = append(optBytes, 0x00)
	}
	dataOffsetWords := 5 + len(optBytes)/4
	hdr := make([]byte, 20)
	hdr[0], hdr[1] = 0xc0, 0x00 // src port
	hdr[2], hdr[3] = 0x01, 0xbb // dst port 443
	hdr[12] = byte(dataOffsetWords << 4)
	hdr[13] = 0x02 // SYN flag
	hdr[14] = byte(window >> 8)
	hdr[15] = byte(window & 0xff)
	full := append(hdr, optBytes...)

	tcp := &layers.TCP{}
	if err := tcp.DecodeFromBytes(full, gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("DecodeFromBytes: %v", err)
	}
	return tcp
}

// TestJA4TFromSYN exercises the gopacket-facing path end to end, including the
// EOL-padding recovery (gopacket records only the first EOL option and dumps the
// rest into tcp.Padding). Inputs are the raw TCP option bytes straight off the
// wire; expected outputs are FoxIO's oracle JA4T strings.
func TestJA4TFromSYN(t *testing.T) {
	cases := []struct {
		name     string
		window   uint16
		optBytes []byte
		want     string
	}{
		{
			// Real macOS SYN captured live from 99.189.176.45 hitting the deployed
			// server. Two trailing EOL bytes (00 00): FoxIO keeps both -> "...-4-0-0".
			// gopacket parses [2,1,3,1,1,8,4,0] + Padding=[00]; we must recover the 2nd 0.
			name:   "macos_real_syn_double_eol_padding",
			window: 65535,
			optBytes: []byte{
				0x02, 0x04, 0x05, 0xb4, // MSS 1460
				0x01,             // NOP
				0x03, 0x03, 0x06, // Window Scale 6
				0x01, 0x01, // NOP NOP
				0x08, 0x0a, 0x6a, 0xeb, 0x2c, 0xf1, 0x00, 0x00, 0x00, 0x00, // Timestamps
				0x04, 0x02, // SACK permitted
				0x00, 0x00, // two EOL bytes
			},
			want: "65535_2-1-3-1-1-8-4-0-0_1460_6",
		},
		{
			// Linux default (latest.pcapng-style): MSS,NOP,WScale,NOP,NOP,SACK-perm,
			// window 64240, MSS 1460, wscale 8, no EOL padding.
			name:   "linux_default_from_bytes",
			window: 64240,
			optBytes: []byte{
				0x02, 0x04, 0x05, 0xb4, // MSS 1460
				0x01,             // NOP
				0x03, 0x03, 0x08, // Window Scale 8
				0x01, 0x01, // NOP NOP
				0x04, 0x02, // SACK permitted
			},
			want: "64240_2-1-3-1-1-4_1460_8",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tcp := buildSYN(t, tc.window, tc.optBytes)
			got := JA4TFromSYN(tcp)
			if got != tc.want {
				t.Fatalf("JA4TFromSYN = %q, want %q (options=%v padding=% x)",
					got, tc.want, optionKindList(tcp), tcp.Padding)
			}
		})
	}
}

func optionKindList(tcp *layers.TCP) []uint8 {
	ks := make([]uint8, 0, len(tcp.Options))
	for _, o := range tcp.Options {
		ks = append(ks, uint8(o.OptionType))
	}
	return ks
}

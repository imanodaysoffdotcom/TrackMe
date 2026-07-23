package tcp

import (
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
)

// JA4T is FoxIO's passive TCP *client* fingerprint, computed from the client's
// TCP SYN packet (a TCP-layer fingerprint, distinct from the TLS ClientHello
// JA4). Reference: github.com/FoxIO-LLC/ja4 (rust/ja4/src/tcp.rs).
//
// Format:
//
//	<window size>_<TCP option kinds, in order, dash-separated>_<MSS>_<window scale>
//
// e.g. "64240_2-1-3-1-1-4_1460_8".
//
//   - window size: the raw 16-bit TCP window value from the SYN (pre-scaling), decimal.
//   - option kinds: every TCP option kind in header order, dash-separated. Nothing
//     is filtered (NOP=1 and EOL=0 padding are included). An empty option list
//     yields an empty middle field ("__").
//   - MSS: the MSS option value (kind 2) in decimal, or "0" if the option is absent.
//   - window scale: the window-scale *shift* (kind 3), or "0" if the option is absent.
//     (FoxIO does not distinguish an absent option from a present shift of 0.)
const ja4tAbsent = -1 // sentinel for an absent MSS / window-scale option

// CalculateJA4T builds the JA4T string from already-extracted SYN fields.
// Pass mss = -1 (ja4tAbsent) when the MSS option is absent, and
// windowScale = -1 when the window-scale option is absent; both render as "0",
// matching FoxIO's reference (mss.unwrap_or(0) / window_scale.unwrap_or(0)).
func CalculateJA4T(window uint16, optionKinds []uint8, mss int, windowScale int) string {
	opts := make([]string, len(optionKinds))
	for i, k := range optionKinds {
		opts[i] = strconv.Itoa(int(k))
	}

	if mss < 0 {
		mss = 0
	}
	if windowScale < 0 {
		windowScale = 0
	}

	var b strings.Builder
	b.WriteString(strconv.Itoa(int(window)))
	b.WriteByte('_')
	b.WriteString(strings.Join(opts, "-"))
	b.WriteByte('_')
	b.WriteString(strconv.Itoa(mss))
	b.WriteByte('_')
	b.WriteString(strconv.Itoa(windowScale))
	return b.String()
}

// JA4TFromSYN computes the JA4T fingerprint directly from a captured client SYN
// (a gopacket *layers.TCP). It extracts the window size, the TCP option kinds in
// order, the MSS (option kind 2) and the window-scale shift (option kind 3) from
// the option data, then defers to CalculateJA4T.
//
// Trailing End-of-Option-List (kind 0) padding: gopacket records only the FIRST
// EOL byte as an option and stuffs any further EOL/zero bytes into tcp.Padding,
// breaking out of its option loop. FoxIO's reference counts every option byte in
// the header, including all trailing EOL padding (e.g. macOS SYNs end in
// "...-4-0-0"). So we append one kind=0 per leftover padding byte to stay
// byte-for-byte compatible with FoxIO's published JA4T values.
func JA4TFromSYN(tcp *layers.TCP) string {
	kinds := make([]uint8, 0, len(tcp.Options)+len(tcp.Padding))
	mss := ja4tAbsent
	windowScale := ja4tAbsent

	for _, opt := range tcp.Options {
		kind := uint8(opt.OptionType)
		kinds = append(kinds, kind)

		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			// MSS is a 2-byte big-endian value.
			if mss == ja4tAbsent && len(opt.OptionData) >= 2 {
				mss = int(opt.OptionData[0])<<8 | int(opt.OptionData[1])
			}
		case layers.TCPOptionKindWindowScale:
			// Window scale carries a single shift byte.
			if windowScale == ja4tAbsent && len(opt.OptionData) >= 1 {
				windowScale = int(opt.OptionData[0])
			}
		}
	}

	// Recover EOL padding bytes gopacket split off after the first EOL option.
	for _, b := range tcp.Padding {
		kinds = append(kinds, uint8(b))
	}

	return CalculateJA4T(tcp.Window, kinds, mss, windowScale)
}

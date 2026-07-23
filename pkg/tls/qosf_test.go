package tls

import (
	"testing"

	"github.com/pagpeter/trackme/pkg/types"
)

// tp is a tiny helper to build a parsed transport parameter.
func tp(id uint64, valueHex string) types.QUICTransportParam {
	return types.QUICTransportParam{ID: id, Value: valueHex}
}

// goldenParams is a synthetic, fully-observed Chrome-like transport-parameter
// set in a deliberately shuffled (non-ascending) wire order. Values are QUIC
// varints: idle=30000, mudp=1472, mdata=15728640, sbidi=100, acid=4, adexp=3,
// madelay=25. 0x2ab2 is grease_quic_bit; 0xff02 is a reserved-GREASE id
// (0xff02 % 31 == 27). 0x0f is present but value is random (not in segment D).
func goldenParams() []types.QUICTransportParam {
	return []types.QUICTransportParam{
		tp(0x01, "80007530"), // idle 30000
		tp(0x2ab2, ""),       // grease_quic_bit
		tp(0x05, "4000"),
		tp(0x03, "45c0"), // mudp 1472
		tp(0x06, "4000"),
		tp(0x04, "80f00000"), // mdata 15728640
		tp(0x07, "4000"),
		tp(0x08, "4064"), // sbidi 100
		tp(0x09, "4064"),
		tp(0x0e, "04"),         // acid 4
		tp(0x0a, "03"),         // adexp 3
		tp(0x0b, "19"),         // madelay 25
		tp(0x0f, "abcdef0011"), // scid (random value)
		tp(0x20, "45c0"),
		tp(0xff02, "abcd"), // reserved GREASE
	}
}

// TestQOSFGoldenFullyObserved is the anchor: a fully-observed QUIC flow (packet
// tap present) yields the exact canonical record, segment by segment. Note the
// stack is "xx" (no verified signature registered) — that is the honest value,
// not the illustrative example's "ch".
func TestQOSFGoldenFullyObserved(t *testing.T) {
	kern := &types.QOSFKernel{
		IPVersion: 4, TTL: 117, ECN: 2 /*ECT0*/, DF: true, SCIDLen: 0,
		QUICVersion: 1, DCIDLen: 8,
	}
	got := buildQOSF(goldenParams(), 0x00000001, "203.0.113.7:54321", kern, nil)
	if got == nil {
		t.Fatal("buildQOSF returned nil for a full param set")
	}
	want := "q1401-_xx1sx00_01.03.04.05.06.07.08.09.0a.0b.0e.0f.20.2ab2.G_30000.4.25.3.1472.15728640.100"
	if got.QOSF != want {
		t.Errorf("QOSF mismatch\n got=%s\nwant=%s", got.QOSF, want)
	}
	if got.SegKernel != "q1401-" {
		t.Errorf("segment A = %q, want q1401-", got.SegKernel)
	}
	if got.SegStack != "xx1sx00" {
		t.Errorf("segment B = %q, want xx1sx00", got.SegStack)
	}
	if got.SegTPValues != "30000.4.25.3.1472.15728640.100" {
		t.Errorf("segment D = %q", got.SegTPValues)
	}
	if got.Source != "pcap+quic" {
		t.Errorf("source = %q, want pcap+quic", got.Source)
	}
}

// TestQOSFNoFabrication proves the no-fabrication rule: transport parameters the
// client did NOT send (here adexp 0x0a and madelay 0x0b) render "-" in segment
// D — NEVER their RFC 9000 defaults (3 and 25) — and drop out of segment C.
func TestQOSFNoFabrication(t *testing.T) {
	var params []types.QUICTransportParam
	for _, p := range goldenParams() {
		if p.ID == 0x0a || p.ID == 0x0b {
			continue // client did not send ack_delay_exponent / max_ack_delay
		}
		params = append(params, p)
	}
	kern := &types.QOSFKernel{IPVersion: 4, TTL: 117, ECN: 2, DF: true, SCIDLen: 0}
	got := buildQOSF(params, 0x00000001, "203.0.113.7:54321", kern, nil)
	want := "q1401-_xx1sx00_01.03.04.05.06.07.08.09.0e.0f.20.2ab2.G_30000.4.-.-.1472.15728640.100"
	if got.QOSF != want {
		t.Errorf("no-fabrication mismatch\n got=%s\nwant=%s", got.QOSF, want)
	}
	if got.SegTPValues != "30000.4.-.-.1472.15728640.100" {
		t.Errorf("segment D should show - for absent madelay/adexp, got %q", got.SegTPValues)
	}
}

// TestQOSFSocketOnly proves graceful degradation: without a packet tap (kern
// nil) the OS-bearing kernel fields and the SCID render "-", but ip (from the
// remote address), ver (from the negotiated version) and the transport-param
// segments still populate.
func TestQOSFSocketOnly(t *testing.T) {
	got := buildQOSF(goldenParams(), 0x00000001, "203.0.113.7:54321", nil, nil)
	want := "q-4---_xx1sx-_01.03.04.05.06.07.08.09.0a.0b.0e.0f.20.2ab2.G_30000.4.25.3.1472.15728640.100"
	if got.QOSF != want {
		t.Errorf("socket-only mismatch\n got=%s\nwant=%s", got.QOSF, want)
	}
	if got.Source != "socket-only" {
		t.Errorf("source = %q, want socket-only", got.Source)
	}
	// df and flow must be unobserved.
	for _, f := range got.Fields {
		if (f.Name == "df" || f.Name == "flow" || f.Name == "ttl" || f.Name == "scid") && f.Observed {
			t.Errorf("field %q must be unobserved without a tap, got Observed=true", f.Name)
		}
	}
}

// TestQOSFIPv6 checks the IPv6 kernel segment: df is "-" (no IPv4 DF bit), flow
// is z/n from the flow label.
func TestQOSFIPv6(t *testing.T) {
	kern := &types.QOSFKernel{IPVersion: 6, TTL: 54 /*->64*/, ECN: 0 /*Not-ECT*/, FlowLabel: 0x12345, SCIDLen: 3}
	got := buildQOSF(goldenParams(), 0x00000001, "[2001:db8::1]:443", kern, nil)
	if got.SegKernel != "q66n-n" {
		t.Errorf("IPv6 segment A = %q, want q66n-n", got.SegKernel)
	}
	if got.SegStack != "xx1sx03" {
		t.Errorf("IPv6 segment B = %q, want xx1sx03", got.SegStack)
	}
}

func TestTTLToCode(t *testing.T) {
	cases := map[int]string{0: "-", 1: "3", 32: "3", 33: "6", 52: "6", 64: "6", 65: "1", 117: "1", 128: "1", 129: "2", 250: "2", 255: "2"}
	for in, want := range cases {
		if got := ttlToCode(in); got != want {
			t.Errorf("ttlToCode(%d)=%q, want %q", in, got, want)
		}
	}
}

func TestECNToCode(t *testing.T) {
	cases := map[int]string{0: "n", 1: "1", 2: "0", 3: "c", 9: "-"}
	for in, want := range cases {
		if got := ecnToCode(in); got != want {
			t.Errorf("ecnToCode(%d)=%q, want %q", in, got, want)
		}
	}
}

func TestVerToCode(t *testing.T) {
	cases := map[uint32]string{0x00000001: "1", 0x6b3343cf: "2", 0xff00001d: "d", 0: "-", 0x12345678: "-"}
	for in, want := range cases {
		if got := verToCode(in); got != want {
			t.Errorf("verToCode(%#x)=%q, want %q", in, got, want)
		}
	}
}

func TestOrderCode(t *testing.T) {
	if got := orderCode([]uint64{0x01, 0x03, 0x04}); got != "a" {
		t.Errorf("ascending order = %q, want a", got)
	}
	if got := orderCode([]uint64{0xff02, 0x01}); got != "g" { // 0xff02 is reserved-GREASE
		t.Errorf("lead-grease order = %q, want g", got)
	}
	if got := orderCode([]uint64{0x03, 0x01}); got != "s" {
		t.Errorf("shuffled order = %q, want s", got)
	}
	if got := orderCode(nil); got != "-" {
		t.Errorf("empty order = %q, want -", got)
	}
}

func TestGreaseCode(t *testing.T) {
	if got := greaseCode([]uint64{0x2ab2, 0xff02}); got != "x" {
		t.Errorf("both grease = %q, want x", got)
	}
	if got := greaseCode([]uint64{0x2ab2, 0x01}); got != "b" {
		t.Errorf("bit-only grease = %q, want b", got)
	}
	if got := greaseCode([]uint64{0xff02, 0x01}); got != "t" {
		t.Errorf("reserved-only grease = %q, want t", got)
	}
	if got := greaseCode([]uint64{0x01, 0x03}); got != "-" {
		t.Errorf("no grease = %q, want -", got)
	}
}

// TestSegmentCGREASECollapse verifies multiple reserved-GREASE ids collapse to a
// single "G" at the sorted position of the smallest such id, while
// grease_quic_bit (0x2ab2) is a normal id and is NOT collapsed.
func TestSegmentCGREASECollapse(t *testing.T) {
	// 0x3a (58) and 0xff02 (65282) are both reserved GREASE; 0x2ab2 is not.
	got := buildSegmentC([]uint64{0x2ab2, 0x01, 0xff02, 0x3a})
	want := "01.G.2ab2" // G at position of smallest grease id (58), between 1 and 10930
	if got != want {
		t.Errorf("segment C = %q, want %q", got, want)
	}
}

// TestClassifyStackMechanism verifies the data-driven table + the grounded
// default signature: a set WITHOUT a Google-custom TP is unclassified ("xx"),
// while one WITH 0x3127/0x3128 is "ch" (Chromium). Also checks a custom rule.
func TestClassifyStackDefault(t *testing.T) {
	// No Google TP -> xx, even with Chromium-like shuffled/grease tells.
	noGoogle := stackInput{SortedIDs: []uint64{0x01, 0x03, 0x04, 0x2ab2}, Order: "s", Grease: "x", SCIDLen: 0}
	if got := classifyStack(noGoogle, defaultStackTable); got != "xx" {
		t.Errorf("no Google TP = %q, want xx", got)
	}
	// Google-custom TP present -> ch.
	withGoogle := stackInput{SortedIDs: []uint64{0x01, 0x03, 0x3127, 0x3128}, Order: "s", Grease: "x", SCIDLen: 0}
	if got := classifyStack(withGoogle, defaultStackTable); got != "ch" {
		t.Errorf("Google TP present = %q, want ch", got)
	}
	// Custom table still honored.
	table := []stackSignature{{Code: "zz", Match: func(s stackInput) bool { return s.Order == "s" }}}
	if got := classifyStack(noGoogle, table); got != "zz" {
		t.Errorf("custom signature = %q, want zz", got)
	}
}

// TestQOSFStackChromiumEndToEnd runs the real default classifier: a client that
// sent a Google-custom TP (0x3128) classifies as "ch" in segment B.
func TestQOSFStackChromiumEndToEnd(t *testing.T) {
	params := append(goldenParams(), tp(0x3128, "00")) // add Google user-agent-id TP
	kern := &types.QOSFKernel{IPVersion: 4, TTL: 117, ECN: 2, DF: true, SCIDLen: 0}
	got := buildQOSF(params, 0x00000001, "203.0.113.7:54321", kern, defaultStackTable)
	if got == nil || got.SegStack[:2] != "ch" {
		t.Fatalf("segment B stack = %q, want ch...", func() string {
			if got == nil {
				return "<nil>"
			}
			return got.SegStack
		}())
	}
	// And segment C must still contain the raw 0x3128 id (auditable).
	if !containsSub(got.SegTPSet, "3128") {
		t.Errorf("segment C %q should list the raw 3128 id", got.SegTPSet)
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestIPVersionOf(t *testing.T) {
	cases := []struct {
		ip   string
		kern *types.QOSFKernel
		want int
	}{
		{"203.0.113.7:54321", nil, 4},
		{"[2001:db8::1]:443", nil, 6},
		{"203.0.113.7", nil, 4},
		{"2001:db8::1", nil, 6},
		{"garbage", nil, 0},
		{"203.0.113.7:1", &types.QOSFKernel{IPVersion: 6}, 6}, // kern overrides
	}
	for _, c := range cases {
		if got := ipVersionOf(c.ip, c.kern); got != c.want {
			t.Errorf("ipVersionOf(%q,%v)=%d, want %d", c.ip, c.kern, got, c.want)
		}
	}
}

func TestCalculateQOSFNilForNoParams(t *testing.T) {
	if got := CalculateQOSF(nil, 1, "203.0.113.7:443", nil); got != nil {
		t.Errorf("CalculateQOSF with no params = %v, want nil", got)
	}
}

// TestQOSFInitialPacket verifies the informational QUIC Initial packet structure
// (version, CID lengths, datagram size) is surfaced when the tap saw the Initial,
// and absent (socket-only) otherwise. It is NOT part of the canonical string.
func TestQOSFInitialPacket(t *testing.T) {
	kern := &types.QOSFKernel{IPVersion: 4, TTL: 117, ECN: 2, DF: true, SCIDLen: 0, DCIDLen: 8, QUICVersion: 1, UDPPayloadLen: 1231}
	before := buildQOSF(goldenParams(), 0x00000001, "203.0.113.7:54321", kern, nil)
	if before.InitialPacket == nil {
		t.Fatal("InitialPacket not set when tap observed the Initial")
	}
	ip := before.InitialPacket
	if ip.QUICVersion != "1" || ip.DCIDLength != 8 || ip.SCIDLength != 0 || ip.UDPDatagramSize != 1231 {
		t.Errorf("InitialPacket = %+v, want {1 8 0 1231}", ip)
	}
	// Adding the structure must NOT change the canonical fingerprint string.
	want := "q1401-_xx1sx00_01.03.04.05.06.07.08.09.0a.0b.0e.0f.20.2ab2.G_30000.4.25.3.1472.15728640.100"
	if before.QOSF != want {
		t.Errorf("canonical string changed: %s", before.QOSF)
	}
	// Socket-only → no InitialPacket.
	so := buildQOSF(goldenParams(), 0x00000001, "203.0.113.7:54321", nil, nil)
	if so.InitialPacket != nil {
		t.Errorf("InitialPacket should be nil socket-only, got %+v", so.InitialPacket)
	}
}

// TestQOSFSpaces verifies the kernel/user-space split: segment A fields are
// "kernel" (the IP/UDP header the OS writes), segments B/C/D fields are "user"
// (the QUIC library), and KernelSpace/UserSpace carry the right substrings.
func TestQOSFSpaces(t *testing.T) {
	kern := &types.QOSFKernel{IPVersion: 4, TTL: 117, ECN: 2, DF: true, SCIDLen: 0}
	got := buildQOSF(goldenParams(), 0x00000001, "203.0.113.7:54321", kern, nil)
	if got.KernelSpace == nil || got.UserSpace == nil {
		t.Fatal("KernelSpace/UserSpace not set")
	}
	if got.KernelSpace.Value != got.SegKernel {
		t.Errorf("KernelSpace.Value=%q, want segA %q", got.KernelSpace.Value, got.SegKernel)
	}
	if wantUser := got.SegStack + "_" + got.SegTPSet + "_" + got.SegTPValues; got.UserSpace.Value != wantUser {
		t.Errorf("UserSpace.Value=%q, want %q", got.UserSpace.Value, wantUser)
	}
	kernelFields := map[string]bool{"ttl": true, "ip": true, "ecn": true, "df": true, "flow": true}
	for _, f := range got.Fields {
		want := "user"
		if kernelFields[f.Name] {
			want = "kernel"
		}
		if f.Space != want {
			t.Errorf("field %q space=%q, want %q", f.Name, f.Space, want)
		}
	}
}

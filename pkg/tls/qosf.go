package tls

// QOSF (QUIC OS Fingerprint) — a readable, non-hashed passive fingerprint for
// QUIC connections, computed ALONGSIDE the QUIC JA4/SPHBI and ONLY for QUIC.
//
// This module is entirely self-contained: it does not modify, wrap, or
// reimplement any part of the JA4/TCP/TLS path. It reads only data that is
// already parsed for QUIC (the client's transport parameters + negotiated QUIC
// version) plus, when a packet tap observed the flow, the kernel/long-header
// fields carried in *types.QOSFKernel.
//
// Format:
//
//	q<ttl><ip><ecn><df><flow>_<stack><ver><order><grease><scid>_<tp-set>_<tp-values>
//
//	A (kernel/OS):  q  ttl{3=32,6=64,1=128,2=255}  ip{4,6}  ecn{n,1,0,c}  df{1,0,-}  flow{z,n,-}
//	B (stack):      stack(2 letters|xx)  ver{1,2,d,-}  order{a,e,s,g,-}  grease{b,t,x,-}  scid(2-hex|-)
//	C (tp-set):     transport-param ids, sorted ascending, reserved-GREASE (id%31==27) collapsed to one "G"
//	D (tp-values):  idle.acid.madelay.adexp.mudp.mdata.sbidi   (each decoded value, or "-" if the client did not send it)
//
// Canonicalization rules (from the spec):
//   - literal "q" prefix; fixed section + field order.
//   - TTL as observed>inferred: the initial TTL is inferred by rounding the
//     observed TTL UP to the nearest of {32,64,128,255}, then mapped to a code.
//   - the tp id-set is SORTED ascending; reserved-GREASE ids collapse to one "G".
//   - lowercase hex, no "0x".
//   - EVERY unobserved field is "-". A transport parameter the client did not
//     send is "-", NEVER its RFC 9000 default — emitting a default would be
//     fabrication. (This is why a real QOSF may show "-" where the spec's
//     illustrative example shows an RFC default.)

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/pagpeter/trackme/pkg/types"
)

// Well-known QUIC transport-parameter IDs used by QOSF (RFC 9000 18.2, RFC 9287).
const (
	tpMaxIdleTimeout        uint64 = 0x01
	tpMaxUDPPayloadSize     uint64 = 0x03
	tpInitialMaxData        uint64 = 0x04
	tpInitialMaxStreamsBidi uint64 = 0x08
	tpAckDelayExponent      uint64 = 0x0a
	tpMaxAckDelay           uint64 = 0x0b
	tpActiveConnIDLimit     uint64 = 0x0e
	tpGreaseQUICBit         uint64 = 0x2ab2
)

// isReservedGREASETP reports whether id is a reserved-GREASE transport parameter.
// RFC 9000 18.1: parameters with an id of the form 31*N+27 are reserved, i.e.
// id % 31 == 27. (Note: this differs from the SPHBI image's GREASE heuristic;
// QOSF deliberately uses the RFC rule and never touches the SPHBI path.)
func isReservedGREASETP(id uint64) bool { return id%31 == 27 }

// CalculateQOSF builds the QUIC OS Fingerprint for a QUIC connection. It returns
// nil when there are no transport parameters (e.g. no ClientHello / 0-RTT), in
// which case the caller emits no QOSF. quicVersion is the negotiated QUIC
// version (h3state.Version, authoritative). remoteIP is the client's address
// ("ip", "ip:port", or "[ip]:port"). kern is the packet-tap observation for this
// flow, or nil for socket-only degradation (segment A / scid render "-").
func CalculateQOSF(params []types.QUICTransportParam, quicVersion uint32, remoteIP string, kern *types.QOSFKernel) *types.QOSFDetails {
	return buildQOSF(params, quicVersion, remoteIP, kern, defaultStackTable)
}

func buildQOSF(params []types.QUICTransportParam, quicVersion uint32, remoteIP string, kern *types.QOSFKernel, stacks []stackSignature) *types.QOSFDetails {
	if len(params) == 0 {
		return nil
	}

	ipVersion := ipVersionOf(remoteIP, kern)

	// Transport-param ids in the client's wire order, and their decoded value bytes.
	ids := make([]uint64, len(params))
	byID := make(map[uint64][]byte, len(params))
	for i, p := range params {
		ids[i] = p.ID
		if b, err := hex.DecodeString(p.Value); err == nil {
			byID[p.ID] = b
		}
	}

	segA, fA := buildSegmentA(ipVersion, kern)
	segB, fB, stack := buildSegmentB(ids, quicVersion, kern, stacks)
	segC := buildSegmentC(ids)
	segD, fD := buildSegmentD(byID)

	source := "socket-only"
	if kern != nil {
		source = "pcap+quic"
	}

	// QUIC Initial packet structure (userspace, informational — not in the
	// canonical string): the shape a passive decryptor reads and a mimic forges.
	var initial *types.QOSFInitialStructure
	if kern != nil {
		initial = &types.QOSFInitialStructure{
			QUICVersion:     verToCode(kern.QUICVersion),
			DCIDLength:      kern.DCIDLen,
			SCIDLength:      kern.SCIDLen,
			UDPDatagramSize: kern.UDPPayloadLen,
		}
	}

	fields := make([]types.QOSFField, 0, len(fA)+len(fB)+len(fD))
	fields = append(fields, fA...)
	fields = append(fields, fB...)
	fields = append(fields, fD...)

	return &types.QOSFDetails{
		QOSF:        segA + "_" + segB + "_" + segC + "_" + segD,
		SegKernel:   segA,
		SegStack:    segB,
		SegTPSet:    segC,
		SegTPValues: segD,
		Source:      source,
		OS:          inferOS(kern, stack),
		// Where each part is produced: the OS kernel writes the IP/UDP header
		// (segment A); the userspace QUIC library writes segments B/C/D.
		KernelSpace: &types.QOSFSpace{
			Label:    "OS kernel — IP/UDP header",
			Segments: []string{"A"},
			Value:    segA,
		},
		UserSpace: &types.QOSFSpace{
			Label:    "userspace QUIC library",
			Segments: []string{"B", "C", "D"},
			Value:    segB + "_" + segC + "_" + segD,
		},
		InitialPacket: initial,
		Fields:        fields,
	}
}

// ipVersionOf prefers the tap's observed IP version, then derives it from the
// remote address. Returns 0 if unknown (rendered "-").
func ipVersionOf(remoteIP string, kern *types.QOSFKernel) int {
	if kern != nil && (kern.IPVersion == 4 || kern.IPVersion == 6) {
		return kern.IPVersion
	}
	host := remoteIP
	if h, _, err := net.SplitHostPort(remoteIP); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}
	return 6
}

// --- Segment A: kernel / OS signal -----------------------------------------

// ttlToCode infers the initial TTL/hop-limit (round observed UP to the nearest
// of {32,64,128,255}) and maps it to a code. "-" if unobserved.
func ttlToCode(ttl int) string {
	switch {
	case ttl <= 0:
		return "-"
	case ttl <= 32:
		return "3" // initial 32
	case ttl <= 64:
		return "6" // initial 64
	case ttl <= 128:
		return "1" // initial 128
	case ttl <= 255:
		return "2" // initial 255
	default:
		return "-"
	}
}

// ecnToCode maps the 2-bit ECN codepoint (RFC 3168) to a QOSF code.
func ecnToCode(cp int) string {
	switch cp {
	case 0:
		return "n" // Not-ECT
	case 1:
		return "1" // ECT(1)
	case 2:
		return "0" // ECT(0)
	case 3:
		return "c" // CE
	default:
		return "-"
	}
}

func buildSegmentA(ipVersion int, kern *types.QOSFKernel) (string, []types.QOSFField) {
	ipCode := "-"
	switch ipVersion {
	case 4:
		ipCode = "4"
	case 6:
		ipCode = "6"
	}

	ttlCode, ecnCode, dfCode, flowCode := "-", "-", "-", "-"
	var ttlNote, dfNote, flowNote string

	if kern != nil {
		ttlCode = ttlToCode(kern.TTL)
		if ttlCode != "-" {
			ttlNote = fmt.Sprintf("observed %d", kern.TTL)
		}
		ecnCode = ecnToCode(kern.ECN)
		switch ipVersion {
		case 4:
			if kern.DF {
				dfCode = "1"
			} else {
				dfCode = "0"
			}
			flowCode = "-" // IPv4 has no flow label
			flowNote = "IPv4 (no flow label)"
		case 6:
			dfCode = "-" // IPv6 has no DF bit
			dfNote = "IPv6 (no DF bit)"
			if kern.FlowLabel == 0 {
				flowCode = "z"
			} else {
				flowCode = "n"
			}
		}
	} else {
		// Socket-only degradation: the tap did not observe this flow, so the
		// kernel fields cannot be read. df/flow are also structurally "-".
		if ipVersion == 4 {
			flowNote = "IPv4 (no flow label)"
		} else if ipVersion == 6 {
			dfNote = "IPv6 (no DF bit)"
		}
	}

	seg := "q" + ttlCode + ipCode + ecnCode + dfCode + flowCode
	fields := []types.QOSFField{
		{Name: "ttl", Value: ttlCode, Observed: ttlCode != "-", Note: ttlNote},
		{Name: "ip", Value: ipCode, Observed: ipCode != "-"},
		{Name: "ecn", Value: ecnCode, Observed: ecnCode != "-"},
		{Name: "df", Value: dfCode, Observed: dfCode != "-", Note: dfNote},
		{Name: "flow", Value: flowCode, Observed: flowCode == "z" || flowCode == "n", Note: flowNote},
	}
	for i := range fields {
		fields[i].Space = "kernel" // the OS kernel writes the IP/UDP header (segment A)
	}
	return seg, fields
}

// --- Segment B: userspace stack --------------------------------------------

// verToCode maps a negotiated QUIC version to a code. "-" if unknown.
func verToCode(v uint32) string {
	switch v {
	case 0x00000001:
		return "1" // QUIC v1 (RFC 9000)
	case 0x6b3343cf:
		return "2" // QUIC v2 (RFC 9369)
	default:
		if v >= 0xff000000 && v <= 0xff0000ff {
			return "d" // draft-ff versions (0xff0000xx)
		}
		return "-"
	}
}

// orderCode classifies the transport-param order as sent by the client.
// Only observable classes are emitted: "g" (leads with reserved-GREASE), "a"
// (strictly ascending), "s" (otherwise). "e" (a library's fixed enumeration)
// cannot be distinguished from "s" in a single flight, so it is never emitted.
func orderCode(ids []uint64) string {
	if len(ids) == 0 {
		return "-"
	}
	if isReservedGREASETP(ids[0]) {
		return "g"
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			return "s"
		}
	}
	return "a"
}

// greaseCode reports which GREASE mechanisms the client used:
// b = grease_quic_bit only, t = reserved-GREASE transport param only,
// x = both, "-" = neither.
func greaseCode(ids []uint64) string {
	hasBit, hasReserved := false, false
	for _, id := range ids {
		if id == tpGreaseQUICBit {
			hasBit = true
		}
		if isReservedGREASETP(id) {
			hasReserved = true
		}
	}
	switch {
	case hasBit && hasReserved:
		return "x"
	case hasBit:
		return "b"
	case hasReserved:
		return "t"
	default:
		return "-"
	}
}

func buildSegmentB(ids []uint64, quicVersion uint32, kern *types.QOSFKernel, stacks []stackSignature) (string, []types.QOSFField, string) {
	ver := verToCode(quicVersion)
	order := orderCode(ids)
	grease := greaseCode(ids)

	scid := "-"
	scidObserved := false
	if kern != nil {
		scid = fmt.Sprintf("%02x", kern.SCIDLen)
		scidObserved = true
	}

	// Sorted id-set for the classifier (GREASE kept as ids; classifier decides).
	sorted := append([]uint64(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	scidLen := -1
	if kern != nil {
		scidLen = kern.SCIDLen
	}
	stack := classifyStack(stackInput{
		SortedIDs: sorted,
		Order:     order,
		Grease:    grease,
		SCIDLen:   scidLen,
	}, stacks)

	seg := stack + ver + order + grease + scid
	fields := []types.QOSFField{
		{Name: "stack", Value: stack, Observed: stack != "xx", Note: stackNote(stack)},
		{Name: "ver", Value: ver, Observed: ver != "-"},
		{Name: "order", Value: order, Observed: order != "-"},
		{Name: "grease", Value: grease, Observed: true},
		{Name: "scid", Value: scid, Observed: scidObserved},
	}
	for i := range fields {
		fields[i].Space = "user" // the userspace QUIC library writes segment B
	}
	return seg, fields, stack
}

func stackNote(code string) string {
	if code == "xx" {
		return "unclassified (no verified signature matched)"
	}
	return ""
}

// --- Segment C: transport-param id-set -------------------------------------

// buildSegmentC returns the transport-param ids sorted ascending, deduplicated,
// with all reserved-GREASE ids collapsed to a single "G" at the sorted position
// of the smallest such id.
func buildSegmentC(ids []uint64) string {
	var normal []uint64
	seen := make(map[uint64]bool)
	greasePresent := false
	var minGrease uint64
	for _, id := range ids {
		if isReservedGREASETP(id) {
			if !greasePresent || id < minGrease {
				minGrease = id
			}
			greasePresent = true
			continue
		}
		if !seen[id] {
			seen[id] = true
			normal = append(normal, id)
		}
	}
	sort.Slice(normal, func(i, j int) bool { return normal[i] < normal[j] })

	toks := make([]string, 0, len(normal)+1)
	insertedG := false
	for _, id := range normal {
		if greasePresent && !insertedG && minGrease < id {
			toks = append(toks, "G")
			insertedG = true
		}
		toks = append(toks, fmt.Sprintf("%02x", id))
	}
	if greasePresent && !insertedG {
		toks = append(toks, "G")
	}
	return strings.Join(toks, ".")
}

// --- Segment D: transport-param values -------------------------------------

// buildSegmentD emits the decoded values of a fixed set of transport params, in
// a fixed order. A parameter the client did not send is "-" (NEVER an RFC
// default — that would be fabrication).
func buildSegmentD(byID map[uint64][]byte) (string, []types.QOSFField) {
	slots := []struct {
		name string
		id   uint64
	}{
		{"idle", tpMaxIdleTimeout},         // 0x01 max_idle_timeout (ms)
		{"acid", tpActiveConnIDLimit},      // 0x0e active_connection_id_limit
		{"madelay", tpMaxAckDelay},         // 0x0b max_ack_delay (ms)
		{"adexp", tpAckDelayExponent},      // 0x0a ack_delay_exponent
		{"mudp", tpMaxUDPPayloadSize},      // 0x03 max_udp_payload_size
		{"mdata", tpInitialMaxData},        // 0x04 initial_max_data
		{"sbidi", tpInitialMaxStreamsBidi}, // 0x08 initial_max_streams_bidi
	}
	toks := make([]string, len(slots))
	fields := make([]types.QOSFField, len(slots))
	for i, s := range slots {
		tok := "-"
		observed := false
		if val, ok := byID[s.id]; ok {
			if n, consumed := readQUICVarint(val); consumed > 0 {
				tok = strconv.FormatUint(n, 10)
				observed = true
			}
		}
		toks[i] = tok
		// Transport-param values are written by the userspace QUIC library (segment D).
		fields[i] = types.QOSFField{Name: s.name, Value: tok, Observed: observed, Space: "user"}
	}
	return strings.Join(toks, "."), fields
}

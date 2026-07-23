package tls

// Data-driven QOSF stack classifier.
//
// The QUIC transport-parameter set identifies the userspace QUIC *library*, not
// the OS. Mapping a signature to a 2-letter stack code is therefore a derived
// label, and per the QOSF no-fabrication rule a stack code is emitted ONLY from
// a VERIFIED signature; anything unmatched stays "xx" (unclassified).
//
// defaultStackTable holds exactly ONE signature, grounded from real UA-labelled
// QUIC captures on the live server (2026-07-23):
//   - "ch" (Chromium): a Google-custom QUIC transport parameter (0x3127/0x3128)
//     is present. These live in Google's reserved range and are sent by no other
//     stack (Firefox/neqo, Apple, quic-go, msquic all lack them in the captures),
//     so their presence is a high-precision, generalizable Chromium tell.
//
// Deliberately NOT seeded, to avoid fabrication / overfitting:
//   - Apple/Safari: research/quic-client-fingerprinting.md 10 explicitly says
//     leave Apple config-empty; the live sample is a single machine -> "xx".
//   - Firefox / quic-go: their live sample is too machine-specific to generalize
//     (e.g. 0x0c is not a unique quic-go tell) -> "xx".
//
// To add a stack: register a verified signature (from real, UA-labelled captures)
// here. Never invent id-sets. A heuristic that guesses "chromium" from loose
// GREASE tells would misclassify Safari/Firefox — itself a form of fabrication.
// Segment C always shows the raw id-set, so even the "ch" label stays auditable.

// Google's QUIC stack (Chromium/Chrome, cronet) sends custom transport
// parameters in its reserved range; 0x3127/0x3128 appear in every live Chrome
// capture and in no other stack's.
const (
	tpGoogleConnectionOptions uint64 = 0x3127
	tpGoogleUserAgentID       uint64 = 0x3128
)

// stackInput is the observed signature offered to each rule.
type stackInput struct {
	SortedIDs []uint64 // transport-param ids, sorted ascending (GREASE ids included)
	Order     string   // "a" | "e" | "s" | "g"
	Grease    string   // "b" | "t" | "x" | "-"
	SCIDLen   int      // client SCID length, or -1 if the tap did not observe it
}

// stackSignature is one data-driven rule. Match reports whether the observed
// signature is this stack; the first matching rule's Code wins.
type stackSignature struct {
	Code  string
	Match func(stackInput) bool
}

// defaultStackTable holds the verified signatures (see file header). Extend only
// from confirmed, UA-labelled captures.
var defaultStackTable = []stackSignature{
	{Code: "ch", Match: func(s stackInput) bool {
		for _, id := range s.SortedIDs {
			if id == tpGoogleConnectionOptions || id == tpGoogleUserAgentID {
				return true
			}
		}
		return false
	}},
}

// classifyStack returns the 2-letter stack code, or "xx" if no rule matches.
func classifyStack(in stackInput, table []stackSignature) string {
	for _, s := range table {
		if s.Match != nil && s.Match(in) {
			return s.Code
		}
	}
	return "xx"
}

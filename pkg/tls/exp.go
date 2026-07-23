package tls

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// b32 matches Python's base64.b32encode(...).rstrip("=").lower():
// RFC 4648 standard alphabet, no padding, lower-cased.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ValidExp verifies an experiment token of the form "cell_id.nonce_b32.sig_b32"
// against the shared secret and returns cell_id on success, "" otherwise.
//
// It mirrors the Python orchestrator's token_mint (fleet/fpdriver/token_mint.py):
//
//	sig = lower(b32nopad( HMAC_SHA256(secret, cell_id+"."+nonce_b32)[:8] ))
//
// so a token minted in Python verifies here byte-for-byte. This keeps drive-by
// scanner traffic hitting "?exp=" out of the experiment dataset.
func ValidExp(token, secret string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	cellID, nonce, sig := parts[0], parts[1], parts[2]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(cellID + "." + nonce))
	want := strings.ToLower(b32.EncodeToString(mac.Sum(nil)[:8]))
	if hmac.Equal([]byte(sig), []byte(want)) {
		return cellID
	}
	return ""
}

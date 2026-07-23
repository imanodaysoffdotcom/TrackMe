package tls

import "testing"

// Token minted by the Python orchestrator: mint("c1", b"s3cr3t")
// (fleet/fpdriver/token_mint.py). The Go verifier must accept it byte-for-byte.
const pyToken = "c1.nokghwuc4yjybpesksevdlg25u.g6fbhsylopg7w"

func TestValidExpMatchesPython(t *testing.T) {
	if got := ValidExp(pyToken, "s3cr3t"); got != "c1" {
		t.Fatalf("want c1, got %q", got)
	}
}

func TestValidExpRejectsWrongSecret(t *testing.T) {
	if ValidExp(pyToken, "nope") != "" {
		t.Fatal("wrong secret accepted")
	}
}

func TestValidExpRejectsTamper(t *testing.T) {
	bad := pyToken[:len(pyToken)-1] + "x"
	if ValidExp(bad, "s3cr3t") != "" {
		t.Fatal("tampered signature accepted")
	}
}

func TestValidExpRejectsMalformed(t *testing.T) {
	for _, m := range []string{"nodots", "a.b", "a.b.c.d", ""} {
		if ValidExp(m, "s3cr3t") != "" {
			t.Fatalf("malformed %q accepted", m)
		}
	}
}

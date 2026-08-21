// T308 — RED: verification that CANNOT COMPLETE refuses; it never reports
// "intact" (FR-030, quickstart S8).
//
// The failure this prevents is the quietest one in the whole feature. A
// verifier that hits an unreadable store, a truncated walk or a malformed
// record and returns "no findings" is indistinguishable, at the seam, from a
// verifier that looked at everything and found nothing wrong. Zero findings
// then means either "clean" or "blind", and the reader cannot tell which.
//
// §11.4.201(6): a null is not evidence until the instrument is proven able to
// see. So an incomplete walk gets its OWN verdict — REFUSE — with the reason
// named, and REFUSE is never collapsed into PASS.
//
// This extends pkg/verify's existing closed vocabulary:
//
//	PASS | FAIL | SKIP   ->   PASS | FAIL | SKIP | DETECTED | REFUSE
//
// REFUSE and SKIP are different states and must not be merged: SKIP means
// "this does not apply here" (honest, non-blocking); REFUSE means "this applies
// and I could not decide" (honest, blocking).
//
// Paired mutation (T319): map the incomplete-walk branch to PASS -> this test
// MUST fail.
package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requireRefusal asserts the verdict is REFUSE and that it names why.
func requireRefusal(t *testing.T, r Result, what string) {
	t.Helper()
	if r.Verdict == PASS {
		t.Fatalf("%s: verification could not complete and reported PASS. "+
			"Zero findings from a blind instrument is not a clean result (FR-030).", what)
	}
	if r.Verdict == SKIP {
		t.Fatalf("%s: reported SKIP. SKIP means 'does not apply'; this applies and could not "+
			"be decided, which is REFUSE.", what)
	}
	if r.Verdict != REFUSE {
		t.Fatalf("%s: got %s, want REFUSE", what, r.Verdict)
	}
	if strings.TrimSpace(r.Detail) == "" {
		t.Errorf("%s: REFUSE carried no reason; an operator cannot act on a bare refusal", what)
	}
}

func TestUnreadableStoreRefuses(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "chain.jsonl")
	if err := os.WriteFile(p, []byte(`{"seq":1,"prev_digest":""}`+"\n"), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	// Make it unreadable. If the host runs this as a user who can read it
	// anyway (root), the premise does not hold and the test must SKIP rather
	// than report a result it did not actually obtain.
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	if _, err := os.ReadFile(p); err == nil {
		t.Skip("host can read a 0000 file (running as root?); the unreadable-store premise " +
			"does not hold here and asserting on it would be reporting an untested condition")
	}

	requireRefusal(t, VerifyChainFile(p), "unreadable store")
}

func TestMidWalkTruncationRefuses(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "chain.jsonl")
	// A final line cut in half: the realistic artifact of a process that died
	// between write() and fsync().
	full := `{"seq":1,"ts":"2026-08-21T12:00:00Z","prev_digest":""}` + "\n" +
		`{"seq":2,"ts":"2026-08-21T12:01:00Z","prev_dig`
	if err := os.WriteFile(p, []byte(full), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	requireRefusal(t, VerifyChainFile(p), "mid-walk truncation")
}

func TestMalformedRecordRefuses(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "chain.jsonl")
	full := `{"seq":1,"ts":"2026-08-21T12:00:00Z","prev_digest":""}` + "\n" +
		"this is not a record\n"
	if err := os.WriteFile(p, []byte(full), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	requireRefusal(t, VerifyChainFile(p), "malformed record")
}

// TestMissingStoreIsRefusedNotPassed — an absent store is the wholesale-
// deletion case. "There is nothing here" must never read as "nothing is wrong".
func TestMissingStoreIsRefusedNotPassed(t *testing.T) {
	r := VerifyChainFile(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	if r.Verdict == PASS {
		t.Fatal("a MISSING chain store verified PASS. Wholesale deletion would then be silent, " +
			"which is the failure entry_count and this refusal exist to prevent.")
	}
	if r.Verdict != REFUSE {
		t.Errorf("got %s, want REFUSE", r.Verdict)
	}
}

// TestRefuseIsNotPass is the vocabulary guard. If REFUSE were ever defined
// equal to PASS, every assertion above would pass while the property was gone.
func TestRefuseIsNotPass(t *testing.T) {
	if REFUSE == PASS {
		t.Fatal("REFUSE == PASS: the refusal verdict has been collapsed into success")
	}
	if REFUSE == SKIP {
		t.Fatal("REFUSE == SKIP: 'could not decide' has been collapsed into 'does not apply'")
	}
	if DETECTED == PASS {
		t.Fatal("DETECTED == PASS: the detection verdict has been collapsed into success")
	}
}

// TestHealthyChainStillPasses is the false-positive guard for this whole file:
// a verifier that refuses everything satisfies every refusal test above and is
// useless. §11.4.201(1).
func TestHealthyChainStillPasses(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "chain.jsonl")
	if err := WriteHealthyChainForTest(p, 4); err != nil {
		t.Fatalf("building a healthy chain: %v", err)
	}
	r := VerifyChainFile(p)
	if r.Verdict != PASS {
		t.Fatalf("a healthy chain verified %s (%s), want PASS. A verifier that refuses "+
			"everything is not strict, it is broken.", r.Verdict, r.Detail)
	}
}

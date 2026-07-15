package verify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vasic-digital/continuum/pkg/model"
	"github.com/vasic-digital/continuum/pkg/snapshot"
	"github.com/vasic-digital/continuum/pkg/store"
)

func TestVerifySkipPassFail(t *testing.T) {
	dir := t.TempDir()
	s, _ := store.Open(dir)
	e := snapshot.New(s, "test", 0)

	// SKIP when nothing committed.
	if r := Verify(e); r.Verdict != SKIP {
		t.Fatalf("want SKIP, got %s (%s)", r.Verdict, r.Detail)
	}

	// PASS after a clean commit.
	e.Set(model.StreamState{StreamID: "A", Kind: "track", NextAction: "n"})
	head, _ := e.Commit("c")
	if r := Verify(e); r.Verdict != PASS {
		t.Fatalf("want PASS, got %s (%s)", r.Verdict, r.Detail)
	}

	// FAIL after tampering a referenced stream blob.
	snap, _ := s.GetSnapshot(head)
	var cid string
	for _, v := range snap.Streams {
		cid = v
	}
	p := filepath.Join(dir, "objects", cid[:2], cid)
	b, _ := os.ReadFile(p)
	b[len(b)-1] ^= 0xFF
	os.WriteFile(p, b, 0o644)
	if r := Verify(e); r.Verdict != FAIL {
		t.Fatalf("want FAIL on tamper, got %s (%s)", r.Verdict, r.Detail)
	}
}

// The self-validating oracle (§11.4.107(10)): the verifier itself cannot bluff.
func TestSelfCheckOracle(t *testing.T) {
	r, err := SelfCheck(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if r.Good.Verdict != PASS {
		t.Fatalf("golden-good must PASS: %s (%s)", r.Good.Verdict, r.Good.Detail)
	}
	if r.Bad.Verdict != FAIL {
		t.Fatalf("golden-bad must be DETECTED as FAIL: %s (%s)", r.Bad.Verdict, r.Bad.Detail)
	}
	if r.NegControl.Verdict != PASS {
		t.Fatalf("negative-control (lagging-but-valid) must PASS: %s (%s)", r.NegControl.Verdict, r.NegControl.Detail)
	}
	if r.Overall != PASS {
		t.Fatalf("oracle overall must PASS: %s (%s)", r.Overall, r.Detail)
	}
}

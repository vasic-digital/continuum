// T303 — RED: DELETION without reconstruction is detected (FR-029).
//
// The distinction that matters: this fixture removes a record and leaves every
// survivor byte-identical. The record after the hole still points at a
// predecessor that no longer exists, so the walk breaks. Contrast
// attack_delete_rechain_boundary_test.go, where the adversary also rebuilds the
// chain — and is NOT detected. Deletion is detectable only because the
// adversary did not do the extra work.
package chain_test

import (
	"testing"

	"github.com/vasic-digital/continuum/pkg/chain"
	fx "github.com/vasic-digital/continuum/test/fixtures/chain"
)

// Paired mutation (T317): skip the predecessor-walk on a missing seq -> this
// test MUST fail.
func TestDeletionWithoutReconstructionIsDetected(t *testing.T) {
	root := corpus(t)
	recs := load(t, root, fx.AttackDeletion)

	if len(recs) != corpusN-1 {
		t.Fatalf("deletion fixture holds %d records, want %d", len(recs), corpusN-1)
	}
	rep := chain.Verify(recs)
	if rep.Verdict != chain.DETECTED {
		t.Fatalf("deletion verified %s, want DETECTED", rep.Verdict)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("deletion reported DETECTED with no findings; the broken link must be named")
	}
	// The report must name the broken link, not merely assert a count mismatch:
	// a chain-alone verifier has no idea how many records there SHOULD be (that
	// is the anchor's job), so a count-based claim here would be unfounded.
	var named bool
	for _, f := range rep.Findings {
		if f.Seq > 0 && f.Detail != "" {
			named = true
		}
	}
	if !named {
		t.Errorf("no finding names a seq with detail; findings=%v", rep.Findings)
	}
}

// T304 — RED: REORDER of two entries without reconstruction is detected (FR-029).
//
// The fixture swaps two adjacent records' POSITIONS; contents are untouched. A
// verifier that sorts by seq before walking silently repairs the swap and
// reports PASS — which is why sorting is this test's paired mutation. The walk
// must follow prev_digest in FILE ORDER, because file order is what an
// adversary controls.
package chain_test

import (
	"testing"

	"github.com/vasic-digital/continuum/pkg/chain"
	fx "github.com/vasic-digital/continuum/test/fixtures/chain"
)

// Paired mutation (T317): sort entries by seq before walking -> this test MUST fail.
func TestReorderWithoutReconstructionIsDetected(t *testing.T) {
	root := corpus(t)
	recs := load(t, root, fx.AttackReorder)

	if len(recs) != corpusN {
		t.Fatalf("reorder fixture holds %d records, want %d (a swap changes order, not count)",
			len(recs), corpusN)
	}
	// Guard the fixture's own premise: the records really are out of order.
	// If they were not, this test would pass against a sorting verifier too.
	outOfOrder := false
	for i, r := range recs {
		if r.Seq != int64(i+1) {
			outOfOrder = true
			break
		}
	}
	if !outOfOrder {
		t.Fatal("reorder fixture is in ascending seq order; the swap did not happen and this " +
			"test would not distinguish a sorting verifier from a correct one")
	}

	rep := chain.Verify(recs)
	if rep.Verdict != chain.DETECTED {
		t.Fatalf("reorder verified %s, want DETECTED — the walk followed sorted order rather "+
			"than file order, which silently repairs exactly the tamper an adversary performs",
			rep.Verdict)
	}
}

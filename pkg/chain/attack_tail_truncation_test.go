// T305 — RED: TAIL TRUNCATION. Both halves live in ONE test on purpose.
//
// ###########################################################################
// # MEASURED, AND NOT A DEFECT: chain-alone verification PASSes here.        #
// #                                                                          #
// # Truncating the tail leaves a byte-identical PREFIX of a valid chain, and #
// # a prefix of a valid chain IS a valid chain. Internal consistency is the  #
// # only thing a chain can ever prove; it cannot know what it should have    #
// # contained. Only the anchor — an external record of the expected head and #
// # entry count — carries that.                                             #
// #                                                                          #
// # The two assertions are deliberately in the SAME test so neither can be   #
// # deleted without the other failing. The PAIR of results is the evidence   #
// # that the anchor, not the chain, carries this property. Splitting them    #
// # into two tests would let someone delete the inconvenient half.           #
// ###########################################################################
package chain_test

import (
	"testing"

	"github.com/vasic-digital/continuum/pkg/anchor"
	"github.com/vasic-digital/continuum/pkg/chain"
	fx "github.com/vasic-digital/continuum/test/fixtures/chain"
)

// summarise builds the anchor's view of a chain: head digest, count, and the
// digest of any prefix. anchor.Check needs the prefix accessor to distinguish a
// LAGGING anchor (chain grew) from a TRUNCATED chain (chain shrank) — comparing
// head digests alone cannot tell those apart and refuses both.
func summarise(t *testing.T, recs []chain.Record) anchor.ChainSummary {
	t.Helper()
	head := ""
	if len(recs) > 0 {
		d, err := chain.Digest(recs[len(recs)-1])
		if err != nil {
			t.Fatalf("digesting head: %v", err)
		}
		head = d
	}
	return anchor.ChainSummary{
		Head:  head,
		Count: len(recs),
		PrefixHead: func(n int) (string, error) {
			if n <= 0 || n > len(recs) {
				return "", anchor.ErrPrefixUnavailable
			}
			return chain.Digest(recs[n-1])
		},
	}
}

// Paired mutation (T322): drop the anchor comparison -> the SECOND half must
// fail while the first still passes. A mutation that breaks both would prove
// nothing about which layer carries the property.
func TestTailTruncation_ChainAlonePasses_AnchorDetects(t *testing.T) {
	root := corpus(t)
	recs := load(t, root, fx.AttackTailTruncation)
	anc, err := fx.LoadAnchor(root + "/" + fx.AttackTailTruncation)
	if err != nil {
		t.Fatalf("loading anchor: %v", err)
	}

	// Fixture premise: the chain really is shorter than the anchor recorded.
	if len(recs) >= anc.EntryCount {
		t.Fatalf("truncation fixture holds %d records vs anchor count %d; nothing was truncated",
			len(recs), anc.EntryCount)
	}

	// ---- half 1: the documented LIMIT -------------------------------------
	// The chain alone PASSes. This is the honest boundary. If a future change
	// makes this report DETECTED, that change has either found a genuinely new
	// property (in which case the research measurement and this comment must be
	// updated together) or — far more likely — introduced a false claim.
	chainAlone := chain.Verify(recs)
	if chainAlone.Verdict != chain.PASS {
		t.Fatalf("chain-alone verified %s on a truncated tail, want PASS.\n"+
			"A truncated chain is a VALID chain; reporting detection here would claim a "+
			"property the chain does not have. Findings=%v", chainAlone.Verdict, chainAlone.Findings)
	}

	// ---- half 2: the MITIGATION -------------------------------------------
	withAnchor := anchor.Check(anchor.Anchor{
		HeadDigest: anc.HeadDigest, EntryCount: anc.EntryCount, Strength: anc.Strength,
	}, summarise(t, recs))
	if withAnchor.Verdict != anchor.DETECTED {
		t.Fatalf("chain-plus-anchor verified %s on a truncated tail, want DETECTED.\n"+
			"The anchor recorded head=%s count=%d; the chain presents %d records. "+
			"If the anchor cannot catch this, nothing can.",
			withAnchor.Verdict, anc.HeadDigest[:12], anc.EntryCount, len(recs))
	}
	if withAnchor.Reason == "" {
		t.Error("anchor detected the truncation but named no reason; a detection an operator " +
			"cannot act on is barely better than silence")
	}
}

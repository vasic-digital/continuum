// T306 — RED: DELETION + FULL RE-CHAIN. The documented honest boundary (S7).
//
// ###########################################################################
// #                          READ THIS BEFORE EDITING                        #
// #                                                                          #
// # THIS TEST ASSERTS THAT CHAIN-ALONE VERIFICATION *PASSES*.                #
// # THAT PASS IS THE DOCUMENTED LIMIT OF A HASH CHAIN AGAINST A SAME-USER    #
// # ADVERSARY. IT IS NOT A DEFECT, AND IT MUST NOT BE "FIXED".               #
// #                                                                          #
// # MEASURED (research D-2): on a purpose-built 100,000-entry ledger an      #
// # adversary deleted one entry and recomputed the ENTIRE chain in 0.43 s,   #
// # and chain-alone verification reported PASS. With an anchor it is         #
// # detected. That is why the security lives in the anchor, and why the      #
// # window of forgeability equals the anchor interval.                       #
// #                                                                          #
// # WHY it is structural, not an oversight: re-chaining after a deletion and #
// # appending honestly are THE SAME OPERATION — renumber, recompute every    #
// # prev_digest. A chain proves internal consistency and nothing else. It    #
// # cannot know what it should have contained.                               #
// #                                                                          #
// # Anyone who makes chain-alone report DETECTED here has made the system    #
// # claim a property it does not have. This test failing is how that is      #
// # caught. Do not delete it, do not skip it, do not invert it.              #
// #                                                                          #
// # Signing would not close this either: any key the producer can sign with  #
// # is a key the same-user adversary can read. The construction that WOULD   #
// # work locally is privilege separation (a signer under a different uid),   #
// # which needs an operator action and is recorded as an option (T336), not  #
// # as scheduled work.                                                       #
// ###########################################################################
package chain_test

import (
	"testing"

	"github.com/vasic-digital/continuum/pkg/anchor"
	"github.com/vasic-digital/continuum/pkg/chain"
	fx "github.com/vasic-digital/continuum/test/fixtures/chain"
)

// Paired mutation (T322/T317): make chain-alone report detection here -> this
// test MUST fail.
func TestChainAloneDoesNotDetectDeleteAndRechain_DocumentedBoundary(t *testing.T) {
	root := corpus(t)
	recs := load(t, root, fx.AttackDeleteRechain)
	anc, err := fx.LoadAnchor(root + "/" + fx.AttackDeleteRechain)
	if err != nil {
		t.Fatalf("loading anchor: %v", err)
	}

	// Fixture premise, asserted rather than assumed: a record really was
	// removed, AND the adversary really did rebuild the chain. If the fixture
	// were an ordinary un-rebuilt deletion, chain-alone WOULD detect it and the
	// PASS below would be asserting nothing at all.
	if len(recs) != corpusN-1 {
		t.Fatalf("delete+re-chain fixture holds %d records, want %d", len(recs), corpusN-1)
	}
	for i, r := range recs {
		if r.Seq != int64(i+1) {
			t.Fatalf("fixture record %d carries seq %d: the adversary did not renumber, so this "+
				"is a plain deletion and the boundary is not being exercised", i, r.Seq)
		}
	}

	// ---- the LIMIT --------------------------------------------------------
	chainAlone := chain.Verify(recs)
	if chainAlone.Verdict != chain.PASS {
		t.Fatalf("chain-alone verified %s on a deleted-and-rebuilt chain, want PASS.\n"+
			"This PASS is the DOCUMENTED BOUNDARY, not a defect: a rebuilt chain is "+
			"internally consistent and indistinguishable from an honest chain of the same "+
			"length. If this now reports detection, either the research measurement is wrong "+
			"and must be re-measured and re-recorded, or a false claim has been introduced.\n"+
			"Findings=%v", chainAlone.Verdict, chainAlone.Findings)
	}

	// ---- the MITIGATION ---------------------------------------------------
	// The anchor recorded head and count BEFORE the deletion. The rebuilt chain
	// is one record short and its head is a digest the anchor never saw.
	withAnchor := anchor.Check(anchor.Anchor{
		HeadDigest: anc.HeadDigest, EntryCount: anc.EntryCount, Strength: anc.Strength,
	}, summarise(t, recs))
	if withAnchor.Verdict != anchor.DETECTED {
		t.Fatalf("chain-plus-anchor verified %s, want DETECTED.\n"+
			"The anchor is the ONLY layer that catches this. If it does not, the system has "+
			"no defence against deletion at all and must say so rather than imply one.",
			withAnchor.Verdict)
	}
}

// TestBothUndetectedAttacksLeaveAValidChain states the reason the two boundary
// rows exist, as an executable claim rather than a comment. If a future change
// makes either fixture internally INVALID, the corresponding PASS assertion
// above would start passing for the wrong reason — it would be detecting a
// malformed fixture rather than exercising the boundary.
func TestBothUndetectedAttacksLeaveAValidChain(t *testing.T) {
	root := corpus(t)
	for _, id := range []string{fx.AttackTailTruncation, fx.AttackDeleteRechain} {
		recs := load(t, root, id)
		rep := chain.Verify(recs)
		if rep.Verdict != chain.PASS {
			t.Errorf("%s: chain-alone reported %s; both boundary fixtures must leave a "+
				"structurally valid chain, which is exactly why the chain cannot see them",
				id, rep.Verdict)
		}
	}
}

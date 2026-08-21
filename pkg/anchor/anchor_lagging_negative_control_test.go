// T307 — RED: NEGATIVE CONTROL. A legitimately-older anchor MUST still PASS.
//
// ###########################################################################
// # This is the false-positive guard for the FR-039 truncation check.        #
// #                                                                          #
// # §11.4.201(1): a false REFUSAL is a FAIL-bluff exactly as serious as a    #
// # false pass. A verifier that refuses a healthy chain sends people to fix  #
// # working code, and — worse — teaches them to ignore the verifier, which   #
// # is how a real detection later gets waved through.                        #
// #                                                                          #
// # The situation: the chain has grown by VALID appends since the last       #
// # anchor was written. Head has advanced, count has increased, and every    #
// # anchored record is intact. Nothing is wrong. This MUST verify clean.     #
// #                                                                          #
// # The discriminator against tail truncation is the direction of the count  #
// # plus the intactness of the anchored PREFIX:                              #
// #                                                                          #
// #   lagging anchor   chain.Count > anchor.EntryCount, prefix intact -> PASS#
// #   tail truncation  chain.Count < anchor.EntryCount              -> DETECT#
// #   history rewrite  chain.Count > anchor.EntryCount, prefix WRONG-> DETECT#
// #                                                                          #
// # Comparing head digests for EQUALITY collapses all three into "refuse",   #
// # which is why that is this test's paired mutation.                        #
// ###########################################################################
//
// Contract added by this file (see pkg/chain/attack_mutation_test.go for the
// full layering note — pkg/anchor imports NOTHING from pkg/chain):
//
//	type Verdict string; PASS | DETECTED | REFUSE | SKIP
//	type Anchor { HeadDigest string; EntryCount int; Strength string }
//	type ChainSummary { Head string; Count int; PrefixHead func(int)(string,error) }
//	type Result { Verdict Verdict; Reason string }
//	var ErrPrefixUnavailable error
//	func Check(Anchor, ChainSummary) Result
//
// Paired mutation (T322): assert head-digest equality instead of anchored-prefix
// containment -> this test MUST fail.
package anchor_test

import (
	"path/filepath"
	"testing"

	"github.com/vasic-digital/continuum/pkg/anchor"
	"github.com/vasic-digital/continuum/pkg/chain"
	fx "github.com/vasic-digital/continuum/test/fixtures/chain"
)

const corpusN = 12

func corpus(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := fx.Generate(root, corpusN); err != nil {
		t.Fatalf("generating fixture corpus: %v", err)
	}
	return root
}

func loadChain(t *testing.T, root, dir string) []chain.Record {
	t.Helper()
	b, err := fx.LoadChainBytes(filepath.Join(root, dir))
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	recs, err := chain.Decode(b)
	if err != nil {
		t.Fatalf("decoding %s: %v", dir, err)
	}
	return recs
}

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

func loadAnchor(t *testing.T, root, dir string) anchor.Anchor {
	t.Helper()
	a, err := fx.LoadAnchor(filepath.Join(root, dir))
	if err != nil {
		t.Fatalf("loading anchor %s: %v", dir, err)
	}
	return anchor.Anchor{HeadDigest: a.HeadDigest, EntryCount: a.EntryCount, Strength: a.Strength}
}

// TestLaggingAnchorVerifiesClean — the control itself.
func TestLaggingAnchorVerifiesClean(t *testing.T) {
	root := corpus(t)
	recs := loadChain(t, root, fx.NegControlDir)
	anc := loadAnchor(t, root, fx.NegControlDir)

	// Premise, asserted: the anchor really is behind, and the chain really did
	// grow by valid appends. A fixture where nothing lagged would pass this
	// test without exercising anything.
	if anc.EntryCount >= len(recs) {
		t.Fatalf("anchor count %d >= chain length %d: this fixture exercises no lag",
			anc.EntryCount, len(recs))
	}

	res := anchor.Check(anc, summarise(t, recs))
	if res.Verdict != anchor.PASS {
		t.Fatalf("a chain that grew by VALID appends since the anchor verified %s (%s), want PASS.\n"+
			"anchor: head=%s count=%d | chain: count=%d\n"+
			"Refusing here is a FAIL-bluff: it condemns healthy work and trains people to "+
			"ignore the verifier.", res.Verdict, res.Reason, short(anc.HeadDigest), anc.EntryCount, len(recs))
	}
}

// TestLaggingAndTruncationAreDistinguished asserts the two situations do not
// collapse into one verdict. A verifier that passes both, or refuses both, is
// not discriminating — it is guessing.
func TestLaggingAndTruncationAreDistinguished(t *testing.T) {
	root := corpus(t)

	lagRecs := loadChain(t, root, fx.NegControlDir)
	lagRes := anchor.Check(loadAnchor(t, root, fx.NegControlDir), summarise(t, lagRecs))

	truncRecs := loadChain(t, root, fx.AttackTailTruncation)
	truncRes := anchor.Check(loadAnchor(t, root, fx.AttackTailTruncation), summarise(t, truncRecs))

	if lagRes.Verdict == truncRes.Verdict {
		t.Fatalf("lagging anchor and tail truncation both verified %s. They are opposite "+
			"situations — one grew, one shrank — and a check that cannot tell them apart is "+
			"either refusing healthy chains or missing real truncation.", lagRes.Verdict)
	}
	if lagRes.Verdict != anchor.PASS {
		t.Errorf("lagging anchor: got %s, want PASS", lagRes.Verdict)
	}
	if truncRes.Verdict != anchor.DETECTED {
		t.Errorf("tail truncation: got %s, want DETECTED", truncRes.Verdict)
	}
}

// TestRewrittenHistoryIsDetectedEvenThoughTheChainGrew closes the gap the
// lagging rule could otherwise open: "the chain is longer, so it must be fine".
// Longer is only fine when the ANCHORED PREFIX still matches.
func TestRewrittenHistoryIsDetectedEvenThoughTheChainGrew(t *testing.T) {
	root := corpus(t)
	recs := loadChain(t, root, fx.NegControlDir)
	anc := loadAnchor(t, root, fx.NegControlDir)

	// Same count as the healthy control, but the anchored prefix no longer
	// hashes to what the anchor recorded.
	bad := anc
	bad.HeadDigest = "0000000000000000000000000000000000000000000000000000000000000000"

	res := anchor.Check(bad, summarise(t, recs))
	if res.Verdict != anchor.DETECTED {
		t.Fatalf("a chain longer than the anchor but whose anchored prefix does NOT match "+
			"verified %s, want DETECTED. 'The chain grew' is not on its own evidence of "+
			"health — the prefix must still be the one that was anchored.", res.Verdict)
	}
}

// TestUnavailablePrefixRefusesRatherThanPasses — if the verifier cannot obtain
// the anchored prefix it cannot decide, and undecided is REFUSE, never PASS
// (FR-030).
func TestUnavailablePrefixRefusesRatherThanPasses(t *testing.T) {
	root := corpus(t)
	recs := loadChain(t, root, fx.NegControlDir)
	anc := loadAnchor(t, root, fx.NegControlDir)

	cs := summarise(t, recs)
	cs.PrefixHead = func(int) (string, error) { return "", anchor.ErrPrefixUnavailable }

	res := anchor.Check(anc, cs)
	if res.Verdict == anchor.PASS {
		t.Fatal("the anchored prefix could not be read and the check reported PASS. " +
			"A verification that cannot complete must REFUSE and name the reason, never " +
			"report intact (FR-030).")
	}
	if res.Verdict != anchor.REFUSE {
		t.Errorf("got %s, want REFUSE", res.Verdict)
	}
	if res.Reason == "" {
		t.Error("REFUSE carried no reason")
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

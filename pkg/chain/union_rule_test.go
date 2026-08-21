// T310 — RED: the union rule AND what it must NOT demand (FR-026/027/028, S14).
//
// Two halves, and the second is the one that usually gets dropped:
//
//	FR-026  a state-changing call (write, exec, deploy) REQUIRES an entry
//	FR-028  a read CITED AS EVIDENCE REQUIRES an entry
//	FR-027  a read that is NOT cited requires NONE — and the chain must verify
//	        COMPLETE without it
//
// FR-027 is a false-positive guard with two jobs. It bounds chain volume to the
// measured 2,000-5,000 entries/day (10^4 burst) rather than logging every read.
// And it stops the gate refusing correct behaviour: a gate that demands an
// entry for every read is not stricter, it is wrong, and per §11.4.201(1) a
// false refusal is a FAIL-bluff exactly as serious as a false pass.
//
// Contract added by this file:
//
//	type Call { Kind string; Cited bool }   // Kind: write|exec|deploy|read
//	func RequiresEntry(Call) bool
//	func VerifyComplete(recs []Record, calls []Call) Report
//
// Paired mutation (T318): require an entry for every read -> the FR-027 half
// MUST fail while the FR-026/028 halves still pass.
package chain_test

import (
	"testing"

	"github.com/vasic-digital/continuum/pkg/chain"
)

func TestUnionRule_RequiresEntryForStateChangingCalls(t *testing.T) {
	for _, kind := range []string{chain.CallWrite, chain.CallExec, chain.CallDeploy} {
		if !chain.RequiresEntry(chain.Call{Kind: kind}) {
			t.Errorf("%s is state-changing and MUST require a chain entry (FR-026)", kind)
		}
		// Citation is irrelevant for a state-changing call: it changed the
		// world whether or not anyone cited it.
		if !chain.RequiresEntry(chain.Call{Kind: kind, Cited: true}) {
			t.Errorf("%s with Cited=true must still require an entry", kind)
		}
	}
}

func TestUnionRule_RequiresEntryForCitedRead(t *testing.T) {
	if !chain.RequiresEntry(chain.Call{Kind: chain.CallRead, Cited: true}) {
		t.Error("a read CITED AS EVIDENCE MUST require a chain entry (FR-028): a claim resting " +
			"on a read that was never recorded rests on nothing")
	}
}

// TestUnionRule_UncitedReadRequiresNoEntry is the FR-027 half — the assertion
// that is a hard requirement, not a comment.
func TestUnionRule_UncitedReadRequiresNoEntry(t *testing.T) {
	if chain.RequiresEntry(chain.Call{Kind: chain.CallRead, Cited: false}) {
		t.Fatal("an UNCITED read must NOT require a chain entry (FR-027). Demanding one is not " +
			"stricter — it refuses correct behaviour and inflates the chain past its measured " +
			"volume budget")
	}
}

// TestChainVerifiesCompleteWithoutUncitedReads is the same rule stated where it
// actually bites: at verification. A chain missing entries only for uncited
// reads is COMPLETE.
func TestChainVerifiesCompleteWithoutUncitedReads(t *testing.T) {
	root := corpus(t)
	recs := load(t, root, chainGoldenGood)

	calls := []chain.Call{
		{Kind: chain.CallExec},
		{Kind: chain.CallRead, Cited: true},
		{Kind: chain.CallRead, Cited: false}, // no entry exists for this one
		{Kind: chain.CallRead, Cited: false},
		{Kind: chain.CallWrite},
	}
	rep := chain.VerifyComplete(recs, calls)
	if rep.Verdict != chain.PASS {
		t.Fatalf("chain verified %s with two uncited reads unrecorded, want PASS (FR-027). "+
			"Findings=%v", rep.Verdict, rep.Findings)
	}
}

// chainGoldenGood is spelled out here rather than imported so this file states
// which fixture it depends on.
const chainGoldenGood = "golden_good"

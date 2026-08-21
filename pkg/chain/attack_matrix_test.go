// T314 — RED: attack-matrix COMPLETENESS.
//
// This is the guard on the guards. Every other test in this package asserts
// something about one fixture; this one asserts the SET of fixtures is still
// the measured five, and — the load-bearing half — that the two rows whose
// chain-alone result is PASS are still present.
//
// Without it, someone could quietly delete the tail-truncation and
// delete+re-chain rows and be left with a matrix that shows only detections.
// Every remaining test would pass. The suite would look stronger. It would be
// claiming a property the system does not have, which is the precise failure
// this feature exists to prevent.
//
// Paired mutation (T301/T318): delete the delete+re-chain row from the corpus
// -> this test MUST fail.
package chain_test

import (
	"testing"

	fx "github.com/vasic-digital/continuum/test/fixtures/chain"
)

func TestAttackMatrixEnumeratesExactlyTheMeasuredRows(t *testing.T) {
	root := corpus(t)
	mx, err := fx.LoadMatrix(root)
	if err != nil {
		t.Fatalf("loading matrix: %v", err)
	}

	want := map[string]bool{
		fx.AttackMutation:       true,  // chain alone detects
		fx.AttackDeletion:       true,  // chain alone detects
		fx.AttackReorder:        true,  // chain alone detects
		fx.AttackTailTruncation: false, // MEASURED: chain alone does NOT detect
		fx.AttackDeleteRechain:  false, // MEASURED: chain alone does NOT detect
	}

	if len(mx.Attacks) != len(want) {
		t.Fatalf("matrix holds %d rows, want exactly %d measured rows: %v",
			len(mx.Attacks), len(want), mx.Attacks)
	}
	seen := map[string]bool{}
	for _, a := range mx.Attacks {
		exp, ok := want[a.ID]
		if !ok {
			t.Errorf("matrix carries unmeasured row %q; every row must trace to a measurement", a.ID)
			continue
		}
		seen[a.ID] = true
		if a.ChainAloneDetects != exp {
			t.Errorf("%s: chain_alone_detects=%v, MEASURED %v — changing a measured result "+
				"requires re-measuring and re-recording, not editing the table", a.ID, a.ChainAloneDetects, exp)
		}
		if !a.AnchorDetects {
			t.Errorf("%s: anchor_detects=false; with an anchor, all five measured attacks are detected", a.ID)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("measured attack row %q is MISSING from the matrix", id)
		}
	}

	// The honest-boundary rows, asserted by name so their removal is loud.
	undetected := map[string]bool{}
	for _, id := range mx.UndetectedByChainAlone {
		undetected[id] = true
	}
	for _, id := range []string{fx.AttackTailTruncation, fx.AttackDeleteRechain} {
		if !undetected[id] {
			t.Errorf("%q is missing from undetected_by_chain_alone. Dropping an honest-boundary "+
				"row leaves a matrix that only shows detections and overstates what the chain proves.", id)
		}
	}
	if len(undetected) != 2 {
		t.Errorf("undetected_by_chain_alone holds %d rows (%v), want exactly 2",
			len(undetected), mx.UndetectedByChainAlone)
	}
}

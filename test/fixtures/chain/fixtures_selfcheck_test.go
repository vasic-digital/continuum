// Self-check for the attack-fixture corpus (T301).
//
// A corpus of "bad" fixtures is only worth something if each one is actually
// bad, and bad in the specific way its downstream test assumes. A generator
// that quietly emitted an unmodified copy would make every downstream attack
// test pass while proving nothing — the exact vacuous-green failure this whole
// feature exists to prevent. So this file re-derives each fixture's difference
// FROM THE EMITTED BYTES and asserts it matches the declared intent.
//
// It also carries the corpus-level guard on the honest boundary: the two
// attacks the chain alone does not detect are exactly the two that leave a
// structurally VALID chain, and that identity is asserted rather than assumed.
package chainfixtures

import (
	"bytes"
	"path/filepath"
	"testing"
)

const fixtureN = 12

// buildCorpus emits a fresh corpus into a temp dir and returns its root.
func buildCorpus(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := Generate(root, fixtureN); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return root
}

func lines(b []byte) [][]byte {
	return bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
}

// TestGoldenGoodIsAValidChain is the precondition for everything else: if the
// good fixture were not valid, "differs from good" would be meaningless.
func TestGoldenGoodIsAValidChain(t *testing.T) {
	root := buildCorpus(t)
	recs, err := LoadChain(filepath.Join(root, GoldenGoodDir))
	if err != nil {
		t.Fatalf("LoadChain(golden_good): %v", err)
	}
	if len(recs) != fixtureN {
		t.Fatalf("golden-good holds %d records, want %d", len(recs), fixtureN)
	}
	if ok, why := IsInternallyValid(recs); !ok {
		t.Fatalf("golden-good is not a valid chain: %s", why)
	}
	anc, err := LoadAnchor(filepath.Join(root, GoldenGoodDir))
	if err != nil {
		t.Fatalf("LoadAnchor(golden_good): %v", err)
	}
	head, err := Head(recs)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if anc.HeadDigest != head {
		t.Errorf("anchor head %q != chain head %q", anc.HeadDigest, head)
	}
	if anc.EntryCount != fixtureN {
		t.Errorf("anchor entry_count %d != %d", anc.EntryCount, fixtureN)
	}
	// FR-038: the recorded strength is "policy" today. Recording "mechanism"
	// without a probe result is the theatre this feature exists to prevent.
	if anc.Strength != StrengthPolicy {
		t.Errorf("anchor strength %q, want %q (policy-forbidden is not mechanically-prevented)", anc.Strength, StrengthPolicy)
	}
}

// TestEveryGoldenBadDiffersFromGoldenGood is the anti-vacuity guard.
// The paired mutation for T301 targets exactly this assertion: make one
// generator emit an unmodified copy and this test MUST fail.
func TestEveryGoldenBadDiffersFromGoldenGood(t *testing.T) {
	root := buildCorpus(t)
	good, err := LoadChainBytes(filepath.Join(root, GoldenGoodDir))
	if err != nil {
		t.Fatalf("LoadChainBytes(golden_good): %v", err)
	}
	for _, a := range Attacks {
		bad, err := LoadChainBytes(filepath.Join(root, a.ID))
		if err != nil {
			t.Fatalf("LoadChainBytes(%s): %v", a.ID, err)
		}
		if bytes.Equal(good, bad) {
			t.Errorf("%s is BYTE-IDENTICAL to golden-good: this fixture proves nothing, "+
				"and every test asserting against it would pass vacuously", a.ID)
		}
	}
}

// TestEachAttackDiffersInExactlyItsIntendedWay re-derives each tamper from the
// emitted bytes. "Differs" is not enough — a fixture that differs in the WRONG
// way sends its downstream test at the wrong property.
func TestEachAttackDiffersInExactlyItsIntendedWay(t *testing.T) {
	root := buildCorpus(t)
	goodB, err := LoadChainBytes(filepath.Join(root, GoldenGoodDir))
	if err != nil {
		t.Fatalf("LoadChainBytes(golden_good): %v", err)
	}
	goodL := lines(goodB)
	goodR, err := LoadChain(filepath.Join(root, GoldenGoodDir))
	if err != nil {
		t.Fatalf("LoadChain(golden_good): %v", err)
	}

	t.Run("mutation_changes_exactly_one_line_and_that_line_is_exit_status", func(t *testing.T) {
		recs, err := LoadChain(filepath.Join(root, AttackMutation))
		if err != nil {
			t.Fatalf("LoadChain: %v", err)
		}
		badB, _ := LoadChainBytes(filepath.Join(root, AttackMutation))
		badL := lines(badB)
		if len(badL) != len(goodL) {
			t.Fatalf("mutation changed the record count (%d -> %d); it must change content only", len(goodL), len(badL))
		}
		diff := 0
		idx := -1
		for i := range goodL {
			if !bytes.Equal(goodL[i], badL[i]) {
				diff++
				idx = i
			}
		}
		if diff != 1 {
			t.Fatalf("mutation altered %d lines, want exactly 1", diff)
		}
		if goodR[idx].ExitStatus == recs[idx].ExitStatus {
			t.Fatalf("line %d differs but exit_status is unchanged (%d); the declared tamper did not happen",
				idx, recs[idx].ExitStatus)
		}
		// The narrative that matters: a recorded FAILURE was rewritten as a PASS.
		if !(goodR[idx].ExitStatus != 0 && recs[idx].ExitStatus == 0) {
			t.Errorf("mutation should rewrite a non-zero exit_status to 0; got %d -> %d",
				goodR[idx].ExitStatus, recs[idx].ExitStatus)
		}
		if ok, _ := IsInternallyValid(recs); ok {
			t.Errorf("mutation left a VALID chain; then chain-alone could not detect it and the matrix row is wrong")
		}
	})

	t.Run("deletion_removes_one_record_and_leaves_survivors_byte_identical", func(t *testing.T) {
		badB, _ := LoadChainBytes(filepath.Join(root, AttackDeletion))
		badL := lines(badB)
		if len(badL) != len(goodL)-1 {
			t.Fatalf("deletion produced %d records, want %d", len(badL), len(goodL)-1)
		}
		// Every surviving line must appear verbatim in golden-good: this is
		// what makes it a deletion rather than a re-chain.
		for i, ln := range badL {
			found := false
			for _, g := range goodL {
				if bytes.Equal(ln, g) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("deletion rewrote record %d; a deletion must not re-chain (that is the delete_rechain attack)", i)
			}
		}
		recs, _ := LoadChain(filepath.Join(root, AttackDeletion))
		if ok, _ := IsInternallyValid(recs); ok {
			t.Errorf("deletion left a VALID chain; a non-re-chained deletion must leave a broken link")
		}
	})

	t.Run("reorder_permutes_positions_without_changing_content", func(t *testing.T) {
		badB, _ := LoadChainBytes(filepath.Join(root, AttackReorder))
		badL := lines(badB)
		if len(badL) != len(goodL) {
			t.Fatalf("reorder changed the record count (%d -> %d)", len(goodL), len(badL))
		}
		// Same multiset of lines, different order, exactly two positions moved.
		moved := 0
		for i := range goodL {
			if !bytes.Equal(goodL[i], badL[i]) {
				moved++
			}
		}
		if moved != 2 {
			t.Fatalf("reorder moved %d positions, want exactly 2 (an adjacent swap)", moved)
		}
		for _, ln := range badL {
			found := false
			for _, g := range goodL {
				if bytes.Equal(ln, g) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("reorder rewrote a record; it must permute, not modify")
			}
		}
		recs, _ := LoadChain(filepath.Join(root, AttackReorder))
		if ok, _ := IsInternallyValid(recs); ok {
			t.Errorf("reorder left a VALID chain; a positional swap must break the walk")
		}
	})

	t.Run("tail_truncation_is_a_byte_identical_strict_prefix", func(t *testing.T) {
		badB, _ := LoadChainBytes(filepath.Join(root, AttackTailTruncation))
		badL := lines(badB)
		if len(badL) >= len(goodL) {
			t.Fatalf("truncation produced %d records, must be fewer than %d", len(badL), len(goodL))
		}
		for i := range badL {
			if !bytes.Equal(badL[i], goodL[i]) {
				t.Fatalf("truncation altered record %d; it must keep an untouched prefix", i)
			}
		}
	})

	t.Run("delete_rechain_removes_a_record_and_rebuilds_a_consistent_chain", func(t *testing.T) {
		recs, err := LoadChain(filepath.Join(root, AttackDeleteRechain))
		if err != nil {
			t.Fatalf("LoadChain: %v", err)
		}
		if len(recs) != len(goodR)-1 {
			t.Fatalf("delete+re-chain produced %d records, want %d", len(recs), len(goodR)-1)
		}
		// The load-bearing property. If this fixture were NOT internally valid
		// it would be an ordinary deletion, chain-alone WOULD detect it, and
		// T306's documented-boundary PASS would be asserting nothing.
		if ok, why := IsInternallyValid(recs); !ok {
			t.Fatalf("delete+re-chain is NOT internally valid (%s); the fixture is an ordinary "+
				"deletion and the honest-boundary test built on it would be vacuous", why)
		}
		// And it must genuinely differ from a truncation: content was removed
		// from the MIDDLE, so it is not a prefix of golden-good.
		badB, _ := LoadChainBytes(filepath.Join(root, AttackDeleteRechain))
		badL := lines(badB)
		if len(badL) > 0 && len(goodL) > 0 && bytes.Equal(badL[len(badL)-1], goodL[len(badL)-1]) {
			t.Errorf("delete+re-chain looks like a prefix of golden-good; it must re-chain, not truncate")
		}
	})
}

// TestHonestBoundaryIsStructural asserts the identity that EXPLAINS the two
// PASS results: an attack is undetectable by the chain alone exactly when it
// leaves a structurally valid chain. Asserting the identity (rather than just
// the two ids) means a future edit cannot flip a matrix flag without also
// making the corpus contradict itself.
func TestHonestBoundaryIsStructural(t *testing.T) {
	root := buildCorpus(t)
	for _, a := range Attacks {
		recs, err := LoadChain(filepath.Join(root, a.ID))
		if err != nil {
			t.Fatalf("LoadChain(%s): %v", a.ID, err)
		}
		valid, why := IsInternallyValid(recs)
		if valid != a.LeavesValidChain {
			t.Errorf("%s: leaves_valid_chain declared %v but the emitted corpus is valid=%v (%s)",
				a.ID, a.LeavesValidChain, valid, why)
		}
		if a.ChainAloneDetects == a.LeavesValidChain {
			t.Errorf("%s: chain_alone_detects=%v and leaves_valid_chain=%v cannot both hold — "+
				"a chain can only prove internal consistency, so it detects exactly the attacks "+
				"that break it", a.ID, a.ChainAloneDetects, a.LeavesValidChain)
		}
		if !a.AnchorDetects {
			t.Errorf("%s: every measured attack is detected WITH an anchor; anchor_detects must be true", a.ID)
		}
	}
}

// TestLaggingAnchorNegativeControlIsGenuinelyLagging proves the false-positive
// guard's fixture really is a lagging anchor and not a disguised truncation.
// §11.4.201(1): a false refusal is a FAIL-bluff exactly as serious as a false
// pass, so the control that catches it must itself be verified.
func TestLaggingAnchorNegativeControlIsGenuinelyLagging(t *testing.T) {
	root := buildCorpus(t)
	goodB, _ := LoadChainBytes(filepath.Join(root, GoldenGoodDir))
	ncB, err := LoadChainBytes(filepath.Join(root, NegControlDir))
	if err != nil {
		t.Fatalf("LoadChainBytes(neg control): %v", err)
	}
	// The CHAIN is untouched — nothing was tampered with. Only the anchor is old.
	if !bytes.Equal(goodB, ncB) {
		t.Fatalf("negative-control chain differs from golden-good; the control must be an UNTAMPERED chain")
	}
	recs, _ := LoadChain(filepath.Join(root, NegControlDir))
	if ok, why := IsInternallyValid(recs); !ok {
		t.Fatalf("negative-control chain is not valid: %s", why)
	}
	anc, err := LoadAnchor(filepath.Join(root, NegControlDir))
	if err != nil {
		t.Fatalf("LoadAnchor: %v", err)
	}
	// Discriminator, half 1: the chain is LONGER than the anchor. Under tail
	// truncation the chain is SHORTER. Comparing counts distinguishes them;
	// comparing head digests for equality does NOT — it refuses both, which is
	// exactly the mutation T307 names.
	if anc.EntryCount >= len(recs) {
		t.Fatalf("anchor entry_count %d >= chain length %d: this is not a LAGGING anchor",
			anc.EntryCount, len(recs))
	}
	// Discriminator, half 2: the anchored PREFIX is intact — the anchor's head
	// is the digest of the chain's first entry_count records.
	prefixHead, err := Head(recs[:anc.EntryCount])
	if err != nil {
		t.Fatalf("Head(prefix): %v", err)
	}
	if anc.HeadDigest != prefixHead {
		t.Fatalf("anchor head %q is not the digest of the chain's first %d records (%q); "+
			"the control would then be a genuine alteration, not a lagging anchor",
			anc.HeadDigest, anc.EntryCount, prefixHead)
	}
	// And the anchor head must NOT equal the current head, or the fixture is
	// not exercising lag at all and the guard would pass trivially.
	curHead, _ := Head(recs)
	if anc.HeadDigest == curHead {
		t.Fatalf("anchor head equals the current chain head; the fixture exercises no lag")
	}
	// Contrast with truncation, asserted here so the two fixtures are provably
	// different situations rather than two names for one shape.
	trunc, err := LoadChain(filepath.Join(root, AttackTailTruncation))
	if err != nil {
		t.Fatalf("LoadChain(truncation): %v", err)
	}
	truncAnc, _ := LoadAnchor(filepath.Join(root, AttackTailTruncation))
	if len(trunc) >= truncAnc.EntryCount {
		t.Fatalf("truncation fixture has %d records vs anchor count %d; truncation must leave FEWER",
			len(trunc), truncAnc.EntryCount)
	}
}

// TestMatrixEnumeratesExactlyTheMeasuredRows guards the emitted matrix at the
// corpus layer. pkg/chain/attack_matrix_test.go (T314) asserts the same closed
// set in-package once the chain implementation lands; this is the layer that
// can run today.
func TestMatrixEnumeratesExactlyTheMeasuredRows(t *testing.T) {
	root := buildCorpus(t)
	mx, err := LoadMatrix(root)
	if err != nil {
		t.Fatalf("LoadMatrix: %v", err)
	}
	want := []string{AttackMutation, AttackDeletion, AttackReorder, AttackTailTruncation, AttackDeleteRechain}
	if len(mx.Attacks) != len(want) {
		t.Fatalf("matrix holds %d rows, want exactly %d measured rows", len(mx.Attacks), len(want))
	}
	got := map[string]AttackSpec{}
	for _, a := range mx.Attacks {
		got[a.ID] = a
	}
	for _, id := range want {
		if _, ok := got[id]; !ok {
			t.Errorf("matrix is missing measured attack row %q", id)
		}
	}
	// The honest-boundary rows, named explicitly so deleting one is loud.
	wantUndetected := map[string]bool{AttackTailTruncation: true, AttackDeleteRechain: true}
	if len(mx.UndetectedByChainAlone) != len(wantUndetected) {
		t.Fatalf("undetected_by_chain_alone holds %d rows (%v), want exactly 2 — dropping one would "+
			"leave a matrix that only shows detections and overstates what the chain proves",
			len(mx.UndetectedByChainAlone), mx.UndetectedByChainAlone)
	}
	for _, id := range mx.UndetectedByChainAlone {
		if !wantUndetected[id] {
			t.Errorf("unexpected row %q in undetected_by_chain_alone", id)
		}
		if got[id].ChainAloneDetects {
			t.Errorf("%q is listed as undetected but its row says chain_alone_detects=true", id)
		}
	}
	if mx.Note == "" {
		t.Error("matrix carries no note; the two PASS rows must be explained in the artifact itself, " +
			"or a future reader will read them as a defect")
	}
	if mx.GoldenGoodEntries != fixtureN {
		t.Errorf("matrix golden_good_entries=%d, want %d", mx.GoldenGoodEntries, fixtureN)
	}
}

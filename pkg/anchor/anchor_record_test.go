// T311 — RED: the anchor records the head digest AND the entry count (FR-037).
//
// Why entry_count is not optional: head_digest alone makes WHOLESALE DELETION
// silent. Delete the entire store and there is no head to compare — an
// absence, and an absence with nothing to measure it against reads as "nothing
// to check" rather than "everything is gone". entry_count is what turns that
// silence into a DETECTED ABSENCE.
//
// Paired mutation (T320): make entry_count optional -> this test MUST fail.
package anchor_test

import (
	"encoding/json"
	"testing"

	"github.com/vasic-digital/continuum/pkg/anchor"
)

func TestAnchorCarriesHeadDigestAndEntryCount(t *testing.T) {
	root := corpus(t)
	a := loadAnchor(t, root, "golden_good")

	if a.HeadDigest == "" {
		t.Error("anchor has no head_digest")
	}
	if a.EntryCount <= 0 {
		t.Errorf("anchor entry_count=%d; it must record how many entries were anchored", a.EntryCount)
	}
	if err := anchor.Validate(a); err != nil {
		t.Errorf("a complete anchor was rejected: %v", err)
	}
}

func TestAnchorMissingEntryCountIsRefused(t *testing.T) {
	// Decoded from JSON that simply lacks the field — the realistic shape of a
	// writer that "forgot" it, not a hand-built struct.
	var a anchor.Anchor
	if err := json.Unmarshal([]byte(`{"head_digest":"`+
		`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`+
		`","anchor_strength":"policy"}`), &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := anchor.Validate(a); err == nil {
		t.Fatal("an anchor with no entry_count was ACCEPTED. Without the count, deleting the " +
			"whole store produces silence rather than a detected absence — which is the single " +
			"thing this field exists to prevent (FR-037).")
	}
}

func TestAnchorMissingHeadDigestIsRefused(t *testing.T) {
	if err := anchor.Validate(anchor.Anchor{EntryCount: 12, Strength: anchor.StrengthPolicy}); err == nil {
		t.Fatal("an anchor with no head_digest was ACCEPTED; there is then nothing to compare against")
	}
}

// TestZeroEntryCountIsRefused closes the loophole the previous test opens. An
// adversary who deletes the store and presents a count of 0 would otherwise
// hand over a "consistent" pair. You do not anchor an empty chain, so 0 is
// absence, not a legitimate value.
func TestZeroEntryCountIsRefused(t *testing.T) {
	if err := anchor.Validate(anchor.Anchor{
		HeadDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EntryCount: 0, Strength: anchor.StrengthPolicy,
	}); err == nil {
		t.Fatal("entry_count=0 was ACCEPTED; an emptied store would then verify consistent " +
			"against a zero-count anchor")
	}
}

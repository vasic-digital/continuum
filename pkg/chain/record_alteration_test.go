// T309 — RED: an evidence record altered after acceptance is reported (FR-009).
//
// The point is COVERAGE, not merely detection: the digest must cover the WHOLE
// canonical record. A field left outside the digest is a field an adversary may
// rewrite freely, and the two fields that matter most here — exit_status and
// evidence_class — are exactly the ones a bluff needs to change (a failure
// rewritten as a pass; a source-layer artifact relabelled as runtime evidence).
//
// Paired mutation (T317): exclude exit_status from the canonical bytes -> the
// exit_status subtest MUST fail while the others still pass. A mutation that
// broke every field would not prove the digest's coverage is per-field.
package chain_test

import (
	"testing"

	"github.com/vasic-digital/continuum/pkg/chain"
	fx "github.com/vasic-digital/continuum/test/fixtures/chain"
)

func TestEveryRecordFieldIsCoveredByTheDigest(t *testing.T) {
	root := corpus(t)
	base := load(t, root, fx.GoldenGoodDir)
	if len(base) < 3 {
		t.Fatalf("need >=3 records, got %d", len(base))
	}

	// Altering a record must break the link its SUCCESSOR carries, so pick a
	// record that has one.
	const target = 1

	cases := []struct {
		field string
		alter func(*chain.Record)
	}{
		{"command", func(r *chain.Record) { r.Command = "run-gate --case 999" }},
		{"exit_status", func(r *chain.Record) { r.ExitStatus = r.ExitStatus + 1 }},
		{"artifact_path", func(r *chain.Record) { r.ArtifactPath = "qa-results/elsewhere.log" }},
		{"evidence_class", func(r *chain.Record) { r.EvidenceClass = "source" }},
		{"author_session_id", func(r *chain.Record) { r.AuthorSessionID = "producer-session-a" }},
		{"independence_tier", func(r *chain.Record) { r.IndependenceTier = "capability" }},
	}

	// Control: unaltered, the chain verifies clean. Without this, "every
	// alteration is detected" could be satisfied by a verifier that detects
	// everything, including the truth (§11.4.201(1)).
	if rep := chain.Verify(base); rep.Verdict != chain.PASS {
		t.Fatalf("unaltered chain verified %s; the per-field results below would be meaningless",
			rep.Verdict)
	}

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			recs := make([]chain.Record, len(base))
			copy(recs, base)
			before, err := chain.Digest(recs[target])
			if err != nil {
				t.Fatalf("digest before: %v", err)
			}
			tc.alter(&recs[target])
			after, err := chain.Digest(recs[target])
			if err != nil {
				t.Fatalf("digest after: %v", err)
			}
			// The direct statement of coverage: change the field, the digest
			// must move. If it does not, the field is outside the canonical
			// bytes and nothing downstream can protect it.
			if before == after {
				t.Fatalf("altering %s did not change the record digest — the field is OUTSIDE "+
					"the canonical bytes and can be rewritten at will", tc.field)
			}
			rep := chain.Verify(recs)
			if rep.Verdict != chain.DETECTED {
				t.Fatalf("altering %s verified %s, want DETECTED", tc.field, rep.Verdict)
			}
		})
	}
}

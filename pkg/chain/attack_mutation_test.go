// T302 — RED: chain-alone verification detects MUTATION.
//
// ############################ CONTRACT (read once) ##########################
// These tests are written BEFORE pkg/chain exists (Constitution Principle IV:
// a test authored after its implementation proves only that it agrees with the
// code, never that it catches the defect). They therefore FAIL TO BUILD today.
// That is the intended RED. T317/T318 turn them GREEN.
//
// The API they pin down — deliberately minimal, and layered so no cycle forms:
//
//	pkg/chain   — chain-alone. Knows nothing about anchors.
//	   type Record  { Seq, Ts, Command, ExitStatus, ArtifactPath,
//	                  EvidenceClass, AuthorSessionID, IndependenceTier,
//	                  PrevDigest }   // declaration order IS canonical order
//	   type Verdict string; PASS | DETECTED | REFUSE
//	   type Finding { Kind string; Seq int64; Detail string }
//	   type Report  { Verdict Verdict; Findings []Finding }
//	   func Digest(Record) (string, error)
//	   func Decode([]byte) ([]Record, error)   // malformed line => error
//	   func Verify([]Record) Report
//
//	pkg/anchor  — the external comparison. Imports NOTHING from pkg/chain.
//	pkg/verify  — composes the two and reports them as SEPARATE results.
//
// The on-disk JSONL corpus in test/fixtures/chain is the byte contract: a
// pkg/chain that cannot verify golden_good/chain.jsonl has diverged from it.
//
// NOTE for T317: test/fixtures/chain currently declares its own Record struct
// because pkg/chain did not exist when the corpus was built. When this package
// lands, the fixtures MUST be refactored to import chain.Record so the module
// carries exactly ONE record type (§11.4.251 — no byte-identical forks). The
// canonicaliser and hash are already shared (model.Canonical / hash.Sum).
// ###########################################################################
package chain_test

import (
	"path/filepath"
	"testing"

	"github.com/vasic-digital/continuum/pkg/chain"
	fx "github.com/vasic-digital/continuum/test/fixtures/chain"
)

const corpusN = 12

// corpus emits a fresh fixture corpus and returns its root. Shared by every
// test in this package.
func corpus(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := fx.Generate(root, corpusN); err != nil {
		t.Fatalf("generating fixture corpus: %v", err)
	}
	return root
}

// load reads one fixture directory's chain through pkg/chain's OWN decoder,
// which is what makes the on-disk corpus a real contract rather than a
// convention two packages happen to share.
func load(t *testing.T, root, dir string) []chain.Record {
	t.Helper()
	b, err := fx.LoadChainBytes(filepath.Join(root, dir))
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	recs, err := chain.Decode(b)
	if err != nil {
		t.Fatalf("pkg/chain cannot decode the fixture corpus (%s): %v", dir, err)
	}
	return recs
}

// findingAtSeq reports whether some finding of the given kind names seq.
func findingAtSeq(rep chain.Report, kind string, seq int64) bool {
	for _, f := range rep.Findings {
		if f.Kind == kind && f.Seq == seq {
			return true
		}
	}
	return false
}

// TestGoldenGoodVerifiesClean is the precondition. If the verifier refused a
// healthy chain, every "detected" below would be meaningless — a verifier that
// refuses everything detects everything (§11.4.201(1)).
func TestGoldenGoodVerifiesClean(t *testing.T) {
	root := corpus(t)
	rep := chain.Verify(load(t, root, fx.GoldenGoodDir))
	if rep.Verdict != chain.PASS {
		t.Fatalf("golden-good verified %s (%v); a verifier that refuses a healthy chain "+
			"cannot be trusted when it reports a detection", rep.Verdict, rep.Findings)
	}
}

// TestMutationIsDetected — a recorded FAILURE rewritten as a PASS. The record
// changed but its successor still carries the old prev_digest, so the walk
// breaks at the mutated record.
//
// Paired mutation (T317): stub the prev_digest comparison to always match ->
// this test MUST fail.
func TestMutationIsDetected(t *testing.T) {
	root := corpus(t)
	recs := load(t, root, fx.AttackMutation)

	rep := chain.Verify(recs)
	if rep.Verdict != chain.DETECTED {
		t.Fatalf("mutation verified %s, want DETECTED — an altered exit_status went unreported",
			rep.Verdict)
	}
	// The seq that was tampered with is record index 2 => seq 3.
	const mutatedSeq = int64(3)
	if !findingAtSeq(rep, chain.KindChainGap, mutatedSeq) {
		t.Errorf("detection did not report %s at seq %d; findings=%v — naming the seq is what "+
			"makes the report actionable rather than a bare 'something is wrong'",
			chain.KindChainGap, mutatedSeq, rep.Findings)
	}
}

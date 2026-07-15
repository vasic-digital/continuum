// Package verify is continuum's deterministic verifier and its self-validating
// oracle.
//
// Verify (§11.4.201/§11.4.205(3)(4)): assert the REAL condition from the
// authoritative source. For the committed HEAD snapshot it re-reads every blob
// integrity-checked (bytes must hash to their id — the Merkle guarantee) AND
// re-serializes each decoded value canonically and asserts it hashes back to
// the referenced id (a determinism / byte-identical round-trip). No timestamp
// is ever consulted.
//
// SelfCheck (§11.4.107(10)): the analyzer is itself proven not to bluff. It
// runs three fixtures: golden-good MUST pass, golden-bad (a tampered blob) MUST
// be detected as FAIL, and a negative-control (a legitimately older-but-valid
// snapshot) MUST pass — proving the verifier distinguishes a LAGGING copy from
// a TAMPERED one (§11.4.201/§11.4.206(3)). A verifier that passes its
// golden-bad, or fails golden-good or the negative-control, is itself a bluff.
package verify

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vasic-digital/continuum/pkg/hash"
	"github.com/vasic-digital/continuum/pkg/model"
	"github.com/vasic-digital/continuum/pkg/snapshot"
	"github.com/vasic-digital/continuum/pkg/store"
)

// Verdict is the closed result vocabulary (§11.4.116).
type Verdict string

const (
	PASS Verdict = "PASS"
	FAIL Verdict = "FAIL"
	SKIP Verdict = "SKIP"
)

// Result carries a verdict + human detail + the reason for a SKIP.
type Result struct {
	Verdict Verdict
	Detail  string
}

// Verify checks the integrity + determinism of the current HEAD snapshot.
func Verify(e *snapshot.Engine) Result {
	head, err := e.Head()
	if err != nil {
		return Result{FAIL, fmt.Sprintf("reading HEAD: %v", err)}
	}
	if head == "" {
		return Result{SKIP, "no committed snapshot (topology_unsupported: nothing to verify)"}
	}
	// Manifest integrity + determinism round-trip.
	snap, err := e.Store.GetSnapshot(head) // GetBlob asserts bytes hash to head
	if err != nil {
		return Result{FAIL, fmt.Sprintf("HEAD snapshot integrity: %v", err)}
	}
	if b, err := model.Canonical(snap); err != nil || hash.Sum(b) != head {
		return Result{FAIL, fmt.Sprintf("HEAD manifest is not a deterministic round-trip (re-serialized hash != %s)", hash.Short(head, 12))}
	}
	// Every referenced stream blob: integrity + determinism round-trip.
	for _, sid := range model.SortedStreamIDs(snap) {
		cid := snap.Streams[sid]
		st, err := e.Store.GetState(cid) // GetBlob asserts bytes hash to cid
		if err != nil {
			return Result{FAIL, fmt.Sprintf("stream %q blob integrity: %v", sid, err)}
		}
		b, err := model.Canonical(st)
		if err != nil {
			return Result{FAIL, fmt.Sprintf("stream %q canonicalize: %v", sid, err)}
		}
		if hash.Sum(b) != cid {
			return Result{FAIL, fmt.Sprintf("stream %q is not a deterministic round-trip", sid)}
		}
	}
	return Result{PASS, fmt.Sprintf("HEAD %s: %d stream(s) integrity + determinism OK", hash.Short(head, 12), len(snap.Streams))}
}

// SelfResult aggregates the three-fixture oracle.
type SelfResult struct {
	Good       Result // MUST be PASS
	Bad        Result // MUST be FAIL (tamper detected)
	NegControl Result // MUST be PASS (lagging-but-valid, not corrupt)
	Overall    Verdict
	Detail     string
}

// SelfCheck runs the golden-good / golden-bad / negative-control oracle in a
// hermetic subtree of root. It returns Overall==PASS only when good==PASS AND
// bad==FAIL AND negControl==PASS.
func SelfCheck(root string) (SelfResult, error) {
	var r SelfResult

	// ---- golden-good ------------------------------------------------------
	goodDir := filepath.Join(root, "selfcheck-good")
	gEng, err := freshEngine(goodDir)
	if err != nil {
		return r, err
	}
	if err := gEng.Set(sampleState("A", "alpha next", "owner-A")); err != nil {
		return r, err
	}
	if err := gEng.Set(sampleState("B", "beta next", "owner-B")); err != nil {
		return r, err
	}
	s1, err := gEng.Commit("golden-good s1")
	if err != nil {
		return r, err
	}
	r.Good = Verify(gEng)

	// negative-control: a second, newer snapshot, then point HEAD back at the
	// OLDER valid s1. A lagging-but-valid snapshot MUST still verify PASS.
	changed := sampleState("A", "alpha CHANGED", "owner-A")
	if err := gEng.Set(changed); err != nil {
		return r, err
	}
	if _, err := gEng.Commit("golden-good s2"); err != nil {
		return r, err
	}
	if err := gEng.Store.WriteRef(store.HeadRef, s1); err != nil {
		return r, err
	}
	r.NegControl = Verify(gEng)

	// ---- golden-bad -------------------------------------------------------
	// Fresh store; commit; then TAMPER one stream blob on disk (flip a byte but
	// keep the filename == its old hash). Verify MUST detect the mismatch.
	badDir := filepath.Join(root, "selfcheck-bad")
	bEng, err := freshEngine(badDir)
	if err != nil {
		return r, err
	}
	if err := bEng.Set(sampleState("A", "alpha next", "owner-A")); err != nil {
		return r, err
	}
	head, err := bEng.Commit("golden-bad")
	if err != nil {
		return r, err
	}
	snap, err := bEng.Store.GetSnapshot(head)
	if err != nil {
		return r, err
	}
	var victim string
	for _, cid := range snap.Streams {
		victim = cid
		break
	}
	if err := tamperBlob(badDir, victim); err != nil {
		return r, err
	}
	r.Bad = Verify(bEng)

	// ---- aggregate --------------------------------------------------------
	okGood := r.Good.Verdict == PASS
	okBad := r.Bad.Verdict == FAIL
	okNeg := r.NegControl.Verdict == PASS
	if okGood && okBad && okNeg {
		r.Overall = PASS
		r.Detail = "oracle intact: golden-good PASS, golden-bad detected (FAIL), negative-control PASS"
	} else {
		r.Overall = FAIL
		r.Detail = fmt.Sprintf("oracle BROKEN: good=%s(want PASS) bad=%s(want FAIL) negctrl=%s(want PASS)",
			r.Good.Verdict, r.Bad.Verdict, r.NegControl.Verdict)
	}
	return r, nil
}

func freshEngine(dir string) (*snapshot.Engine, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s, err := store.Open(dir)
	if err != nil {
		return nil, err
	}
	return snapshot.New(s, "selfcheck", 0), nil
}

func sampleState(id, next, owner string) model.StreamState {
	return model.StreamState{
		StreamID:   id,
		Kind:       "track",
		Phase:      "phase-1",
		NextAction: next,
		Goal:       "ship",
		Head:       "deadbeef",
		Owner:      owner,
		Evidence:   []string{"qa-results/" + id + ".log"},
	}
}

// tamperBlob flips the last byte of the blob file for id, keeping its filename.
// This simulates on-disk corruption / tampering that a hash check must catch.
func tamperBlob(root, id string) error {
	p := filepath.Join(root, "objects", id[:2], id)
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return fmt.Errorf("empty blob %s", id)
	}
	b[len(b)-1] ^= 0xFF
	return os.WriteFile(p, b, 0o644)
}

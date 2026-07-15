// Package e2e is continuum's end-to-end + stress + chaos suite (§11.4.85).
//
// It proves the load-bearing product claims with captured, measured evidence
// (§11.4.5 / §11.4.69 / §11.4.107):
//
//   - a real multi-stream round-trip: snapshot the whole fleet at once, open a
//     BRAND-NEW process-equivalent (fresh Store + Engine over the same root),
//     restore, and assert BYTE-IDENTICAL rehydration of every stream;
//   - a measured resume Metric proving resume reads ONLY the manifest + one blob
//     per stream (BlobsRead == 1+N), never the O(history) ledger — the token win;
//   - stress: >=150 sustained commits (p50/p95/p99 recorded) and >=12 concurrent
//     writers with zero lost updates, run under -race;
//   - chaos: on-disk blob corruption DETECTED (never silently restored) then
//     recovered to a consistent state, and a crashed-writer stale lock REAPED.
//
// Evidence artifacts (resume_metric.json, latency.json, selfcheck.json,
// roundtrip.json) are written into $CONTINUUM_EVIDENCE_DIR when that env is set,
// so a runner can capture them; otherwise the metrics are emitted via t.Logf and
// the go-test output itself is the captured evidence.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/vasic-digital/continuum/pkg/model"
	"github.com/vasic-digital/continuum/pkg/resume"
	"github.com/vasic-digital/continuum/pkg/snapshot"
	"github.com/vasic-digital/continuum/pkg/store"
	"github.com/vasic-digital/continuum/pkg/verify"
)

func openEngine(t *testing.T, root string) *snapshot.Engine {
	t.Helper()
	s, err := store.Open(root)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return snapshot.New(s, "e2e", 0)
}

func writeEvidence(t *testing.T, name string, v any) {
	t.Helper()
	dir := os.Getenv("CONTINUUM_EVIDENCE_DIR")
	b, _ := json.MarshalIndent(v, "", "  ")
	t.Logf("EVIDENCE %s = %s", name, b)
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir evidence: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
}

func fleet() []model.StreamState {
	return []model.StreamState{
		{StreamID: "T1/main", Kind: "main", Phase: "release", NextAction: "flash D4", Goal: "1.2.1 tag", Head: "8e2b49fd", Owner: "conductor",
			Evidence: []string{"qa-results/flash_20260715.log"}},
		{StreamID: "T2/feature/mistiq-vader", Kind: "track", Phase: "dev", NextAction: "SPK-512 HAL", Owner: "worker-2",
			InFlight: []model.Job{{Kind: "build", ID: "b-778", Log: "qa-results/aosp_b778.log"}}},
		{StreamID: "T3/feature/dolby-remap", Kind: "track", Phase: "dev", NextAction: "2.2.3 remap", Owner: "worker-3"},
		{StreamID: "T4/feature/board-cleanup", Kind: "track", Phase: "blocked", NextAction: "await operator", Owner: "worker-4",
			Blockers: []string{"operator STOP: 119 uncommitted files"}},
		{StreamID: "agent:review-ab5478", Kind: "agent", Phase: "reviewing", NextAction: "GO/NO-GO SPK-512", Owner: "reviewer"},
		{StreamID: "agent:alias-a17c31", Kind: "agent", Phase: "running", NextAction: "rebind on recovery", Owner: "ruler"},
	}
}

// TestE2E_MultiStreamRoundTripAndResumeMetric is the flagship proof.
func TestE2E_MultiStreamRoundTripAndResumeMetric(t *testing.T) {
	root := t.TempDir()
	orig := fleet()

	// --- write session -----------------------------------------------------
	e := openEngine(t, root)
	for _, st := range orig {
		if err := e.Set(st); err != nil {
			t.Fatalf("Set %s: %v", st.StreamID, err)
		}
	}
	head, err := e.Commit("fleet snapshot")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// --- FRESH SESSION: new Store + new Engine over the SAME root -----------
	fresh := openEngine(t, root)
	got, gotHead, err := fresh.RestoreAll("")
	if err != nil {
		t.Fatalf("RestoreAll (fresh session): %v", err)
	}
	if gotHead != head {
		t.Fatalf("fresh session HEAD %s != %s", gotHead, head)
	}
	if len(got) != len(orig) {
		t.Fatalf("restored %d streams, want %d", len(got), len(orig))
	}
	// BYTE-IDENTICAL rehydration: canonical(restored) == canonical(original).
	for _, st := range orig {
		want, _ := model.Canonical(st)
		have, _ := model.Canonical(got[st.StreamID])
		if !bytes.Equal(want, have) {
			t.Fatalf("stream %s not byte-identical after restore:\nwant %s\n got %s", st.StreamID, want, have)
		}
	}

	// --- measured resume Metric (the token-cost proof) ---------------------
	b, err := resume.Render(fresh, "", resume.Options{Title: "ATMOSphere fleet resume"})
	if err != nil {
		t.Fatalf("resume.Render: %v", err)
	}
	if b.Metric.Streams != len(orig) {
		t.Fatalf("metric streams=%d want %d", b.Metric.Streams, len(orig))
	}
	// The load-bearing claim: resume reads manifest(1) + one blob per stream.
	if b.Metric.BlobsRead != 1+len(orig) {
		t.Fatalf("resume read %d blobs, want %d (1 manifest + %d streams) — NOT the history",
			b.Metric.BlobsRead, 1+len(orig), len(orig))
	}
	if b.Metric.Bytes == 0 || b.Metric.EstTokens == 0 {
		t.Fatal("resume metric bytes/tokens must be > 0")
	}
	writeEvidence(t, "resume_metric.json", b.Metric)
	writeEvidence(t, "roundtrip.json", map[string]any{
		"head": head, "streams": len(orig), "byte_identical": true,
		"short": b.Short,
	})
}

// TestE2E_DedupAcrossSnapshots proves the O(changed) global-snapshot cost.
func TestE2E_DedupAcrossSnapshots(t *testing.T) {
	root := t.TempDir()
	e := openEngine(t, root)
	for _, st := range fleet() {
		if err := e.Set(st); err != nil {
			t.Fatal(err)
		}
	}
	s1, _ := e.Commit("s1")

	// Change exactly ONE stream and re-commit the whole fleet.
	if err := e.Set(model.StreamState{StreamID: "T3/feature/dolby-remap", Kind: "track", Phase: "dev", NextAction: "2.2.3 remap DONE", Owner: "worker-3"}); err != nil {
		t.Fatal(err)
	}
	s2, _ := e.Commit("s2")

	d, err := e.Diff(s1, s2)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Changed) != 1 || d.Changed[0] != "T3/feature/dolby-remap" || len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Fatalf("global snapshot diff not O(changed): %+v", d)
	}
	// Every unchanged stream shares its content hash across s1 and s2 (dedup).
	sn1, _ := e.Store.GetSnapshot(s1)
	sn2, _ := e.Store.GetSnapshot(s2)
	for sid := range sn1.Streams {
		if sid == "T3/feature/dolby-remap" {
			continue
		}
		if sn1.Streams[sid] != sn2.Streams[sid] {
			t.Fatalf("unchanged stream %s was not deduped across snapshots", sid)
		}
	}
}

// TestStress_SustainedCommits — §11.4.85 sustained load with recorded latency.
func TestStress_SustainedCommits(t *testing.T) {
	const iters = 150
	root := t.TempDir()
	e := openEngine(t, root)
	for _, st := range fleet() {
		if err := e.Set(st); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.Commit("seed"); err != nil {
		t.Fatal(err)
	}

	streams := fleet()
	lat := make([]time.Duration, 0, iters)
	for i := 0; i < iters; i++ {
		s := streams[i%len(streams)]
		s.NextAction = fmt.Sprintf("iter-%d", i)
		if err := e.Set(s); err != nil {
			t.Fatalf("iter %d set: %v", i, err)
		}
		if _, err := e.Commit(fmt.Sprintf("iter-%d", i)); err != nil {
			t.Fatalf("iter %d commit: %v", i, err)
		}
		// measure a full fresh-session resume each iteration
		start := time.Now()
		fresh := openEngine(t, root)
		if _, _, err := fresh.RestoreAll(""); err != nil {
			t.Fatalf("iter %d restore: %v", i, err)
		}
		lat = append(lat, time.Since(start))
	}

	// Determinism holds after all the churn: HEAD still verifies.
	if r := verify.Verify(e); r.Verdict != verify.PASS {
		t.Fatalf("post-stress verify: %s (%s)", r.Verdict, r.Detail)
	}

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) time.Duration {
		if len(lat) == 0 {
			return 0
		}
		idx := int(p * float64(len(lat)))
		if idx >= len(lat) {
			idx = len(lat) - 1
		}
		return lat[idx]
	}
	summary := map[string]any{
		"iterations": iters,
		"p50_micros": pct(0.50).Microseconds(),
		"p95_micros": pct(0.95).Microseconds(),
		"p99_micros": pct(0.99).Microseconds(),
		"max_micros": lat[len(lat)-1].Microseconds(),
	}
	writeEvidence(t, "latency.json", summary)
}

// TestStress_ConcurrentWriters — §11.4.85 >=10 parallel writers, zero lost
// updates, run under -race. Each goroutine owns a DISTINCT stream (single-writer
// per stream, §11.4.206) and the advisory lock serializes the manifest writes.
func TestStress_ConcurrentWriters(t *testing.T) {
	const G, N = 12, 25
	root := t.TempDir()
	e := openEngine(t, root)

	var wg sync.WaitGroup
	errCh := make(chan error, G)
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			sid := fmt.Sprintf("stream-%02d", g)
			owner := fmt.Sprintf("owner-%02d", g)
			for i := 0; i < N; i++ {
				st := model.StreamState{StreamID: sid, Kind: "track", NextAction: fmt.Sprintf("v%d", i), Owner: owner}
				if err := e.Set(st); err != nil {
					errCh <- fmt.Errorf("%s set v%d: %w", sid, i, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	head, err := e.Commit("concurrent")
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	fresh := openEngine(t, root)
	all, _, err := fresh.RestoreAll(head)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != G {
		t.Fatalf("lost updates: %d streams committed, want %d", len(all), G)
	}
	for g := 0; g < G; g++ {
		sid := fmt.Sprintf("stream-%02d", g)
		st, ok := all[sid]
		if !ok {
			t.Fatalf("stream %s missing after concurrent writes", sid)
		}
		if st.NextAction != fmt.Sprintf("v%d", N-1) {
			t.Fatalf("stream %s final value = %q, want v%d", sid, st.NextAction, N-1)
		}
	}
}

// TestChaos_CorruptBlobDetectedAndRecovered — §11.4.85 state-corruption
// injection. A tampered on-disk blob MUST be DETECTED (never silently restored),
// and re-establishing the good bytes MUST restore a consistent, verifying state.
func TestChaos_CorruptBlobDetectedAndRecovered(t *testing.T) {
	root := t.TempDir()
	e := openEngine(t, root)
	good := model.StreamState{StreamID: "A", Kind: "track", NextAction: "n", Owner: "o"}
	if err := e.Set(good); err != nil {
		t.Fatal(err)
	}
	head, err := e.Commit("c")
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := e.Store.GetSnapshot(head)
	cid := snap.Streams["A"]
	blobPath := filepath.Join(root, "objects", cid[:2], cid)

	// inject: flip a byte in the on-disk blob.
	orig, _ := os.ReadFile(blobPath)
	corrupt := append([]byte(nil), orig...)
	corrupt[len(corrupt)-1] ^= 0xFF
	if err := os.WriteFile(blobPath, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(blobPath, orig, 0o644) // trap-style cleanup (§11.4.14)

	// DETECTED: verify FAILs and restore errors — never a silent bad restore.
	if r := verify.Verify(e); r.Verdict != verify.FAIL {
		t.Fatalf("corruption not detected: verify=%s (%s)", r.Verdict, r.Detail)
	}
	if _, _, err := e.RestoreAll(head); err == nil {
		t.Fatal("RestoreAll silently returned a corrupt blob (integrity bypass)")
	}

	// RECOVER: restore the good bytes -> consistent, verifying state again.
	if err := os.WriteFile(blobPath, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	if r := verify.Verify(e); r.Verdict != verify.PASS {
		t.Fatalf("post-recovery verify: %s (%s)", r.Verdict, r.Detail)
	}
}

// TestChaos_StaleLockReapedMidWrite — §11.4.85 process-death injection. A writer
// that died holding the lock leaves a stale lockfile with a dead PID; the next
// Set MUST reap it (kill -0 fails -> provably dead, §11.4.180) and proceed,
// logging the REAPED decision as captured evidence — never block forever.
func TestChaos_StaleLockReapedMidWrite(t *testing.T) {
	root := t.TempDir()
	s, _ := store.Open(root)
	var ev bytes.Buffer
	e := snapshot.New(s, "e2e", 0)
	e.Evidence = &ev

	// simulate the crashed writer's leftover lock (dead PID, fresh stamp).
	lockPath := filepath.Join(root, ".continuum.lock")
	deadPID := 424242
	if err := os.WriteFile(lockPath, []byte(fmt.Sprintf("%d\n%d\n", deadPID, time.Now().UnixNano())), 0o644); err != nil {
		t.Fatal(err)
	}

	// the write must still succeed by reaping the dead holder.
	if err := e.Set(model.StreamState{StreamID: "A", Kind: "track", NextAction: "after-crash", Owner: "o"}); err != nil {
		t.Fatalf("Set did not recover from stale lock: %v", err)
	}
	if !bytes.Contains(ev.Bytes(), []byte("REAPED")) || !bytes.Contains(ev.Bytes(), []byte(fmt.Sprint(deadPID))) {
		t.Fatalf("stale-lock reap not captured as evidence: %s", ev.String())
	}
	if _, err := e.Commit("after-crash"); err != nil {
		t.Fatalf("commit after reap: %v", err)
	}
	writeEvidence(t, "chaos_reap.json", map[string]any{"reaped_pid": deadPID, "evidence": ev.String()})
}

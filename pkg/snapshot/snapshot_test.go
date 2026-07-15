package snapshot

import (
	"testing"

	"github.com/vasic-digital/continuum/pkg/model"
	"github.com/vasic-digital/continuum/pkg/store"
)

func newEngine(t *testing.T) *Engine {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return New(s, "test", 0)
}

func st(id, next, owner string) model.StreamState {
	return model.StreamState{StreamID: id, Kind: "track", NextAction: next, Owner: owner}
}

func TestSetCommitRestoreRoundTrip(t *testing.T) {
	e := newEngine(t)
	if err := e.Set(st("A", "a1", "oA")); err != nil {
		t.Fatal(err)
	}
	if err := e.Set(st("B", "b1", "oB")); err != nil {
		t.Fatal(err)
	}
	id, err := e.Commit("s1")
	if err != nil {
		t.Fatal(err)
	}
	all, gotID, err := e.RestoreAll("")
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id {
		t.Fatalf("HEAD mismatch")
	}
	if len(all) != 2 || all["A"].NextAction != "a1" || all["B"].NextAction != "b1" {
		t.Fatalf("round-trip mismatch: %+v", all)
	}
	// byte-identical: canonical of restored == canonical of original
	orig, _ := model.Canonical(st("A", "a1", "oA"))
	rt, _ := model.Canonical(all["A"])
	if string(orig) != string(rt) {
		t.Fatalf("not byte-identical:\n%s\n%s", orig, rt)
	}
}

func TestSingleWriterRefused(t *testing.T) {
	e := newEngine(t)
	if err := e.Set(st("A", "a1", "ownerX")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Commit("s1"); err != nil {
		t.Fatal(err)
	}
	// A different owner must NOT be able to write stream A (§11.4.206).
	if err := e.Set(st("A", "hijack", "ownerY")); err == nil {
		t.Fatal("non-owner write was allowed")
	}
	// The real owner still can.
	if err := e.Set(st("A", "a2", "ownerX")); err != nil {
		t.Fatalf("owner write refused: %v", err)
	}
}

func TestDiffAndDedup(t *testing.T) {
	e := newEngine(t)
	e.Set(st("A", "a1", "oA"))
	e.Set(st("B", "b1", "oB"))
	s1, _ := e.Commit("s1")
	e.Set(st("A", "a2", "oA")) // change A only
	s2, _ := e.Commit("s2")

	d, err := e.Diff(s1, s2)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Changed) != 1 || d.Changed[0] != "A" || len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Fatalf("diff wrong: %+v", d)
	}
	// dedup: unchanged B shares the same content hash across snapshots.
	sn1, _ := e.Store.GetSnapshot(s1)
	sn2, _ := e.Store.GetSnapshot(s2)
	if sn1.Streams["B"] != sn2.Streams["B"] {
		t.Fatal("unchanged stream B was not deduped")
	}
	if sn1.Streams["A"] == sn2.Streams["A"] {
		t.Fatal("changed stream A kept same hash (should differ)")
	}
	// parent chain
	if sn2.Parent != s1 {
		t.Fatalf("parent chain broken: %q != %q", sn2.Parent, s1)
	}
}

func TestCommitEmptyRefused(t *testing.T) {
	e := newEngine(t)
	if _, err := e.Commit("empty"); err == nil {
		t.Fatal("empty commit should be refused")
	}
}

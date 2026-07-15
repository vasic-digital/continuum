package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vasic-digital/continuum/pkg/model"
)

func TestBlobIdempotentAndIntegrity(t *testing.T) {
	s, _ := Open(t.TempDir())
	id1, err := s.PutBlob([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := s.PutBlob([]byte("payload"))
	if id1 != id2 {
		t.Fatal("content-addressed put not idempotent")
	}
	got, err := s.GetBlob(id1)
	if err != nil || string(got) != "payload" {
		t.Fatalf("get: %v %q", err, got)
	}
	// Tamper the on-disk blob: GetBlob MUST detect it (§11.4.201).
	p := filepath.Join(s.Root, objectsDir, id1[:2], id1)
	b, _ := os.ReadFile(p)
	b[0] ^= 0xFF
	os.WriteFile(p, b, 0o644)
	if _, err := s.GetBlob(id1); err == nil {
		t.Fatal("tampered blob not detected — integrity check failed")
	}
}

func TestRefAtomicRoundTrip(t *testing.T) {
	s, _ := Open(t.TempDir())
	if v, _ := s.ReadRef("HEAD"); v != "" {
		t.Fatal("missing ref must read empty")
	}
	if err := s.WriteRef("HEAD", "abc123"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.ReadRef("HEAD"); v != "abc123" {
		t.Fatalf("ref round-trip: %q", v)
	}
}

func TestWorkingSeedFromHead(t *testing.T) {
	s, _ := Open(t.TempDir())
	// commit a snapshot manually
	id, _ := s.PutState(model.StreamState{StreamID: "A"})
	snapID, _ := s.PutSnapshot(model.Snapshot{Streams: map[string]string{"A": id}})
	s.WriteRef(HeadRef, snapID)
	// ReadWorking with no working.json seeds from HEAD
	w, err := s.ReadWorking()
	if err != nil {
		t.Fatal(err)
	}
	if w["A"] != id {
		t.Fatalf("working not seeded from HEAD: %v", w)
	}
}

func TestEventLedgerMonotonicAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	for i := 0; i < 5; i++ {
		if _, err := s.AppendEvent(model.Event{Type: "set", Time: "t"}); err != nil {
			t.Fatal(err)
		}
	}
	// reopen: seq must continue from 5, not reset.
	s2, _ := Open(dir)
	ev, _ := s2.AppendEvent(model.Event{Type: "set", Time: "t"})
	if ev.Seq != 6 {
		t.Fatalf("seq did not persist across reopen: got %d want 6", ev.Seq)
	}
	all, _ := s2.Events()
	if len(all) != 6 {
		t.Fatalf("want 6 events, got %d", len(all))
	}
	for i, e := range all {
		if e.Seq != int64(i+1) {
			t.Fatalf("non-monotonic seq at %d: %d", i, e.Seq)
		}
	}
}

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

func TestHasBlob(t *testing.T) {
	s, _ := Open(t.TempDir())
	id, _ := s.PutBlob([]byte("present"))
	if !s.HasBlob(id) {
		t.Fatal("HasBlob should return true for existing blob")
	}
	if s.HasBlob("deadbeef" + "00000000000000000000000000000000000000000000000000000000") {
		t.Fatal("HasBlob should return false for missing blob")
	}
	if s.HasBlob("not-a-valid-hash") {
		t.Fatal("HasBlob should return false for malformed id")
	}
}

func TestWriteWorkingRoundTrip(t *testing.T) {
	s, _ := Open(t.TempDir())
	m := map[string]string{"stream-a": "hash1", "stream-b": "hash2"}
	if err := s.WriteWorking(m); err != nil {
		t.Fatalf("WriteWorking: %v", err)
	}
	got, err := s.ReadWorking()
	if err != nil {
		t.Fatalf("ReadWorking: %v", err)
	}
	if len(got) != 2 || got["stream-a"] != "hash1" || got["stream-b"] != "hash2" {
		t.Fatalf("round-trip mismatch: %v", got)
	}
}

func TestGetStateRoundTrip(t *testing.T) {
	s, _ := Open(t.TempDir())
	st := model.StreamState{StreamID: "test-stream", Head: "abc123"}
	id, err := s.PutState(st)
	if err != nil {
		t.Fatalf("PutState: %v", err)
	}
	got, err := s.GetState(id)
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if got.StreamID != "test-stream" || got.Head != "abc123" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestGetStateIntegrityFailure(t *testing.T) {
	s, _ := Open(t.TempDir())
	st := model.StreamState{StreamID: "x"}
	id, _ := s.PutState(st)
	// tamper
	p := filepath.Join(s.Root, objectsDir, id[:2], id)
	b, _ := os.ReadFile(p)
	b[0] ^= 0xFF
	os.WriteFile(p, b, 0o644)
	if _, err := s.GetState(id); err == nil {
		t.Fatal("tampered state blob not detected")
	}
}

func TestGetSnapshotRoundTrip(t *testing.T) {
	s, _ := Open(t.TempDir())
	snap := model.Snapshot{Streams: map[string]string{"A": "hashA", "B": "hashB"}}
	id, err := s.PutSnapshot(snap)
	if err != nil {
		t.Fatalf("PutSnapshot: %v", err)
	}
	got, err := s.GetSnapshot(id)
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if len(got.Streams) != 2 || got.Streams["A"] != "hashA" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestGetSnapshotMissingBlob(t *testing.T) {
	s, _ := Open(t.TempDir())
	if _, err := s.GetSnapshot("deadbeef00000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("GetSnapshot on missing blob should error")
	}
}

func TestParsePID(t *testing.T) {
	tests := []struct {
		input string
		want  int
		ok    bool
	}{
		{"12345", 12345, true},
		{"  42  ", 42, true},
		{"0", 0, true},
		{"abc", 0, false},
		{"", 0, false},
		{"12.34", 0, false},
	}
	for _, tc := range tests {
		got, ok := ParsePID(tc.input)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("ParsePID(%q) = %d, %v; want %d, %v", tc.input, got, ok, tc.want, tc.ok)
		}
	}
}

func TestOpenEmptyRoot(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("Open with empty root should return error")
	}
}

func TestGetBlobMalformedID(t *testing.T) {
	s, _ := Open(t.TempDir())
	if _, err := s.GetBlob("short"); err == nil {
		t.Fatal("GetBlob with malformed id should error")
	}
}

func TestEventsEmptyLedger(t *testing.T) {
	s, _ := Open(t.TempDir())
	evs, err := s.Events()
	if err != nil {
		t.Fatalf("Events on empty: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("want 0 events, got %d", len(evs))
	}
}

func TestReadWorkingSeedsFromHead(t *testing.T) {
	s, _ := Open(t.TempDir())
	// No working.json, no HEAD => empty
	w, err := s.ReadWorking()
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 0 {
		t.Fatalf("want empty, got %v", w)
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

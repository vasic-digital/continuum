package model

import (
	"strings"
	"testing"
)

func TestCanonicalDeterministic(t *testing.T) {
	st := StreamState{
		StreamID:   "T1/main",
		Kind:       "track",
		Phase:      "build",
		NextAction: "flash canary",
		Fields:     map[string]string{"z": "1", "a": "2", "m": "3"},
		Evidence:   []string{"qa/x.log"},
	}
	first, err := Canonical(st)
	if err != nil {
		t.Fatal(err)
	}
	// 1000 re-marshals must be byte-identical (map key order stable).
	for i := 0; i < 1000; i++ {
		b, err := Canonical(st)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != string(first) {
			t.Fatalf("non-deterministic canonical at iter %d:\n%s\nvs\n%s", i, first, b)
		}
	}
	// map key order in the SOURCE map must not change the output.
	st2 := st
	st2.Fields = map[string]string{"m": "3", "a": "2", "z": "1"}
	b2, _ := Canonical(st2)
	if string(b2) != string(first) {
		t.Fatalf("map insertion order leaked into canonical form")
	}
	// no trailing newline
	if strings.HasSuffix(string(first), "\n") {
		t.Fatalf("canonical form must not have a trailing newline")
	}
}

func TestValidate(t *testing.T) {
	if err := (&StreamState{}).Validate(); err == nil {
		t.Fatal("empty StreamID must be invalid")
	}
	if err := (&StreamState{StreamID: "x"}).Validate(); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}
}

func TestSortedStreamIDs(t *testing.T) {
	s := Snapshot{Streams: map[string]string{"c": "3", "a": "1", "b": "2"}}
	got := SortedStreamIDs(s)
	want := []string{"a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sort mismatch: %v", got)
		}
	}
}

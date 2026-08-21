package store

import (
	"sync"
	"testing"

	"github.com/vasic-digital/continuum/pkg/model"
)

// RED test for the confirmed sequence race (spec 002-anti-slop-enforcement T005).
//
// The defect: Store.seq is cached at Open time by loadSeq (store.go:236 / :259)
// and AppendEvent increments THAT cached value (store.go:267) with
// atomic.AddInt64. atomic makes the increment safe within one handle; it says
// nothing across handles. Two handles opened before either appends therefore
// both cache 0 and both hand out sequence 1 — two ledger records claiming the
// same position in a total order the chain depends on (§11.4.207).
//
// Observed FAIL before the fix, GREEN after (§11.4.115(F)); the paired mutation
// in store_race_mutation_test.sh is what proves this test can catch the defect.

// TestAppendEventDistinctSeqAcrossHandlesOpenedBeforeAppend is the deterministic
// core of the RED: no concurrency is needed to expose it, only two handles
// opened before either appends.
func TestAppendEventDistinctSeqAcrossHandlesOpenedBeforeAppend(t *testing.T) {
	root := t.TempDir()

	// BOTH handles are opened BEFORE either appends — this is the precondition
	// the defect needs, and it is the ordinary case for two processes attached
	// to one store.
	a, err := Open(root)
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	b, err := Open(root)
	if err != nil {
		t.Fatalf("open b: %v", err)
	}

	evA, err := a.AppendEvent(model.Event{Type: "set", Time: "t", Note: "handle-a"})
	if err != nil {
		t.Fatalf("append a: %v", err)
	}
	evB, err := b.AppendEvent(model.Event{Type: "set", Time: "t", Note: "handle-b"})
	if err != nil {
		t.Fatalf("append b: %v", err)
	}

	if evA.Seq == evB.Seq {
		t.Fatalf("duplicate sequence across handles: handle-a and handle-b both got Seq=%d; "+
			"the ledger has no total order", evA.Seq)
	}

	// The returned values are only half the claim: the ledger ON DISK must also
	// carry two distinct sequences, or the duplicate was merely hidden.
	all, err := a.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("want 2 ledger records, got %d", len(all))
	}
	if all[0].Seq == all[1].Seq {
		t.Fatalf("ledger holds duplicate Seq=%d on disk", all[0].Seq)
	}
}

// TestAppendEventConcurrentHandlesTotalOrder exercises the same property under
// the race detector: N handles appending concurrently must produce exactly
// N*perHandle records carrying every sequence 1..N*perHandle exactly once.
func TestAppendEventConcurrentHandlesTotalOrder(t *testing.T) {
	root := t.TempDir()

	const handles = 6
	const perHandle = 5
	const want = handles * perHandle

	// Every handle is opened BEFORE any append happens.
	stores := make([]*Store, handles)
	for i := range stores {
		s, err := Open(root)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		stores[i] = s
	}

	var wg sync.WaitGroup
	errs := make(chan error, want)
	start := make(chan struct{})
	for _, s := range stores {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			<-start // maximise overlap
			for j := 0; j < perHandle; j++ {
				if _, err := s.AppendEvent(model.Event{Type: "set", Time: "t"}); err != nil {
					errs <- err
					return
				}
			}
		}(s)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent append: %v", err)
	}

	all, err := stores[0].Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(all) != want {
		t.Fatalf("want %d ledger records, got %d", want, len(all))
	}
	seen := make(map[int64]int, want)
	for _, e := range all {
		seen[e.Seq]++
	}
	for seq := int64(1); seq <= want; seq++ {
		switch n := seen[seq]; {
		case n == 0:
			t.Fatalf("sequence %d missing from the ledger (holes break the total order)", seq)
		case n > 1:
			t.Fatalf("sequence %d assigned %d times (duplicates break the total order)", seq, n)
		}
	}
}

// TestAppendEventSingleHandleSequenceUnchanged is this file's NEGATIVE CONTROL.
// The two tests above refuse duplicate sequences; this one proves they do not
// over-reach onto the correct behaviour they might damage — a single handle
// must still hand out 1,2,3 in order. A fix that satisfied the tests above by
// breaking ordinary sequencing would fail here, so a false refusal is caught
// with the same weight as a false pass (§11.4.201(1)).
func TestAppendEventSingleHandleSequenceUnchanged(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := int64(1); i <= 3; i++ {
		ev, err := s.AppendEvent(model.Event{Type: "set", Time: "t"})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if ev.Seq != i {
			t.Fatalf("single-handle sequence broken: append %d returned Seq=%d", i, ev.Seq)
		}
	}
}

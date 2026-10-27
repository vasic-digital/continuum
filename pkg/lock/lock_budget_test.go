package lock

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// N3 killer: time queued at the in-process gate is charged against Wait, so
// total blocking stays about Wait, not gate-wait + Wait.
func TestAcquire_WaitBudgetChargedAtGate(t *testing.T) {
	const W = 600 * time.Millisecond
	p := filepath.Join(t.TempDir(), "b.lock")
	// A live foreign holder owns the file (alive injected; no real PID signalled).
	stamp := fmt.Sprintf("%d\n%d\n", 1, time.Now().UnixNano())
	if err := os.WriteFile(p, []byte(stamp), 0o644); err != nil {
		t.Fatal(err)
	}
	g := gateFor(p)
	g <- struct{}{} // occupy the gate
	go func() {
		time.Sleep(W / 2)
		<-g // free it at 0.5W
	}()
	start := time.Now()
	_, err := Acquire(p, Options{Wait: W, Poll: 5 * time.Millisecond, alive: func(int) bool { return true }})
	el := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout: file is held by a live holder")
	}
	if el > W*125/100 {
		t.Fatalf("blocked %s with Wait=%s: gate wait was not charged to the budget", el, W)
	}
	if el < W*8/10 {
		t.Fatalf("returned after %s, before the Wait budget %s", el, W)
	}
}

// R2 killer: the gate is NEVER freed (the in-process holder never releases).
// Acquire must give up at about Wait with the documented timeout error, not at
// 2*Wait and not before Wait.
func TestAcquire_NeverFreedGateTimesOutAtWait(t *testing.T) {
	const W = 600 * time.Millisecond
	p := filepath.Join(t.TempDir(), "never.lock")
	g := gateFor(p)
	g <- struct{}{} // occupied for the whole test
	defer func() { <-g }()
	start := time.Now()
	l, err := Acquire(p, Options{Wait: W, Poll: 5 * time.Millisecond})
	el := time.Since(start)
	if err == nil {
		_ = l.Release()
		t.Fatal("expected timeout: the gate is never freed")
	}
	if !strings.Contains(err.Error(), "timed out acquiring") {
		t.Fatalf("unexpected error: %v", err)
	}
	if el > W*125/100 {
		t.Fatalf("blocked %s with Wait=%s: gate wait exceeds the Wait budget", el, W)
	}
	if el < W*9/10 {
		t.Fatalf("returned after %s, before the Wait budget %s", el, W)
	}
}

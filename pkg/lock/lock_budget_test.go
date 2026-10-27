package lock

import (
	"fmt"
	"os"
	"path/filepath"
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

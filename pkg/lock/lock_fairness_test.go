package lock

import (
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAcquire_NoStarvationUnderTightLoopContention reproduces the
// TestStress_ConcurrentWriters failure class: several holders re-acquire the
// lock in a tight loop (Release immediately followed by Acquire) while one
// waiter polls. With an unfair O_EXCL poll the waiter only wins if its 25ms
// poll lands in the microsecond gap between Release and re-create, so it
// starves until its Wait budget expires although the lock is never held by a
// dead or stuck holder. A fair lock MUST grant the waiter within a bounded
// number of holder turns.
func TestAcquire_NoStarvationUnderTightLoopContention(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fair.lock")
	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				l, err := Acquire(p, Options{Wait: 30 * time.Second})
				if err != nil {
					t.Errorf("looper acquire: %v", err)
					return
				}
				time.Sleep(2 * time.Millisecond) // critical section
				_ = l.Release()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond) // let the loopers reach steady state

	// Repeat the waiter trial: a single trial on the unfair lock wins by luck
	// roughly one trial in five, K independent trials make a false GREEN rare.
	const trials = 15
	var starved error
	var worst time.Duration
	for i := 0; i < trials && starved == nil; i++ {
		start := time.Now()
		l, err := Acquire(p, Options{Wait: 200 * time.Millisecond})
		waited := time.Since(start)
		if waited > worst {
			worst = waited
		}
		if err != nil {
			starved = fmt.Errorf("trial %d: waiter starved: gave up after %s while holders cycled (no dead holder): %w", i, waited, err)
			break
		}
		_ = l.Release()
	}
	stop.Store(true)
	wg.Wait()
	if starved != nil {
		t.Fatal(starved)
	}
	t.Logf("%d waiter trials ok, worst wait %s", trials, worst)
}

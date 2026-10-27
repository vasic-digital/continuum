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
	var turns atomic.Int64 // total looper acquisitions, a scheduler-independent clock
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
				turns.Add(1)
				time.Sleep(2 * time.Millisecond) // critical section
				_ = l.Release()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond) // let the loopers reach steady state

	// Repeat the waiter trial: a single trial on the unfair lock wins by luck
	// roughly one trial in five. The trials are CORRELATED (they share the
	// loopers and the lock), so they are not independent draws; that is why a
	// contention precondition is enforced per trial below instead of relying on
	// the trial count alone.
	const trials = 15
	// Fairness is measured in HOLDER TURNS, not wall-clock: a FIFO gate admits
	// the waiter after at most the 8 loopers queued ahead of it, whereas the
	// unfair O_EXCL poll lets the loopers take dozens of turns first. A host
	// stall freezes the loopers too, so it cannot fake starvation (a wall-clock
	// budget flaked about 1 run in 35 on an overloaded host even at 1s).
	const maxTurns = 40
	var starved error
	var worst int64
	for i := 0; i < trials && starved == nil; i++ {
		// Gap between trials: wait until the loopers have taken a turn since the
		// previous trial. On the unfair lock a waiter that wins one trial and
		// re-acquires back-to-back starves the loopers (worst 0 holder turns, a
		// vacuous pass); the gap hands them the lock so every trial is contended.
		gapFrom := turns.Load()
		for gapDeadline := time.Now().Add(10 * time.Second); turns.Load() == gapFrom; {
			if time.Now().After(gapDeadline) {
				starved = fmt.Errorf("trial %d: no looper took a turn in the inter-trial gap; contention precondition not met", i)
				break
			}
			time.Sleep(time.Millisecond)
		}
		if starved != nil {
			break
		}
		before := turns.Load()
		l, err := Acquire(p, Options{Wait: 30 * time.Second})
		took := turns.Load() - before
		if took > worst {
			worst = took
		}
		if err != nil {
			starved = fmt.Errorf("trial %d: waiter gave up after %d holder turns: %w", i, took, err)
			break
		}
		if took < 1 {
			starved = fmt.Errorf("trial %d: vacuous: 0 holder turns passed while the waiter waited (no contention), the waiter did not queue behind a holder", i)
			_ = l.Release()
			break
		}
		if took > maxTurns {
			starved = fmt.Errorf("trial %d: waiter starved: %d holder turns passed before it was admitted (fair bound ~8, limit %d)", i, took, maxTurns)
			_ = l.Release()
			break
		}
		_ = l.Release()
	}
	stop.Store(true)
	wg.Wait()
	if starved != nil {
		t.Fatal(starved)
	}
	t.Logf("%d waiter trials ok, worst %d holder turns", trials, worst)
}

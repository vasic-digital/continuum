package lock

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// C9: Release after a chdir must remove the REAL lockfile. Lock.path used to keep
// the spelling given to Acquire, so a relative path was resolved against the new
// working directory: Release saw ErrNotExist, returned nil, freed the gate and
// orphaned the lockfile, held by our own live PID.
func TestRelease_AfterChdir_RemovesRealLockfile(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	old, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(old) })
	if err := os.Chdir(a); err != nil {
		t.Fatal(err)
	}
	l, err := Acquire("x.lock", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(b); err != nil {
		t.Fatal(err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := os.Stat(filepath.Join(a, "x.lock")); !os.IsNotExist(err) {
		t.Fatalf("lockfile in the original directory was orphaned by Release after chdir (stat err=%v)", err)
	}
}

// C10: two spellings of one file through a symlinked directory must share a gate
// (and therefore one FIFO queue); otherwise fairness is lost between them.
func TestGateFor_SymlinkedDirectoriesShareGate(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if gateFor(filepath.Join(real, "k.lock")) != gateFor(filepath.Join(link, "k.lock")) {
		t.Fatal("real and symlinked spellings of one lockfile got different gates")
	}
	// negative control: genuinely different files must NOT share a gate.
	if gateFor(filepath.Join(real, "k.lock")) == gateFor(filepath.Join(real, "other.lock")) {
		t.Fatal("distinct lockfiles share a gate")
	}
}

// C11: the timeout path must not leak the gate slot when the gate frees at the
// instant the timer fires. An injectable timer makes that instant reproducible:
// a ready timer and a free gate are both selectable, so select picks either at
// random; every outcome has to leave the gate usable.
func TestAcquire_TimerAndFreeGateRace_NoSlotLeak(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.lock")
	var won, lost int
	for i := 0; i < 400; i++ {
		fired := make(chan time.Time, 1)
		fired <- time.Now()
		l, err := Acquire(p, Options{Wait: time.Hour, timer: func(time.Duration) (<-chan time.Time, func() bool) { return fired, func() bool { return true } }})
		if err == nil {
			won++
			if rerr := l.Release(); rerr != nil {
				t.Fatal(rerr)
			}
		} else {
			lost++
		}
		if n := len(gateFor(p)); n != 0 {
			t.Fatalf("iteration %d (err=%v): gate slot leaked (len=%d)", i, err, n)
		}
	}
	if won == 0 || lost == 0 {
		t.Fatalf("race not exercised in both directions: won=%d lost=%d", won, lost)
	}
}

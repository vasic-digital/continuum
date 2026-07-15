package lock

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAcquireRelease(t *testing.T) {
	p := filepath.Join(t.TempDir(), "l.lock")
	l, err := Acquire(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("lockfile not created")
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("lockfile not removed on release")
	}
}

// A dead-holder lock is REAPED (kill -0 fails) — the exact 9-hour-freeze fix.
func TestReapDeadHolder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "l.lock")
	// Write a stale lock owned by PID 424242 with a fresh timestamp.
	os.WriteFile(p, []byte("424242\n"+fmt.Sprint(time.Now().UnixNano())+"\n"), 0o644)
	var ev bytes.Buffer
	l, err := Acquire(p, Options{
		Evidence: &ev,
		alive:    func(pid int) bool { return false }, // holder is dead
	})
	if err != nil {
		t.Fatalf("should have reaped dead holder: %v", err)
	}
	l.Release()
	if !bytes.Contains(ev.Bytes(), []byte("REAPED")) || !bytes.Contains(ev.Bytes(), []byte("424242")) {
		t.Fatalf("reap decision not logged as evidence: %s", ev.String())
	}
}

// A LIVE-holder lock is KEPT — we must NOT steal it (§9.2), so Acquire times out.
func TestKeepLiveHolder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "l.lock")
	os.WriteFile(p, []byte("777\n"+fmt.Sprint(time.Now().UnixNano())+"\n"), 0o644)
	var ev bytes.Buffer
	_, err := Acquire(p, Options{
		Wait:     80 * time.Millisecond,
		Poll:     10 * time.Millisecond,
		Evidence: &ev,
		alive:    func(pid int) bool { return true }, // holder is alive
	})
	if err == nil {
		t.Fatal("must NOT acquire a live-held lock")
	}
	if !bytes.Contains(ev.Bytes(), []byte("KEEP")) {
		t.Fatalf("KEEP decision not logged: %s", ev.String())
	}
	// The live holder's lockfile must still be intact.
	if b, _ := os.ReadFile(p); !bytes.Contains(b, []byte("777")) {
		t.Fatal("live-held lock was wrongly removed")
	}
}

// No-PID + aged-past-TTL is reaped; no-PID + within-TTL is kept.
func TestTTLReapNoPID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "l.lock")
	old := time.Now().Add(-time.Hour).UnixNano()
	os.WriteFile(p, []byte("0\n"+fmt.Sprint(old)+"\n"), 0o644)
	l, err := Acquire(p, Options{TTL: time.Minute, alive: func(int) bool { return false }})
	if err != nil {
		t.Fatalf("aged no-PID lock should be reaped: %v", err)
	}
	l.Release()
}

// Stress: 12 goroutines contend for the lock, each performing a read-modify-write
// of an EXTERNAL counter FILE — the kind of shared resource an inter-process
// advisory lock exists to protect (§11.4.180). If mutual exclusion is broken a
// lost update leaves the final file value < G*N. A counter file (not a shared Go
// variable) is the correct target: a file lock establishes no Go happens-before
// edge, so guarding an in-memory Go var with it would itself be a data race —
// the file is the honest, race-detector-clean shared resource.
func TestConcurrentMutualExclusion(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "l.lock")
	counterPath := filepath.Join(dir, "counter")
	if err := os.WriteFile(counterPath, []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	const G, N = 12, 40
	var wg sync.WaitGroup
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < N; i++ {
				l, err := Acquire(p, Options{Wait: 10 * time.Second, Poll: time.Millisecond})
				if err != nil {
					t.Errorf("acquire: %v", err)
					return
				}
				// read-modify-write the external counter under the lock.
				raw, err := os.ReadFile(counterPath)
				if err != nil {
					t.Errorf("read counter: %v", err)
					l.Release()
					return
				}
				v, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
				if err := os.WriteFile(counterPath, []byte(strconv.Itoa(v+1)), 0o644); err != nil {
					t.Errorf("write counter: %v", err)
					l.Release()
					return
				}
				l.Release()
			}
		}()
	}
	wg.Wait()
	raw, _ := os.ReadFile(counterPath)
	got, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if got != G*N {
		t.Fatalf("lost updates: counter=%d want %d", got, G*N)
	}
}

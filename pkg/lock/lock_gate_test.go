package lock

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// safeBuf is a goroutine-safe evidence sink.
type safeBuf struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *safeBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}
func (b *safeBuf) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Len()
}

// Gate-release probes (adopted from the independent review, §11.4.194(6)(d)).

func TestGate_FreedAfterAcquireError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	if err := os.WriteFile(p, []byte("1\n1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(p, Options{Wait: 50 * time.Millisecond}); err == nil {
		t.Fatal("expected timeout")
	}
	_ = os.Remove(p)
	l, err := Acquire(p, Options{Wait: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("gate leaked after Acquire error: %v", err)
	}
	_ = l.Release()
}

func TestGate_FreedAfterRefusedRelease(t *testing.T) {
	p := filepath.Join(t.TempDir(), "y.lock")
	l, err := Acquire(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("1\n2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if l.Release() == nil {
		t.Fatal("expected refusal")
	}
	_ = os.Remove(p)
	l2, err := Acquire(p, Options{Wait: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("gate leaked after refused Release: %v", err)
	}
	_ = l2.Release()
}

func TestGate_DoubleReleaseDoesNotBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "z.lock")
	l, err := Acquire(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Release()
	done := make(chan struct{})
	go func() { _ = l.Release(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("double Release blocked")
	}
}

// Deterministic M4 killer: with a live holder, exactly ONE of two in-process
// waiters may be admitted to the file protocol (it logs a KEEP decision per
// poll); the other must sit at the gate and log nothing.
func TestGate_AdmitsExactlyOneWaiter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "one.lock")
	// A foreign live holder (PID 1) so the in-process gate is NOT held by it.
	if err := os.WriteFile(p, []byte("1\n1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bufs := []*safeBuf{{}, {}}
	var wg sync.WaitGroup
	for _, b := range bufs {
		wg.Add(1)
		go func(b *safeBuf) {
			defer wg.Done()
			l, err := Acquire(p, Options{Wait: 600 * time.Millisecond, Poll: 5 * time.Millisecond, Evidence: b})
			if err == nil {
				_ = l.Release()
			}
		}(b)
	}
	time.Sleep(250 * time.Millisecond) // both waiters have long since polled if admitted
	admitted := 0
	for _, b := range bufs {
		if b.Len() > 0 {
			admitted++
		}
	}
	wg.Wait()
	if admitted != 1 {
		t.Fatalf("gate admitted %d concurrent waiters to the file protocol, want exactly 1", admitted)
	}
}

// C3: a panic inside the file-acquire step must not leak the gate slot.
func TestGate_FreedAfterAcquirePanic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "panic.lock")
	if err := os.WriteFile(p, []byte("12345\n1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() { _ = recover() }()
		_, _ = Acquire(p, Options{Wait: 100 * time.Millisecond, alive: func(int) bool { panic("boom") }})
		t.Fatal("expected panic")
	}()
	_ = os.Remove(p)
	l, err := Acquire(p, Options{Wait: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("gate leaked after panic: %v", err)
	}
	_ = l.Release()
}

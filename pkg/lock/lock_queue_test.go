package lock

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func qEntries(t *testing.T, p string) []string {
	t.Helper()
	ents, err := os.ReadDir(queueDir(p))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// A waiter that gives up must not leave its ticket behind: a stranded ticket at
// the head would block every later arrival until TTL.
func TestQueue_TimeoutLeavesNoTicket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "q.lock")
	// a live holder (this very process, so alive) that never releases
	if err := os.WriteFile(p, []byte(fmt.Sprintf("%d\n%d\n", os.Getpid(), time.Now().UnixNano())), 0o644); err != nil {
		t.Fatal(err)
	}
	// a second queued process makes our Acquire take a ticket
	other := filepath.Join(queueDir(p), fmt.Sprintf("%020d-%010d-%s", time.Now().UnixNano()-1, os.Getppid(), "aa"))
	_ = os.MkdirAll(queueDir(p), 0o755)
	_ = os.WriteFile(other, nil, 0o644)
	if _, err := Acquire(p, Options{Wait: 80 * time.Millisecond, Poll: 5 * time.Millisecond}); err == nil {
		t.Fatal("expected timeout")
	}
	if got := qEntries(t, p); len(got) != 1 || got[0] != filepath.Base(other) {
		t.Fatalf("queue after timeout = %v, want only the foreign ticket", got)
	}
}

// A ticket whose owner is dead is reaped (kill -0 proof) and the evidence says so.
func TestQueue_DeadOwnerTicketReaped(t *testing.T) {
	p := filepath.Join(t.TempDir(), "q.lock")
	_ = os.MkdirAll(queueDir(p), 0o755)
	dead := filepath.Join(queueDir(p), fmt.Sprintf("%020d-%010d-%s", time.Now().UnixNano()-1, 424242, "dead"))
	_ = os.WriteFile(dead, nil, 0o644)
	var ev safeBuf
	l, err := Acquire(p, Options{Evidence: &ev, Wait: time.Second, alive: func(pid int) bool { return pid == os.Getpid() }})
	if err != nil {
		t.Fatalf("a dead waiter's ticket must not block acquisition: %v", err)
	}
	_ = l.Release()
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Fatal("dead owner's ticket was not reaped")
	}
}

// A LIVE owner's fresh ticket is NOT reaped and is served before us (FIFO).
func TestQueue_LiveOwnerTicketKeptAndServedFirst(t *testing.T) {
	p := filepath.Join(t.TempDir(), "q.lock")
	_ = os.MkdirAll(queueDir(p), 0o755)
	ahead := filepath.Join(queueDir(p), fmt.Sprintf("%020d-%010d-%s", time.Now().UnixNano()-int64(time.Millisecond), 99999, "live"))
	_ = os.WriteFile(ahead, nil, 0o644)
	_, err := Acquire(p, Options{Wait: 100 * time.Millisecond, Poll: 5 * time.Millisecond, alive: func(int) bool { return true }})
	if err == nil {
		t.Fatal("acquired the lock ahead of a live earlier waiter: FIFO violated")
	}
	if _, serr := os.Stat(ahead); serr != nil {
		t.Fatal("a live waiter's ticket was reaped")
	}
}

// A ticket older than TTL is reaped even if its pid looks alive (pid reuse), so a
// crashed waiter whose pid was recycled cannot block the queue forever.
func TestQueue_StaleTicketReapedDespiteLivePid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "q.lock")
	_ = os.MkdirAll(queueDir(p), 0o755)
	old := filepath.Join(queueDir(p), fmt.Sprintf("%020d-%010d-%s", time.Now().Add(-time.Hour).UnixNano(), 99999, "old"))
	_ = os.WriteFile(old, nil, 0o644)
	l, err := Acquire(p, Options{Wait: time.Second, TTL: time.Minute, alive: func(int) bool { return true }})
	if err != nil {
		t.Fatalf("stale ticket blocked acquisition: %v", err)
	}
	_ = l.Release()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("stale ticket not reaped")
	}
}

// If the queue cannot be created the lock must still work (degrade to the
// unqueued protocol), never fail or deadlock.
func TestQueue_UnusableQueueDegradesToUnqueued(t *testing.T) {
	p := filepath.Join(t.TempDir(), "q.lock")
	if err := os.WriteFile(queueDir(p), []byte("a regular file where the queue directory should be"), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := Acquire(p, Options{Wait: time.Second})
	if err != nil {
		t.Fatalf("unusable queue must degrade, got: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
}

// Mutual exclusion is O_EXCL and must hold with the queue in play: many goroutines
// across two spellings of the path, a non-atomic counter guarded only by the lock.
func TestQueue_MutualExclusionHolds(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "m.lock")
	counter, inside := 0, 0
	done := make(chan struct{})
	const n, per = 8, 40
	for g := 0; g < n; g++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < per; i++ {
				l, err := Acquire(p, Options{Wait: 30 * time.Second, Poll: time.Millisecond})
				if err != nil {
					t.Error(err)
					return
				}
				inside++
				if inside != 1 {
					t.Errorf("two holders inside the critical section")
				}
				counter++
				inside--
				_ = l.Release()
			}
		}()
	}
	for g := 0; g < n; g++ {
		<-done
	}
	if counter != n*per {
		t.Fatalf("counter=%d want %d", counter, n*per)
	}
}

func heldBySelf(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(fmt.Sprintf("%d\n%d\n", os.Getpid(), time.Now().UnixNano())), 0o644); err != nil {
		t.Fatal(err)
	}
}

// F1: a queued waiter that is alive but frozen (SIGSTOP, Ctrl-Z) stops
// heartbeating; its ticket must be reaped so a FREE lock is not blocked for TTL.
func TestQueue_FrozenWaiterTicketReapedByMissingHeartbeat(t *testing.T) {
	p := filepath.Join(t.TempDir(), "q.lock")
	_ = os.MkdirAll(queueDir(p), 0o755)
	ahead := filepath.Join(queueDir(p), fmt.Sprintf("%020d-%010d-%s", time.Now().UnixNano()-int64(time.Millisecond), 99999, "frozen"))
	if err := os.WriteFile(ahead, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(ahead, old, old); err != nil {
		t.Fatal(err)
	}
	var ev safeBuf
	l, err := Acquire(p, Options{Wait: 2 * time.Second, Poll: 5 * time.Millisecond, hbStale: 100 * time.Millisecond, Evidence: &ev,
		alive: func(int) bool { return true }})
	if err != nil {
		t.Fatalf("a frozen waiter blocked a free lock: %v", err)
	}
	_ = l.Release()
	if _, serr := os.Stat(ahead); !os.IsNotExist(serr) {
		t.Fatal("frozen waiter's ticket not reaped")
	}
}

// A waiter that is merely waiting keeps its ticket fresh, so a healthy queue is
// never reaped by the heartbeat rule.
func TestQueue_WaiterHeartbeatsItsTicket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "q.lock")
	heldBySelf(t, p)
	done := make(chan error, 1)
	var hev safeBuf
	go func() {
		l, err := Acquire(p, Options{Wait: 5 * time.Second, Poll: 5 * time.Millisecond, hbStale: 200 * time.Millisecond, Evidence: &hev})
		if err == nil {
			_ = l.Release()
		}
		done <- err
	}()
	time.Sleep(700 * time.Millisecond) // > 3 hbStale
	ents := qEntries(t, p)
	if len(ents) != 1 {
		t.Fatalf("waiter ticket missing after 3 staleness windows: %v", ents)
	}
	st, err := os.Stat(filepath.Join(queueDir(p), ents[0]))
	if err != nil {
		t.Fatal(err)
	}
	if age := time.Since(st.ModTime()); age > 200*time.Millisecond {
		t.Fatalf("ticket mtime age %s: waiter is not heartbeating", age)
	}
	_ = os.Remove(p)
	if err := <-done; err != nil {
		t.Fatalf("waiter failed: %v", err)
	}
	if strings.Contains(hev.String(), "no heartbeat") {
		t.Fatalf("a healthy waiter's own ticket was reaped for missing heartbeat (it is not beating):\n%s", hev.String())
	}
}

// F4: a waiter whose ticket (or whole queue directory) disappears mid-wait must
// re-enqueue and still acquire a lock that becomes free.
func TestQueue_TicketLostMidWaitReenqueues(t *testing.T) {
	for _, name := range []string{"queue-dir-removed", "ticket-removed"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "q.lock")
			heldBySelf(t, p)
			done := make(chan error, 1)
			go func() {
				l, err := Acquire(p, Options{Wait: 5 * time.Second, Poll: 5 * time.Millisecond, hbStale: time.Second})
				if err == nil {
					_ = l.Release()
				}
				done <- err
			}()
			time.Sleep(150 * time.Millisecond)
			if name == "queue-dir-removed" {
				_ = os.RemoveAll(queueDir(p))
			} else {
				for _, e := range qEntries(t, p) {
					_ = os.Remove(filepath.Join(queueDir(p), e))
				}
			}
			time.Sleep(150 * time.Millisecond)
			_ = os.Remove(p)
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("waiter that lost its ticket failed: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("waiter that lost its ticket never acquired a free lock")
			}
		})
	}
}

// F5: after an OS crash the (not fsynced) lockfile can be empty/garbled with no
// live writer; once older than TTL it must be reaped, not kept forever. A fresh
// empty file (a live holder mid-stamp) must NOT be reaped.
func TestReap_EmptyLockfileOlderThanTTL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "e.lock")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(p, Options{Wait: 100 * time.Millisecond, Poll: 5 * time.Millisecond, TTL: time.Minute}); err == nil {
		t.Fatal("fresh empty lockfile was reaped: a live holder mid-stamp would be broken")
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	l, err := Acquire(p, Options{Wait: time.Second, TTL: time.Minute})
	if err != nil {
		t.Fatalf("crash-residue empty lockfile blocked acquisition: %v", err)
	}
	_ = l.Release()
}

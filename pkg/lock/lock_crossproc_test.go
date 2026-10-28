package lock

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Cross-process fairness (residual R1 of the lock-fairness work). The in-process
// FIFO gate cannot order contenders in DIFFERENT processes: a looper process
// that Releases and immediately re-Acquires recreates the lockfile within
// microseconds, while a waiter in another process only samples every Poll.

const (
	envRole  = "CONTINUUM_LOCK_TEST_ROLE"
	envLock  = "CONTINUUM_LOCK_TEST_PATH"
	envTurns = "CONTINUUM_LOCK_TEST_TURNS"
	envStop  = "CONTINUUM_LOCK_TEST_STOP"
)

// TestMain doubles as the looper child: when the role env is set the binary
// loops Acquire -> record a turn -> hold 2ms -> Release until the stop file
// appears, instead of running the tests.
func TestMain(m *testing.M) {
	switch os.Getenv(envRole) {
	case "looper":
		os.Exit(runLooper())
	case "victim":
		os.Exit(runVictim())
	}
	os.Exit(m.Run())
}

func runLooper() int {
	p, turns, stop := os.Getenv(envLock), os.Getenv(envTurns), os.Getenv(envStop)
	tf, err := os.OpenFile(turns, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer tf.Close()
	for {
		if _, err := os.Stat(stop); err == nil {
			return 0
		}
		l, err := Acquire(p, Options{Wait: 30 * time.Second, Poll: 2 * time.Millisecond})
		if err != nil {
			fmt.Fprintln(os.Stderr, "looper:", err)
			return 1
		}
		_, _ = tf.Write([]byte{'x'})
		// Cross-process mutual-exclusion probe: an O_EXCL marker that exists only
		// while this process is inside the critical section. Failing to create it
		// means another process is inside too.
		in, ierr := os.OpenFile(turns+".inside", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if ierr != nil {
			_ = os.WriteFile(turns+".viol", []byte("two processes inside the critical section"), 0o644)
		} else {
			in.Close()
		}
		time.Sleep(2 * time.Millisecond)
		if ierr == nil {
			_ = os.Remove(turns + ".inside")
		}
		_ = l.Release()
	}
}

func turnsSoFar(f string) int64 {
	st, err := os.Stat(f)
	if err != nil {
		return 0
	}
	return st.Size()
}

// startLoopers spawns n looper processes on lock path p and returns the turns
// file; they are stopped (stop file, then Wait) on cleanup.
func startLoopers(t *testing.T, dir, p string, n int) string {
	t.Helper()
	turns := filepath.Join(dir, "turns")
	stop := filepath.Join(dir, "stop")
	var cmds []*exec.Cmd
	for i := 0; i < n; i++ {
		c := exec.Command(os.Args[0])
		c.Env = append(os.Environ(), envRole+"=looper", envLock+"="+p, envTurns+"="+turns, envStop+"="+stop)
		c.Stderr = os.Stderr
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, c)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(stop, nil, 0o644)
		for _, c := range cmds {
			_ = c.Wait()
		}
	})
	for dl := time.Now().Add(10 * time.Second); turnsSoFar(turns) < 20; {
		if time.Now().After(dl) {
			t.Fatal("loopers never reached steady state")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return turns
}

// TestAcquire_NoStarvationAcrossProcesses: 4 looper PROCESSES hammer one lock; a
// waiter in this process must get it within a bounded number of holder turns.
// Measured in turns (a shared append-only counter file), not wall-clock, so host
// stalls cannot fake starvation. The fair bound is about the number of loopers
// (4); the unfair O_EXCL poll lets them take dozens to thousands of turns first.
func TestAcquire_NoStarvationAcrossProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "x.lock")
	turns := startLoopers(t, dir, p, 4)
	const maxTurns = 60
	var worst int64
	for i := 0; i < 10; i++ {
		before := turnsSoFar(turns)
		l, err := Acquire(p, Options{Wait: 20 * time.Second}) // default 25ms Poll: the realistic slow poller
		took := turnsSoFar(turns) - before
		if took > worst {
			worst = took
		}
		if err != nil {
			t.Fatalf("trial %d: waiter gave up after %d holder turns: %v", i, took, err)
		}
		_ = l.Release()
		if took > maxTurns {
			t.Fatalf("trial %d: waiter starved: %d holder turns by other processes before it was served (limit %d)", i, took, maxTurns)
		}
		// hand the loopers a turn so each trial is contended
		for gf := turnsSoFar(turns); turnsSoFar(turns) == gf; time.Sleep(time.Millisecond) {
		}
	}
	t.Logf("10 cross-process waiter trials ok, worst %d holder turns", worst)
}

// runVictim acquires the lock (queueing behind the loopers first) and, once it
// holds it, announces itself via a marker file and then sleeps forever so the
// parent can SIGKILL it while it holds the lock.
func runVictim() int {
	p, marker := os.Getenv(envLock), os.Getenv(envTurns)
	if _, err := Acquire(p, Options{Wait: 60 * time.Second, Poll: 2 * time.Millisecond}); err != nil {
		fmt.Fprintln(os.Stderr, "victim:", err)
		return 1
	}
	_ = os.WriteFile(marker, []byte("held"), 0o644)
	time.Sleep(10 * time.Minute)
	return 0
}

func liveQueue(p string) []string {
	ents, _ := os.ReadDir(queueDir(p))
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// Chaos (section 11.4.85): processes that are SIGKILLed while queued, and one
// that is SIGKILLed while HOLDING the lock, must not strand the system. Only
// children this test started are signalled.
func TestAcquire_ChaosKilledWaitersAndHolder_DoNotStrandQueue(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "x.lock")
	startLoopers(t, dir, p, 3)

	var victims []*exec.Cmd
	for i := 0; i < 4; i++ {
		c := exec.Command(os.Args[0])
		c.Env = append(os.Environ(), envRole+"=victim", envLock+"="+p, envTurns+"="+filepath.Join(dir, fmt.Sprintf("held%d", i)))
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		victims = append(victims, c)
	}
	// Wait until at least one victim holds the lock (the others queue behind it).
	var holder = -1
	for dl := time.Now().Add(20 * time.Second); holder < 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(dl) {
			t.Fatal("no victim ever acquired the lock")
		}
		for i := range victims {
			if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("held%d", i))); err == nil {
				holder = i
			}
		}
	}
	// Kill every victim: the holder (dead owner of the lockfile) and all queued waiters.
	for _, c := range victims {
		_ = c.Process.Kill()
		_ = c.Wait()
	}
	l, err := Acquire(p, Options{Wait: 20 * time.Second})
	if err != nil {
		t.Fatalf("after SIGKILL of holder %d and the queued victims, waiter could not acquire: %v (queue=%v)", holder, err, liveQueue(p))
	}
	_ = l.Release()
	// Dead tickets are reaped by whoever scans next; trigger one more cycle.
	l2, err := Acquire(p, Options{Wait: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Release()
	for dl := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		dead := 0
		for _, n := range liveQueue(p) {
			if _, pid, ok := parseTicket(n); ok {
				for _, c := range victims {
					if c.Process.Pid == pid {
						dead++
					}
				}
			}
		}
		if dead == 0 {
			return
		}
		if time.Now().After(dl) {
			t.Fatalf("tickets of SIGKILLed processes were never reaped: %v", liveQueue(p))
		}
	}
}

// F10: mutual exclusion across PROCESSES with the queue in play. Four loopers
// contend for a few seconds; none may ever be inside while another is.
func TestAcquire_MutualExclusionAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.lock")
	turns := startLoopers(t, dir, p, 4)
	base := turnsSoFar(turns)
	time.Sleep(2 * time.Second)
	if got := turnsSoFar(turns) - base; got < 20 {
		t.Fatalf("only %d turns in 2s: loopers made no progress", got)
	}
	if b, err := os.ReadFile(turns + ".viol"); err == nil {
		t.Fatalf("mutual exclusion violated across processes: %s", b)
	}
}

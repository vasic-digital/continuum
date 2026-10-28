// Package lock is continuum's advisory lock with provably-stale auto-reap.
//
// Discipline (§11.4.180 / §11.4.201):
//   - The lock is a DEDICATED lockfile, never one of the store's data files —
//     because a data write does rename(2) which swaps the inode, so a lock held
//     on a data file would be silently lost.
//   - Acquisition auto-reaps a PROVABLY-stale lock: the recorded holder PID is
//     DEAD (kill -0 fails), OR (age > TTL AND no live holder). It NEVER removes
//     a lock whose holder is alive — that would corrupt a concurrent writer
//     (§9.2). Liveness is PROVEN, never assumed (§11.4.6).
//   - Every REAPED / KEPT decision is logged as captured evidence with the real
//     holder PID + reason (§11.4.180). A false-positive reap is as forbidden as
//     a false-negative block (§11.4.201) — hence the strict liveness proof.
package lock

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Lock is a held advisory lock. Call Release when done.
type Lock struct {
	path  string
	pid   int
	stamp string // the exact content we wrote, to prove ownership on Release
	gate  chan struct{}
	freed atomic.Bool // gate released exactly once even if Release is called twice
}

// gates serialises in-process contenders per lock path in FIFO order. The
// O_EXCL create is an unfair try-lock: a holder that re-acquires in a loop
// recreates the file within microseconds of Release, while a waiter only
// samples it every Poll, so a waiter can starve until its Wait budget expires
// although no holder is dead or stuck (reproduced: TestStress_ConcurrentWriters,
// first Set timed out after 15s with 276 other Sets completing). A buffered
// channel hands its slot to blocked senders (waiters) in the order they began
// waiting, so admitting one in-process contender at a time to the file protocol
// removes the starvation.
// Cross-process fairness is provided by a ticket queue (see acquireFile).
//
// Known limitations (documented, deliberately not fixed here):
//   - The gate and the ticket queue order contenders, they do not provide
//     exclusion: mutual exclusion is always the O_EXCL create. If the ticket
//     queue cannot be used (read-only directory, queue entries unreadable) the
//     lock degrades to the previous unfair-but-safe behaviour, never to an
//     unsafe one.
//   - Ticket order is by the creator's wall-clock nanosecond stamp, so two
//     processes enqueueing within the same clock tick are ordered by pid; the
//     queue is FIFO up to clock resolution and not a strict total order across
//     hosts (a lock directory shared over a network filesystem has no such
//     guarantee either way, and pid liveness is host-local).
//   - A recycled pid can keep a crashed waiter's ticket "alive"; tickets older
//     than TTL are therefore reaped regardless of liveness and a live waiter
//     whose ticket was reaped simply re-enqueues.
var gates sync.Map // path -> chan struct{} (capacity 1)

// canonicalKey is the identity two spellings of one lockfile must share: the
// absolute path with the DIRECTORY's symlinks resolved. The directory is
// resolved rather than the file because the lockfile itself comes and goes.
func canonicalKey(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	if real, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		return filepath.Join(real, filepath.Base(abs))
	}
	return abs
}

func gateFor(path string) chan struct{} {
	g, _ := gates.LoadOrStore(canonicalKey(path), make(chan struct{}, 1))
	return g.(chan struct{})
}

// Options tune acquisition.
type Options struct {
	// TTL is the age past which a lock with no live holder is reapable. Only
	// consulted when the holder PID is alive-unknown (no PID) — a dead PID is
	// reaped immediately regardless of age.
	TTL time.Duration
	// Wait is the max time to block trying to acquire before giving up.
	Wait time.Duration
	// Poll is the retry interval while waiting.
	Poll time.Duration
	// Evidence, if non-nil, receives one line per REAPED/KEPT decision.
	Evidence io.Writer
	// now / alive are injectable for deterministic tests; nil -> real impls.
	now   func() time.Time
	alive func(pid int) bool
	// timer is the Wait-budget timer source for the in-process gate; nil -> a
	// real time.Timer. It returns the channel and a stop func so an unfired timer
	// is released on every exit. Injectable so the timer/gate race is reproducible.
	timer func(time.Duration) (<-chan time.Time, func() bool)
	// hbStale is how long a queued ticket may go without a heartbeat before it is
	// reaped even though its owner pid is alive (a stopped/frozen waiter must not
	// block a free lock). nil-zero -> max(2s, 20*Poll).
	hbStale time.Duration
}

func (o *Options) withDefaults() {
	if o.TTL == 0 {
		o.TTL = 2 * time.Minute
	}
	if o.Wait == 0 {
		o.Wait = 10 * time.Second
	}
	if o.Poll == 0 {
		o.Poll = 25 * time.Millisecond
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.alive == nil {
		o.alive = ProcessAlive
	}
	if o.timer == nil {
		o.timer = func(d time.Duration) (<-chan time.Time, func() bool) {
			t := time.NewTimer(d)
			return t.C, t.Stop
		}
	}
	if o.hbStale == 0 {
		o.hbStale = 2 * time.Second
		if 20*o.Poll > o.hbStale {
			o.hbStale = 20 * o.Poll
		}
	}
}

// ProcessAlive reports whether pid is a live process (kill -0 semantics).
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	// signal 0 performs error checking without sending a signal.
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	// EPERM means the process exists but we may not signal it -> alive.
	return errors.Is(err, syscall.EPERM)
}

// Acquire blocks (up to opts.Wait) until it holds the lock at path, reaping a
// provably-stale holder if present. Returns the held Lock.
func Acquire(path string, opts Options) (*Lock, error) {
	opts.withDefaults()
	// Pin the absolute spelling now: a relative path would otherwise be resolved
	// against whatever the working directory is when Release runs.
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	deadline := opts.now().Add(opts.Wait)

	// FIFO in-process admission, bounded by the same Wait budget.
	gate := gateFor(path)
	tc, stopTimer := opts.timer(opts.Wait)
	select {
	case gate <- struct{}{}:
		stopTimer()
	case <-tc:
		return nil, fmt.Errorf("continuum/lock: timed out acquiring %s (lock held, or earlier waiters did not release their turn)", path)
	}
	// Free the slot on every non-success exit, including a panic raised by
	// injected alive/Evidence code inside acquireFile.
	acquired := false
	defer func() {
		if !acquired {
			<-gate
		}
	}()
	l, err := acquireFile(path, opts, deadline)
	if err != nil {
		return nil, err
	}
	l.gate = gate
	acquired = true
	return l, nil
}

// queueDir holds one ticket per CROSS-PROCESS waiter. The gate already admits a
// single contender per process, so the queue is at most one entry per process.
func queueDir(path string) string { return path + ".q" }

// headPoll is how often the head-of-queue waiter retries the O_EXCL create. It
// is capped independently of opts.Poll because only ONE waiter per lock polls at
// this rate (the others wait for their turn at opts.Poll), so a short interval
// costs one stat-like syscall per head-poll while keeping the hand-off latency
// after a Release small.
const headPoll = 2 * time.Millisecond

// newTicket creates this waiter's queue entry. The name sorts by arrival stamp
// (zero-padded nanoseconds), then pid, then a random suffix, so lexical order is
// arrival order.
func newTicket(path string, opts Options) (string, error) {
	dir := queueDir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	var r [4]byte
	if _, err := rand.Read(r[:]); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%020d-%010d-%s", opts.now().UnixNano(), os.Getpid(), hex.EncodeToString(r[:]))
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	_ = f.Close()
	return name, nil
}

// liveTickets lists the queue in arrival order after reaping tickets that are
// provably dead (owner pid not alive) or older than TTL. A reaped ticket is
// logged like any other reap decision. An unreadable queue yields (nil, err) and
// the caller degrades to the unqueued protocol.
func liveTickets(path string, opts Options) ([]string, error) {
	ents, err := os.ReadDir(queueDir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	now := opts.now().UnixNano()
	for _, e := range ents {
		name := e.Name()
		stamp, pid, ok := parseTicket(name)
		if !ok {
			continue // foreign file: neither ours to order by nor to delete
		}
		switch {
		case pid != os.Getpid() && !opts.alive(pid):
			if os.Remove(filepath.Join(queueDir(path), name)) == nil {
				logDecision(opts.Evidence, "REAPED", path, pid, "queue ticket owner is DEAD (kill -0 failed)")
			}
		case heartbeatStale(filepath.Join(queueDir(path), name), opts):
			if os.Remove(filepath.Join(queueDir(path), name)) == nil {
				logDecision(opts.Evidence, "REAPED", path, pid, fmt.Sprintf("queue ticket has no heartbeat for over %s (owner stopped or wedged)", opts.hbStale))
			}
		case time.Duration(now-stamp) > opts.TTL:
			if os.Remove(filepath.Join(queueDir(path), name)) == nil {
				logDecision(opts.Evidence, "REAPED", path, pid, fmt.Sprintf("queue ticket older than TTL %s", opts.TTL))
			}
		default:
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// heartbeatStale reports whether the ticket file has not been touched within
// opts.hbStale. The mtime is wall-clock, so it is compared with time.Now (not the
// injectable opts.now, which tests may skew). A stat error is "not stale": the
// ticket vanished or is unreadable and other branches handle that.
func heartbeatStale(file string, opts Options) bool {
	st, err := os.Stat(file)
	if err != nil {
		return false
	}
	return time.Since(st.ModTime()) > opts.hbStale
}

// touchTicket refreshes the heartbeat of our ticket.
func touchTicket(path, ticket string) {
	now := time.Now()
	_ = os.Chtimes(filepath.Join(queueDir(path), ticket), now, now)
}

func parseTicket(name string) (stamp int64, pid int, ok bool) {
	parts := strings.Split(name, "-")
	if len(parts) != 3 {
		return 0, 0, false
	}
	st, err1 := strconv.ParseInt(parts[0], 10, 64)
	p, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || p <= 0 {
		return 0, 0, false
	}
	return st, p, true
}

func acquireFile(path string, opts Options, deadline time.Time) (*Lock, error) {
	pid := os.Getpid()
	stamp := fmt.Sprintf("%d\n%d\n", pid, opts.now().UnixNano())

	// ticket is this waiter's queue entry; "" while no other process is queued
	// (the uncontended fast path takes no ticket and costs one directory read).
	ticket := ""
	defer func() {
		if ticket != "" {
			_ = os.Remove(filepath.Join(queueDir(path), ticket))
		}
	}()
	queueOK := true // false once the queue proved unusable: degrade, never block
	lastBeat := time.Now()

	for {
		myTurn, poll := true, opts.Poll
		if queueOK {
			tickets, qerr := liveTickets(path, opts)
			if qerr != nil {
				queueOK = false
			} else {
				if ticket != "" && !contains(tickets, ticket) {
					ticket = "" // reaped (TTL) or removed: take a fresh place
				}
				if ticket == "" && len(tickets) > 0 {
					// Someone is already waiting: queue behind them rather than
					// barging past with a back-to-back create.
					if t, terr := newTicket(path, opts); terr != nil {
						queueOK = false
					} else {
						ticket = t
						tickets, _ = liveTickets(path, opts)
					}
				}
				if ticket != "" {
					myTurn = len(tickets) > 0 && tickets[0] == ticket
					if myTurn && headPoll < poll {
						poll = headPoll
					}
				}
			}
		}

		if ticket != "" && time.Since(lastBeat) > opts.hbStale/4 {
			touchTicket(path, ticket)
			lastBeat = time.Now()
		}

		if myTurn {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
			if err == nil {
				// The lockfile is deliberately NOT fsynced: it carries no data
				// that must survive a crash. After a crash the stamp names a dead
				// pid (reaped) or never reached disk (empty file, reaped once
				// older than TTL); fsyncing it only added a disk flush to every
				// acquisition (benchmark, same ext4 disk: ~7-9 ms per cycle with
				// the fsync, ~0.1-0.6 ms without).
				if _, werr := f.WriteString(stamp); werr != nil {
					f.Close()
					_ = os.Remove(path)
					return nil, werr
				}
				f.Close()
				return &Lock{path: path, pid: pid, stamp: stamp}, nil
			}
			if !errors.Is(err, os.ErrExist) {
				return nil, err
			}
			// Lock exists — decide reap vs keep.
			if tryReap(path, opts) {
				continue // race to re-create
			}
			if ticket == "" && queueOK {
				// We lost the race while nobody was queued: become a visible
				// waiter so later arrivals (including the holder re-acquiring)
				// queue behind us instead of barging past.
				if t, terr := newTicket(path, opts); terr == nil {
					ticket = t
				} else {
					queueOK = false
				}
			}
		}
		if !opts.now().Before(deadline) {
			return nil, fmt.Errorf("continuum/lock: timed out acquiring %s (lock held, or earlier waiters did not release their turn)", path)
		}
		time.Sleep(poll)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// tryReap removes path IFF the holder is provably stale, logging the decision.
// Returns true if it removed a stale lock.
func tryReap(path string, opts Options) bool {
	holderPID, stampNano, ok := readHolder(path)
	if !ok {
		// Unreadable/malformed lock: conservative-safe default is KEEP with an
		// honest log (§11.4.201) — do not delete what we cannot prove stale.
		// An empty/garbled lockfile older than TTL is what an OS crash leaves
		// when the lockfile (deliberately not fsynced) was created but its stamp
		// never reached disk. A live holder writes its stamp within microseconds
		// of the create, so an unparseable file past TTL has no live writer.
		if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) > opts.TTL {
			if _, _, ok2 := readHolder(path); !ok2 {
				if st2, err2 := os.Stat(path); err2 == nil && os.SameFile(st, st2) && st2.ModTime().Equal(st.ModTime()) && os.Remove(path) == nil {
					logDecision(opts.Evidence, "REAPED", path, 0, fmt.Sprintf("lock content unreadable and older than TTL %s (crash residue)", opts.TTL))
					return true
				}
			}
		}
		logDecision(opts.Evidence, "KEEP", path, 0, "lock content unreadable/malformed; cannot prove stale")
		return false
	}
	if holderPID > 0 && opts.alive(holderPID) {
		logDecision(opts.Evidence, "KEEP", path, holderPID, "holder PID is ALIVE (kill -0 ok)")
		return false
	}
	// Holder not alive (or no PID). Two proof paths:
	if holderPID > 0 && !opts.alive(holderPID) {
		if removeIf(path, holderPID, stampNano) {
			logDecision(opts.Evidence, "REAPED", path, holderPID, "holder PID is DEAD (kill -0 failed)")
			return true
		}
		return false
	}
	// No usable PID: reap only when aged past TTL AND still no live holder.
	age := time.Duration(opts.now().UnixNano() - stampNano)
	if stampNano > 0 && age > opts.TTL {
		if removeIf(path, holderPID, stampNano) {
			logDecision(opts.Evidence, "REAPED", path, holderPID, fmt.Sprintf("no PID and age %s > TTL %s", age.Round(time.Second), opts.TTL))
			return true
		}
	}
	logDecision(opts.Evidence, "KEEP", path, holderPID, "no dead-PID proof and within TTL")
	return false
}

// removeIf removes path only if it still contains the same holder stamp we read
// (guards against reaping a lock that a new holder just recreated).
func removeIf(path string, pid int, stampNano int64) bool {
	cur, curNano, ok := readHolder(path)
	if !ok || cur != pid || curNano != stampNano {
		return false // changed under us — someone else owns it now
	}
	return os.Remove(path) == nil
}

func readHolder(path string) (pid int, stampNano int64, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 {
		return 0, 0, false
	}
	p, err1 := strconv.Atoi(strings.TrimSpace(lines[0]))
	n, err2 := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return p, n, true
}

func logDecision(w io.Writer, decision, path string, pid int, reason string) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, "%s lock=%s holder_pid=%d reason=%q\n",
		decision, path, pid, reason)
}

// Release removes the lock, but only if we still own it (content unchanged).
func (l *Lock) Release() error {
	if l == nil {
		return nil
	}
	if l.gate != nil && l.freed.CompareAndSwap(false, true) {
		// Admit the next in-process waiter only after the lockfile is gone.
		defer func() { <-l.gate }()
	}
	cur, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // already gone
	}
	if err != nil {
		return err
	}
	if string(cur) != l.stamp {
		// We no longer own it (was reaped + retaken). Do NOT remove another
		// holder's lock (§9.2).
		return fmt.Errorf("continuum/lock: refusing to release %s — no longer owned by this process", l.path)
	}
	return os.Remove(l.path)
}

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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Lock is a held advisory lock. Call Release when done.
type Lock struct {
	path  string
	pid   int
	stamp string // the exact content we wrote, to prove ownership on Release
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	deadline := opts.now().Add(opts.Wait)
	pid := os.Getpid()
	stamp := fmt.Sprintf("%d\n%d\n", pid, opts.now().UnixNano())

	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			if _, werr := f.WriteString(stamp); werr != nil {
				f.Close()
				_ = os.Remove(path)
				return nil, werr
			}
			if serr := f.Sync(); serr != nil {
				f.Close()
				_ = os.Remove(path)
				return nil, serr
			}
			f.Close()
			return &Lock{path: path, pid: pid, stamp: stamp}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		// Lock exists — decide reap vs keep.
		reaped := tryReap(path, opts)
		if reaped {
			continue // race to re-create
		}
		if !opts.now().Before(deadline) {
			return nil, fmt.Errorf("continuum/lock: timed out acquiring %s (held by a live holder)", path)
		}
		time.Sleep(opts.Poll)
	}
}

// tryReap removes path IFF the holder is provably stale, logging the decision.
// Returns true if it removed a stale lock.
func tryReap(path string, opts Options) bool {
	holderPID, stampNano, ok := readHolder(path)
	if !ok {
		// Unreadable/malformed lock: conservative-safe default is KEEP with an
		// honest log (§11.4.201) — do not delete what we cannot prove stale.
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

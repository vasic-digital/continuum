// Package store is the durable substrate of continuum: a content-addressed
// blob store + atomic refs + an append-only event ledger.
//
// Durability + atomicity (§11.4.205(6)): every ref write is temp-in-same-dir
// -> fsync file -> rename(2) -> fsync directory. rename(2) is atomic for
// readers; the directory fsync makes the rename itself durable. A temp in a
// DIFFERENT directory would be a copy (can tear) — so temps are always in the
// target's own directory.
//
// The event ledger is append-only (§11.4.205(6)) so a lost update is
// recoverable and detectable, never silent.
//
// Blob writes are content-addressed and write-once: the name IS the hash, so a
// second write of identical content is a no-op and concurrent writers cannot
// corrupt each other (idempotent). Only refs (single mutable pointers) need the
// advisory lock (see package lock).
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vasic-digital/continuum/pkg/hash"
	"github.com/vasic-digital/continuum/pkg/lock"
	"github.com/vasic-digital/continuum/pkg/model"
)

const (
	objectsDir = "objects"
	refsDir    = "refs"
	logDir     = "log"
	logFile    = "events.jsonl"
	// HeadRef names the latest committed Snapshot's content id.
	HeadRef = "HEAD"
	// workingFile holds the mutable, staged streamID->contentHash manifest.
	workingFile = "working.json"
	// eventsLockFile is the DEDICATED advisory lockfile guarding sequence
	// assignment. It is deliberately NOT the ledger itself: a lock held on a
	// data file is lost the moment that file is replaced (pkg/lock).
	eventsLockFile = "events.lock"
)

const (
	// appendLockWait bounds how long an append blocks on a live holder before
	// refusing. It refuses loudly rather than assigning a sequence it could not
	// order.
	appendLockWait = 30 * time.Second
	// appendLockPoll is the retry interval while waiting; small enough that a
	// contended append is not dominated by sleep.
	appendLockPoll = 2 * time.Millisecond
)

// ErrUnverifiableTail reports that the event ledger contains a record whose
// position in the total order cannot be established — an unparseable line, or a
// line carrying no sequence. AppendEvent REFUSES rather than deriving a
// sequence from a tail it never verified.
//
// It is exported so a caller can tell "this ledger is not safe to append to"
// from an I/O failure with errors.Is, rather than by matching message text: an
// error string is not an interface, and a gate that greps one is an instrument
// that breaks silently when the wording changes (§11.4.201).
var ErrUnverifiableTail = errors.New("continuum/store: unverifiable ledger tail")

// Store is a handle to a continuum store rooted at Root.
type Store struct {
	Root string
	seq  int64 // last assigned event seq (loaded lazily)
}

// Open returns a Store handle for root, creating the directory skeleton if
// absent. It is safe to Open the same root from many processes.
func Open(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("continuum/store: empty root")
	}
	s := &Store{Root: root}
	for _, d := range []string{objectsDir, refsDir, logDir} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return nil, err
		}
	}
	if err := s.loadSeq(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) objectPath(id string) string {
	return filepath.Join(s.Root, objectsDir, id[:2], id)
}

// PutBlob writes b under its content id (write-once) and returns the id.
func (s *Store) PutBlob(b []byte) (string, error) {
	id := hash.Sum(b)
	p := s.objectPath(id)
	if _, err := os.Stat(p); err == nil {
		return id, nil // already present — idempotent
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if err := atomicWrite(p, b); err != nil {
		return "", err
	}
	return id, nil
}

// GetBlob returns the bytes stored under id, verifying integrity: the bytes
// MUST hash back to id (§11.4.201 — assert the real condition; a tampered blob
// is DETECTED here, never silently returned).
func (s *Store) GetBlob(id string) ([]byte, error) {
	if !hash.Valid(id) {
		return nil, fmt.Errorf("continuum/store: malformed id %q", id)
	}
	b, err := os.ReadFile(s.objectPath(id))
	if err != nil {
		return nil, err
	}
	if got := hash.Sum(b); got != id {
		return nil, fmt.Errorf("continuum/store: integrity failure for %s (bytes hash to %s)", hash.Short(id, 12), hash.Short(got, 12))
	}
	return b, nil
}

// HasBlob reports whether id is present (no integrity read).
func (s *Store) HasBlob(id string) bool {
	if !hash.Valid(id) {
		return false
	}
	_, err := os.Stat(s.objectPath(id))
	return err == nil
}

// WriteRef atomically sets ref name to value.
func (s *Store) WriteRef(name, value string) error {
	return atomicWrite(filepath.Join(s.Root, refsDir, name), []byte(value+"\n"))
}

// ReadRef returns the value of ref name, or "" (no error) if it does not exist.
func (s *Store) ReadRef(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(s.Root, refsDir, name))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ---- working manifest (mutable staged streamID->contentHash) --------------

// ReadWorking returns the current working manifest. If none exists it is seeded
// from the committed HEAD snapshot (so a fresh process's edits layer on top of
// the last committed state), or empty if there is no HEAD.
func (s *Store) ReadWorking() (map[string]string, error) {
	p := filepath.Join(s.Root, refsDir, workingFile)
	b, err := os.ReadFile(p)
	if err == nil {
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		if m == nil {
			m = map[string]string{}
		}
		return m, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// seed from HEAD
	head, err := s.ReadRef(HeadRef)
	if err != nil {
		return nil, err
	}
	if head == "" {
		return map[string]string{}, nil
	}
	snap, err := s.GetSnapshot(head)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for k, v := range snap.Streams {
		m[k] = v
	}
	return m, nil
}

// WriteWorking atomically persists the working manifest.
func (s *Store) WriteWorking(m map[string]string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.Root, refsDir, workingFile), b)
}

// ---- typed snapshot helpers ------------------------------------------------

// PutSnapshot serializes snap canonically, stores it and returns its id.
func (s *Store) PutSnapshot(snap model.Snapshot) (string, error) {
	b, err := model.Canonical(snap)
	if err != nil {
		return "", err
	}
	return s.PutBlob(b)
}

// GetSnapshot loads and decodes the snapshot blob at id (integrity-checked).
func (s *Store) GetSnapshot(id string) (model.Snapshot, error) {
	var snap model.Snapshot
	b, err := s.GetBlob(id)
	if err != nil {
		return snap, err
	}
	if err := json.Unmarshal(b, &snap); err != nil {
		return snap, err
	}
	if snap.Streams == nil {
		snap.Streams = map[string]string{}
	}
	return snap, nil
}

// PutState serializes a StreamState canonically, stores it and returns its id.
func (s *Store) PutState(st model.StreamState) (string, error) {
	if err := st.Validate(); err != nil {
		return "", err
	}
	b, err := model.Canonical(st)
	if err != nil {
		return "", err
	}
	return s.PutBlob(b)
}

// GetState loads and decodes the StreamState blob at id (integrity-checked).
func (s *Store) GetState(id string) (model.StreamState, error) {
	var st model.StreamState
	b, err := s.GetBlob(id)
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(b, &st)
	return st, err
}

// ---- append-only event ledger ---------------------------------------------

// scanLastSeq reads the ledger from disk and returns the highest sequence it
// records (0 when the ledger does not exist yet).
//
// This is the ONLY authority on the next sequence number. The in-memory
// Store.seq is a cache, and a per-handle cache cannot order two handles: two
// handles opened before either appends both cache the same value and both hand
// out the same next sequence. Callers assigning a sequence MUST call this
// while holding the append lock (see AppendEvent).
//
// It VERIFIES the tail rather than merely skimming it: every non-blank line
// must parse as an Event and must carry a sequence, and the first line that
// does not is reported as ErrUnverifiableTail instead of being skipped.
// Skipping WAS the defect. An unparseable record read as ABSENT lowers the
// derived maximum, so the next append re-issues a sequence the ledger already
// contains, and the total order the snapshot chain depends on (§11.4.207)
// silently acquires two records claiming one position — a corruption the
// ledger itself would then say nothing about.
//
// On a fault it still returns the highest sequence VERIFIED before that line,
// so a caller that deliberately tolerates the fault (loadSeq) gets a truthful,
// never inflated, value.
func (s *Store) scanLastSeq() (int64, error) {
	f, err := os.Open(filepath.Join(s.Root, logDir, logFile))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var last int64
	lineNo := 0
	ledger := filepath.Join(logDir, logFile)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev model.Event
		if perr := json.Unmarshal([]byte(line), &ev); perr != nil {
			return last, fmt.Errorf("%w: %s line %d is malformed and could not be parsed (%v)",
				ErrUnverifiableTail, ledger, lineNo, perr)
		}
		// A line that parses but carries no sequence is equally unverifiable: it
		// occupies no position in the total order, so a maximum derived past it
		// is derived past an unknown. This cannot fire on a record this package
		// wrote — AppendEvent assigns last+1 from a last that starts at 0 and
		// only rises, so every written record carries seq >= 1. That is why the
		// check cannot refuse a healthy ledger (§11.4.201(1): a false refusal is
		// as serious as a false pass).
		if ev.Seq < 1 {
			return last, fmt.Errorf("%w: %s line %d parses but carries no sequence (seq=%d)",
				ErrUnverifiableTail, ledger, lineNo, ev.Seq)
		}
		if ev.Seq > last {
			last = ev.Seq
		}
	}
	if err := sc.Err(); err != nil {
		return last, err
	}
	return last, nil
}

// loadSeq refreshes the in-memory cache from disk. The cache is observational
// only — it is NEVER the source of an assigned sequence.
//
// An unverifiable tail is deliberately NOT fatal HERE, and the asymmetry with
// AppendEvent is the point: the refusal belongs at the seam that would ACT on
// the unverified tail, not at the seam that merely reads it (§11.4.120). Open
// certifies nothing, and refusing here would make a damaged ledger impossible
// to open and therefore impossible to inspect or repair — an outage, not a fix.
// The cache is then set to the highest sequence verified BEFORE the fault, so
// it under-reports rather than over-reports, and nothing derives a sequence
// from it in any case.
//
// The tolerance is narrow and named: ONLY ErrUnverifiableTail is absorbed.
// Every other error — a read failure, an over-long line — still propagates, so
// this is the opposite of the blanket err-swallow the tail verification exists
// to remove.
func (s *Store) loadSeq() error {
	last, err := s.scanLastSeq()
	if err != nil && !errors.Is(err, ErrUnverifiableTail) {
		return err
	}
	atomic.StoreInt64(&s.seq, last)
	return nil
}

// AppendEvent assigns the next sequence number and appends ev to the ledger,
// fsyncing so the record is durable. The caller supplies ev.Time (the audit
// clock) and the semantic fields.
//
// Sequence assignment is derived from the ledger tail ON DISK while holding an
// exclusive advisory lock across read-tail-then-append, never from the
// open-time cached counter. The cache is per-handle, so two handles opened
// before either appends would both hand out the same sequence and the ledger
// would carry two records claiming one position in a total order the snapshot
// chain depends on (§11.4.207). Holding the lock across BOTH the read and the
// write is what makes the derivation atomic: releasing between them would
// reintroduce the same duplicate under a different name.
//
// The same lock-held read is also the tail VERIFICATION: scanLastSeq refuses an
// unparseable or sequence-less record instead of skipping it, so AppendEvent
// returns ErrUnverifiableTail rather than assigning a position on a tail it
// could not verify. The refusal path runs after the lock's release is deferred,
// so a refused append frees the lock exactly as a successful one does — a
// refusal that stranded the lock would convert one damaged ledger into a
// permanently blocked store.
func (s *Store) AppendEvent(ev model.Event) (_ model.Event, err error) {
	lk, lerr := lock.Acquire(filepath.Join(s.Root, logDir, eventsLockFile), lock.Options{
		Wait: appendLockWait,
		Poll: appendLockPoll,
	})
	if lerr != nil {
		return ev, fmt.Errorf("continuum/store: acquiring append lock: %w", lerr)
	}
	// Released only after the record is durable. A release failure is reported
	// rather than swallowed (§11.4.252) — it leaves a lockfile behind, and a
	// silent one would strand every later append.
	defer func() {
		if rerr := lk.Release(); rerr != nil && err == nil {
			err = fmt.Errorf("continuum/store: releasing append lock: %w", rerr)
		}
	}()

	// ---- under the exclusive lock ----
	// This read both derives the next sequence AND verifies the tail; the error
	// below is therefore the refusal branch as well as the I/O branch.
	last, err := s.scanLastSeq()
	if err != nil {
		return ev, err
	}
	ev.Seq = last + 1

	b, err := json.Marshal(ev)
	if err != nil {
		return ev, err
	}
	f, err := os.OpenFile(filepath.Join(s.Root, logDir, logFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return ev, err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return ev, err
	}
	if err := f.Sync(); err != nil {
		return ev, err
	}
	// Keep the observational cache truthful rather than stale.
	atomic.StoreInt64(&s.seq, ev.Seq)
	return ev, nil
}

// Events returns the full append-only ledger in order.
func (s *Store) Events() ([]model.Event, error) {
	f, err := os.Open(filepath.Join(s.Root, logDir, logFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []model.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev model.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("continuum/store: corrupt ledger line: %w", err)
		}
		out = append(out, ev)
	}
	return out, sc.Err()
}

// ---- atomic write ----------------------------------------------------------

// atomicWrite writes b to path via temp-in-same-dir -> fsync -> rename -> dir
// fsync (§11.4.205(6)). The temp is created in path's directory so the rename
// is a real move (never a cross-directory copy that could tear).
func atomicWrite(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return fsyncDir(dir)
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	// Directory fsync is best-effort on some platforms; ignore EINVAL-style
	// errors that indicate the platform does not support it.
	if err := d.Sync(); err != nil {
		// Not fatal on filesystems that reject dir fsync.
		return nil
	}
	return nil
}

// ParsePID is a small helper for the lock package's reap decision logging.
func ParsePID(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return n, true
}

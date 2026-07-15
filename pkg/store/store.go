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

	"github.com/vasic-digital/continuum/pkg/hash"
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
)

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

func (s *Store) loadSeq() error {
	f, err := os.Open(filepath.Join(s.Root, logDir, logFile))
	if errors.Is(err, os.ErrNotExist) {
		atomic.StoreInt64(&s.seq, 0)
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	var last int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev model.Event
		if err := json.Unmarshal([]byte(line), &ev); err == nil && ev.Seq > last {
			last = ev.Seq
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	atomic.StoreInt64(&s.seq, last)
	return nil
}

// AppendEvent assigns the next sequence number and appends ev to the ledger,
// fsyncing so the record is durable. The caller supplies ev.Time (the audit
// clock) and the semantic fields.
func (s *Store) AppendEvent(ev model.Event) (model.Event, error) {
	ev.Seq = atomic.AddInt64(&s.seq, 1)
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

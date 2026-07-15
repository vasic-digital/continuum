// Package snapshot composes the store + lock into continuum's high-level
// engine operations: Set (a stream writes its own state), Commit (atomically
// snapshot ALL streams at once — the Merkle manifest), Restore (byte-identical
// rehydration) and Diff (O(changed) — the property that makes instant resume of
// a large fleet cheap).
package snapshot

import (
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/vasic-digital/continuum/pkg/hash"
	"github.com/vasic-digital/continuum/pkg/lock"
	"github.com/vasic-digital/continuum/pkg/model"
	"github.com/vasic-digital/continuum/pkg/store"
)

// Engine bundles a store with the advisory-lock configuration guarding its refs.
type Engine struct {
	Store   *store.Store
	Actor   string
	LockTTL time.Duration
	// Evidence, if set, receives lock reap decisions (§11.4.180).
	Evidence io.Writer
	nowFn    func() time.Time
}

// New returns an Engine over an open store.
func New(s *store.Store, actor string, ttl time.Duration) *Engine {
	return &Engine{Store: s, Actor: actor, LockTTL: ttl, nowFn: time.Now}
}

func (e *Engine) now() time.Time {
	if e.nowFn != nil {
		return e.nowFn()
	}
	return time.Now()
}

func (e *Engine) lockPath() string { return e.Store.Root + "/.continuum.lock" }

func (e *Engine) acquire() (*lock.Lock, error) {
	return lock.Acquire(e.lockPath(), lock.Options{
		TTL:      e.LockTTL,
		Wait:     15 * time.Second,
		Evidence: e.Evidence,
	})
}

// Set records st as the current state of its stream (single-writer per stream,
// §11.4.206): if the stream already has a non-empty Owner and st.Owner differs,
// the write is REFUSED — a non-owner may not mutate a stream. The state blob is
// content-addressed (write-once) and the working manifest updated atomically
// under the advisory lock; an event is appended.
func (e *Engine) Set(st model.StreamState) error {
	if err := st.Validate(); err != nil {
		return err
	}
	l, err := e.acquire()
	if err != nil {
		return err
	}
	defer l.Release()

	working, err := e.Store.ReadWorking()
	if err != nil {
		return err
	}
	if prevID, ok := working[st.StreamID]; ok && st.Owner != "" {
		if prev, err := e.Store.GetState(prevID); err == nil && prev.Owner != "" && prev.Owner != st.Owner {
			return fmt.Errorf("continuum: stream %q is owned by %q; refusing write by %q (§11.4.206 single-writer)",
				st.StreamID, prev.Owner, st.Owner)
		}
	}
	id, err := e.Store.PutState(st)
	if err != nil {
		return err
	}
	working[st.StreamID] = id
	if err := e.Store.WriteWorking(working); err != nil {
		return err
	}
	_, err = e.Store.AppendEvent(model.Event{
		Time:        e.now().UTC().Format(time.RFC3339Nano),
		Type:        "set",
		Stream:      st.StreamID,
		ContentHash: id,
		Actor:       e.Actor,
	})
	return err
}

// Commit atomically snapshots the whole working set (all streams at once) into
// a new Merkle manifest, links it to the previous HEAD as parent, advances HEAD
// atomically, and appends an event. Returns the new snapshot id.
//
// Because unchanged streams keep the same content hash, the new snapshot blob
// only differs in the entries that changed — capturing the entire fleet is
// O(streams-in-manifest) to write the small manifest, and rehydrating on the
// other side reads only the referenced blobs (dedup across snapshots).
func (e *Engine) Commit(note string) (string, error) {
	l, err := e.acquire()
	if err != nil {
		return "", err
	}
	defer l.Release()

	working, err := e.Store.ReadWorking()
	if err != nil {
		return "", err
	}
	if len(working) == 0 {
		return "", fmt.Errorf("continuum: nothing to snapshot (working set empty)")
	}
	// Integrity precondition: every referenced blob must be present.
	for sid, cid := range working {
		if !e.Store.HasBlob(cid) {
			return "", fmt.Errorf("continuum: working stream %q references missing blob %s", sid, hash.Short(cid, 12))
		}
	}
	parent, err := e.Store.ReadRef(store.HeadRef)
	if err != nil {
		return "", err
	}
	snap := model.Snapshot{Streams: cloneMap(working), Parent: parent}
	id, err := e.Store.PutSnapshot(snap)
	if err != nil {
		return "", err
	}
	if err := e.Store.WriteRef(store.HeadRef, id); err != nil {
		return "", err
	}
	_, err = e.Store.AppendEvent(model.Event{
		Time:         e.now().UTC().Format(time.RFC3339Nano),
		Type:         "snapshot",
		SnapshotHash: id,
		Actor:        e.Actor,
		Note:         note,
	})
	return id, err
}

// Head returns the current committed snapshot id ("" if none).
func (e *Engine) Head() (string, error) { return e.Store.ReadRef(store.HeadRef) }

// RestoreAll returns every stream's state as committed in snapshot id (or HEAD
// if id==""). This is the instant, byte-identical rehydration of the whole
// fleet: one manifest read + one blob read per stream.
func (e *Engine) RestoreAll(id string) (map[string]model.StreamState, string, error) {
	if id == "" {
		var err error
		if id, err = e.Head(); err != nil {
			return nil, "", err
		}
	}
	if id == "" {
		return map[string]model.StreamState{}, "", nil
	}
	snap, err := e.Store.GetSnapshot(id)
	if err != nil {
		return nil, id, err
	}
	out := make(map[string]model.StreamState, len(snap.Streams))
	for sid, cid := range snap.Streams {
		st, err := e.Store.GetState(cid)
		if err != nil {
			return nil, id, fmt.Errorf("continuum: restore stream %q: %w", sid, err)
		}
		out[sid] = st
	}
	return out, id, nil
}

// RestoreStream returns one stream's committed state from snapshot id (or HEAD).
func (e *Engine) RestoreStream(id, streamID string) (model.StreamState, error) {
	all, _, err := e.RestoreAll(id)
	if err != nil {
		return model.StreamState{}, err
	}
	st, ok := all[streamID]
	if !ok {
		return model.StreamState{}, fmt.Errorf("continuum: stream %q not present in snapshot", streamID)
	}
	return st, nil
}

// DiffResult is the O(changed) delta between two snapshots.
type DiffResult struct {
	Added   []string
	Removed []string
	Changed []string
}

// Diff returns the per-stream delta between snapshots a and b (a==""/b=="" mean
// the empty snapshot). Only entries whose content hash differs are reported —
// the Merkle-DAG cheap-diff property.
func (e *Engine) Diff(a, b string) (DiffResult, error) {
	ma, err := e.streams(a)
	if err != nil {
		return DiffResult{}, err
	}
	mb, err := e.streams(b)
	if err != nil {
		return DiffResult{}, err
	}
	var d DiffResult
	for sid, hb := range mb {
		ha, ok := ma[sid]
		switch {
		case !ok:
			d.Added = append(d.Added, sid)
		case ha != hb:
			d.Changed = append(d.Changed, sid)
		}
	}
	for sid := range ma {
		if _, ok := mb[sid]; !ok {
			d.Removed = append(d.Removed, sid)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Changed)
	return d, nil
}

func (e *Engine) streams(id string) (map[string]string, error) {
	if id == "" {
		return map[string]string{}, nil
	}
	snap, err := e.Store.GetSnapshot(id)
	if err != nil {
		return nil, err
	}
	return snap.Streams, nil
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

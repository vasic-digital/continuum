// Package model defines the project-agnostic state model for the continuum
// instant-resume engine and its deterministic canonical serialization.
//
// Design constraints (constitution):
//   - §11.4.28/§11.4.177 — ZERO project literals. A StreamState is opaque
//     structured facts supplied by the consuming project as DATA. The engine
//     never interprets what a "track", "agent" or any Kind means.
//   - §11.4.205(4)/(5) & §11.4.201 — the hashed content is DETERMINISTIC in
//     committed state. Genuinely-volatile fields (wall-clock timestamps) are
//     NOT part of the content and never enter the content hash; they live in
//     the append-only event ledger (which legitimately records time) and in
//     the rendered resume view (informational, outside the verified block).
//     This is why a timestamp bump can never satisfy a freshness check.
package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
)

// Job is one in-flight unit of work a stream owns (build, test, push, ...).
// Fields are opaque strings; the engine never parses them.
type Job struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`  // pid / job id / correlation id (consumer-defined)
	Log  string `json:"log"` // captured-log path (§11.4.89 background-execution log)
}

// StreamState is the compact, structured, resumable state of ONE work stream
// (a track, a main stream, an agent, the ruler, ... — Kind is opaque).
//
// It is the unit that is content-addressed: two streams whose committed state
// is byte-identical share the same content hash and therefore the same stored
// blob (the Merkle-DAG dedup property that makes a global snapshot cost
// O(changed) not O(total)).
//
// IMPORTANT: this struct carries NO wall-clock timestamp. Time is recorded in
// the event ledger, not in hashed content (§11.4.205(4)/(5)).
type StreamState struct {
	// StreamID is the stable, unique identifier of the stream. Consumer-owned
	// and opaque (e.g. "T1/main", "agent:6a1c2da", "ruler"). §11.4.111 —
	// resolve by stable name, never an enumeration ordinal.
	StreamID string `json:"stream_id"`

	// Kind classifies the stream for the renderer only (opaque to the engine).
	Kind string `json:"kind"`

	// Phase / NextAction / Goal are the §11.4.127 resume triad: where we are,
	// the immediate next action, the terminal goal.
	Phase      string `json:"phase"`
	NextAction string `json:"next_action"`
	Goal       string `json:"goal"`

	// Head is the committed-state anchor the consumer derives (e.g. git HEAD,
	// an artifact checksum). Machine-derived by the consumer; opaque here.
	Head string `json:"head"`

	// InFlight enumerates jobs still running (pid + log path, §11.4.89).
	InFlight []Job `json:"in_flight,omitempty"`

	// Evidence lists captured-evidence artefact paths (§11.4.5/§11.4.69).
	Evidence []string `json:"evidence,omitempty"`

	// Blockers lists blocking decisions / operator-blocked reasons (§11.4.21).
	Blockers []string `json:"blockers,omitempty"`

	// Constraints restates binding constraints for a fresh session
	// (anti-bluff §11.4, no-force-push §11.4.113, exact version/naming, ...).
	Constraints []string `json:"constraints,omitempty"`

	// Owner is the single writer of this stream (§11.4.206 one-writer-per-SSoT
	// entity). A fresh writer must match this to update the stream.
	Owner string `json:"owner"`

	// Fields carries arbitrary extra structured facts. encoding/json marshals
	// string-keyed maps in sorted key order, so this stays deterministic.
	Fields map[string]string `json:"fields,omitempty"`
}

// Snapshot is the Merkle manifest: an atomic capture of the whole world.
// It maps every stream id to the content hash of that stream's StreamState
// blob, plus a link to the parent snapshot (forming the Merkle-DAG history).
// A snapshot's own hash covers ONLY Streams + Parent — deterministic content.
type Snapshot struct {
	Streams map[string]string `json:"streams"`          // streamID -> StreamState content hash
	Parent  string            `json:"parent,omitempty"` // parent snapshot hash ("" = root)
}

// Event is one entry in the append-only ledger (§11.4.116 real-time sync
// channel + §11.4.205(6) append-only-so-a-lost-update-is-recoverable). The
// ledger is the ONE place a real timestamp is recorded.
type Event struct {
	Seq          int64  `json:"seq"`
	Time         string `json:"time"` // RFC3339 UTC — the audit clock
	Type         string `json:"type"` // set|snapshot|restore|verify|reap
	Stream       string `json:"stream,omitempty"`
	ContentHash  string `json:"content_hash,omitempty"`
	SnapshotHash string `json:"snapshot_hash,omitempty"`
	Actor        string `json:"actor,omitempty"`
	Evidence     string `json:"evidence,omitempty"` // §11.4.116 verdict carries evidence path
	Note         string `json:"note,omitempty"`
}

// ErrEmptyStreamID is returned when a StreamState has no id.
var ErrEmptyStreamID = errors.New("continuum/model: empty StreamID")

// Validate checks the minimal invariants a StreamState must satisfy.
func (s *StreamState) Validate() error {
	if s.StreamID == "" {
		return ErrEmptyStreamID
	}
	return nil
}

// Canonical returns the deterministic canonical byte encoding of the value.
// It is the exact input to the content hash and the exact bytes written to the
// content-addressed blob store. Determinism: encoding/json emits struct fields
// in declaration order and sorts string map keys, and this model uses only
// strings, ints and slices/maps of them — so the encoding is stable across
// runs and Go versions. No wall-clock field participates.
func Canonical(v any) ([]byte, error) {
	// json.Marshal already produces deterministic output for this model; we go
	// through a compact buffer to strip any accidental HTML escaping and keep a
	// single stable form.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encoder appends a trailing newline; strip it so the canonical form is
	// exactly the value's bytes.
	out := bytes.TrimRight(buf.Bytes(), "\n")
	return out, nil
}

// canonicalSnapshotStreamKeys is a determinism belt-and-braces: it asserts the
// stream map is emitted in sorted order (used by tests, cheap at runtime).
func SortedStreamIDs(s Snapshot) []string {
	ids := make([]string, 0, len(s.Streams))
	for k := range s.Streams {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	return ids
}

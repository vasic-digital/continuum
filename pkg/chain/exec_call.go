// The FR-045 execution row -> union-rule adapter (F-002-24).
//
// # The divergence this file closes, stated plainly
//
// Three schemas were in play, and only two of them were ever written down in
// Go:
//
//	FR-045 execution row   ts cwd command argv exit_status duration_ms
//	(what the shell        stdout_digest stderr_digest stdout_bytes
//	 recorder emits)       stderr_bytes stream_ref stream_truncated
//	                       stream_redacted
//
//	E2 chain Record        seq ts command exit_status artifact_path
//	(what Decode reads)    evidence_class author_session_id
//	                       independence_tier prev_digest
//
//	Call                   kind cited
//	(what the union rule
//	 classifies)
//
// They share exactly TWO field names -- ts and command -- and even exit_status,
// present in two of them, is a STRING on the wire and an int in the record. So
// a real producer row does not "nearly" decode as a chain record; Decode
// refuses it outright (DisallowUnknownFields), which is asserted in
// TestExecRow_RawProducerRowIsRefusedByChainDecode.
//
// The important half is what the producer row does NOT carry. It has no
// artifact_path, no evidence_class, no author_session_id, no independence_tier,
// no prev_digest, no seq, and no citation bit. Those are not spellings waiting
// to be translated -- they are ABSENT CONCEPTS. So this adapter takes them as
// explicit PARAMETERS (ExecRecordFields) rather than defaulting them. A
// defaulted evidence_class would be a fabricated field sealed inside a digest
// that then certifies the fabrication, which is the precise failure the digest
// exists to prevent (see Record's doc comment on exit_status and
// evidence_class).
//
// # Why classification needs no argv-sniffing table
//
// Every row the execution recorder writes describes a command it ACTUALLY RAN
// -- exec_record_run runs the argv and then records it. So the kind is EXEC by
// construction of the producer, not by inference from the command text. That
// matters: a table mapping command names to kinds would be a guess (§11.4.6),
// it would drift silently as commands were added, and it would be wrong the
// first time someone recorded a shell wrapper.
//
// It also means `cited` never has to be invented here. Cited is decisive only
// for a READ; for a state-changing call the union rule states outright that it
// is irrelevant. The producer emits no citation bit, and this adapter
// classifies nothing that would need one. If a future producer records reads,
// it MUST emit the citation bit -- ClassifyExec will not guess it.
package chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// ExecRow is the FR-045 execution-recorder row exactly as the shell producer
// emits it, string wire types included. It is deliberately NOT a prettified
// Go-shaped view: the point of this type is to be the truthful edge of the
// system, so the string-typed exit_status is visible here rather than quietly
// coerced somewhere a reader will not look.
type ExecRow struct {
	Ts              string   `json:"ts"`
	Cwd             string   `json:"cwd"`
	Command         string   `json:"command"`
	Argv            []string `json:"argv"`
	ExitStatus      string   `json:"exit_status"`
	DurationMs      string   `json:"duration_ms"`
	StdoutDigest    string   `json:"stdout_digest"`
	StderrDigest    string   `json:"stderr_digest"`
	StdoutBytes     string   `json:"stdout_bytes"`
	StderrBytes     string   `json:"stderr_bytes"`
	StreamRef       string   `json:"stream_ref"`
	StreamTruncated string   `json:"stream_truncated"`
	StreamRedacted  string   `json:"stream_redacted"`
}

// ErrExecMalformedRow is returned for a line that is not exactly one FR-045 row.
var ErrExecMalformedRow = errors.New("continuum/chain: malformed execution row")

// ErrExecUnclassified is returned when a row cannot be classified. The adapter
// fails CLOSED rather than assuming a kind: an unclassified call whose entry is
// demanded costs one wasted record, whereas an unclassified call waved through
// costs the record of what happened.
var ErrExecUnclassified = errors.New("continuum/chain: execution row cannot be classified")

// DecodeExecRows parses an FR-045 recorder file -- one row per line.
//
// Unknown fields are REFUSED, for the same reason chain.Decode refuses them and
// for one more that is specific to this seam: an unknown field here means the
// PRODUCER has moved and this adapter no longer describes it. Dropping it would
// let the two schemas drift apart silently again, which is the condition this
// file was written to end. A loud refusal naming the line is the intended
// signal that the wire contract changed.
func DecodeExecRows(b []byte) ([]ExecRow, error) {
	var out []ExecRow
	lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
	for i, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var r ExecRow
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrExecMalformedRow, i+1, err)
		}
		if dec.More() {
			return nil, fmt.Errorf("%w: line %d carries more than one row", ErrExecMalformedRow, i+1)
		}
		out = append(out, r)
	}
	return out, nil
}

// ClassifyExec maps one recorder row to the Call the union rule classifies.
//
// The kind is CallExec by construction of the producer (see the package note),
// so the only thing that can go wrong is a row that does not describe a command
// at all -- and that refuses rather than defaulting.
func ClassifyExec(r ExecRow) (Call, error) {
	if r.Command == "" && len(r.Argv) == 0 {
		return Call{}, fmt.Errorf("%w: row carries neither command nor argv, so nothing was demonstrably executed", ErrExecUnclassified)
	}
	// Cited is left false and is IRRELEVANT here, not assumed: the union rule
	// ignores it for every state-changing kind.
	return Call{Kind: CallExec, Cited: false}, nil
}

// ExecRecordFields carries the E2 fields the producer row does not have.
//
// Every field here is one the FR-045 row CANNOT supply. Making them parameters
// is the whole point: the caller is forced to state them, so the gap is visible
// at every call site instead of being silently filled with a plausible default.
type ExecRecordFields struct {
	Seq              int64
	ArtifactPath     string
	EvidenceClass    string
	AuthorSessionID  string
	IndependenceTier string
	PrevDigest       string
}

// ToRecord converts an FR-045 row into an E2 chain Record.
//
// exit_status is PARSED, never defaulted (FR-003 / T119). A value that is not
// exactly a canonical decimal integer is an error: "007" and "+0" are refused
// alongside "" and "nope", because a status this adapter had to interpret is a
// status it could get wrong, and a wrong status sealed in a digest is a failure
// rewritten as a pass.
func (r ExecRow) ToRecord(f ExecRecordFields) (Record, error) {
	n, err := strconv.Atoi(r.ExitStatus)
	if err != nil || strconv.Itoa(n) != r.ExitStatus {
		return Record{}, fmt.Errorf(
			"continuum/chain: exit_status %q is not a canonical decimal integer; it is NOT defaulted to 0 (FR-003)",
			r.ExitStatus)
	}
	if f.EvidenceClass == "" {
		return Record{}, errors.New(
			"continuum/chain: evidence_class must be stated by the caller; the FR-045 row does not carry one and a default would be a fabricated field inside the digest")
	}
	cmd := r.Command
	if cmd == "" && len(r.Argv) > 0 {
		cmd = r.Argv[0]
	}
	return Record{
		Seq:              f.Seq,
		Ts:               r.Ts,
		Command:          cmd,
		ExitStatus:       n,
		ArtifactPath:     f.ArtifactPath,
		EvidenceClass:    f.EvidenceClass,
		AuthorSessionID:  f.AuthorSessionID,
		IndependenceTier: f.IndependenceTier,
		PrevDigest:       f.PrevDigest,
	}, nil
}

// VerifyExecRows is the consumer seam: it classifies real recorder rows and
// verifies a real chain against the union rule's demand for them.
//
// It returns the classified calls alongside the report so a caller can show its
// working -- a verdict whose inputs cannot be inspected is a verdict nobody can
// check.
//
// # Honest boundary (§11.4.6)
//
// This inherits VerifyComplete's limit exactly and adds nothing to it: Call
// carries no identity, so this is a COUNT check, not a per-call join. It
// catches a chain that recorded nothing, or fewer entries than commands ran. It
// does NOT catch a chain with the right number of entries describing different
// commands. Closing that needs a correlation key on both sides -- a change to
// the recording path, not something this function can conjure.
func VerifyExecRows(recs []Record, rows []ExecRow) (Report, []Call, error) {
	calls := make([]Call, 0, len(rows))
	for i, r := range rows {
		c, err := ClassifyExec(r)
		if err != nil {
			return Report{}, nil, fmt.Errorf("execution row %d: %w", i+1, err)
		}
		calls = append(calls, c)
	}
	return VerifyComplete(recs, calls), calls, nil
}

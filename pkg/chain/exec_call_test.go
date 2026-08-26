// Tests for the FR-045 execution-row -> union-rule adapter (F-002-24).
//
// The load-bearing test here is TestExecRow_CapturedRealProducerRow_*: its input
// is a row a REAL shell producer actually emitted, captured byte-for-byte, not a
// hand-written fixture shaped the way the Go type happens to want. A hand-written
// fixture would agree with the decoder by construction and would therefore have
// caught none of the divergence this file exists to pin down.
//
// TestExecRow_LiveProducerStillMatchesCapturedShape is the drift guard: it runs
// the ACTUAL producer when the caller points at it and asserts the frozen row
// above still has the shape the producer emits today. Frozen fixture = the
// contract; live run = proof the contract still describes reality.
package chain

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vasic-digital/continuum/pkg/model"
)

// capturedProducerRow is VERBATIM stdout from a real invocation of the shell
// execution recorder (constitution/scripts/gates/lib/execution_record.sh):
//
//	. ./execution_record.sh
//	exec_record_run "$T/rec.jsonl" "$T/streams" -- /bin/echo hello-real-producer
//
// captured 2026-08-22T00:10:28Z. Nothing about it has been reshaped for Go.
const capturedProducerRow = `{"ts":"2026-08-22T00:10:28Z","cwd":"/mnt/track1/atmosphere-t1/constitution/scripts/gates/lib","command":"/bin/echo hello-real-producer","argv":["/bin/echo","hello-real-producer"],"exit_status":"0","duration_ms":"4","stdout_digest":"fb458d7fc8693e1421ce30eb3f94df981b0d5d0379504b0b1c88591b390558b9","stderr_digest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","stdout_bytes":"20","stderr_bytes":"0","stream_ref":"/tmp/.private/milos/tmp.Zs6jQ3bJbG/streams/20260822T001028Z_1161905","stream_truncated":"false","stream_redacted":"false"}`

// ---------------------------------------------------------------------------
// The fork, stated mechanically
// ---------------------------------------------------------------------------

// A real producer row is REFUSED by the E2 record decoder. This is the
// divergence itself, asserted rather than described: the two schemas are not
// two spellings of one thing, they are different field sets, and Decode's
// DisallowUnknownFields makes that a hard refusal rather than a silent partial
// parse (which would be far worse -- see Decode's doc comment).
func TestExecRow_RawProducerRowIsRefusedByChainDecode(t *testing.T) {
	_, err := Decode([]byte(capturedProducerRow))
	if err == nil {
		t.Fatalf("a raw FR-045 producer row decoded as an E2 chain record; " +
			"the two schemas would then be silently conflated")
	}
	if !errors.Is(err, ErrMalformedRecord) {
		t.Fatalf("want ErrMalformedRecord, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Round-trip through the Go type
// ---------------------------------------------------------------------------

func TestExecRow_CapturedRealProducerRowRoundTrips(t *testing.T) {
	rows, err := DecodeExecRows([]byte(capturedProducerRow))
	if err != nil {
		t.Fatalf("DecodeExecRows on a real producer row: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	r := rows[0]

	if r.Command != "/bin/echo hello-real-producer" {
		t.Errorf("command: got %q", r.Command)
	}
	if r.ExitStatus != "0" {
		t.Errorf("exit_status is a STRING on the wire; got %q", r.ExitStatus)
	}
	if len(r.Argv) != 2 || r.Argv[0] != "/bin/echo" {
		t.Errorf("argv: got %#v", r.Argv)
	}

	// The E2 fields the producer row does NOT carry are PARAMETERS, never
	// defaulted: an invented artifact_path or evidence_class would be a
	// fabricated field inside a digest that then certifies the fabrication.
	rec, err := r.ToRecord(ExecRecordFields{
		Seq:              1,
		ArtifactPath:     "qa-results/002/exec/echo.log",
		EvidenceClass:    "runtime",
		AuthorSessionID:  "SESS-TEST",
		IndependenceTier: "instance",
		PrevDigest:       GenesisPrev,
	})
	if err != nil {
		t.Fatalf("ToRecord: %v", err)
	}
	if rec.ExitStatus != 0 {
		t.Errorf("exit_status must be parsed to int 0, got %d", rec.ExitStatus)
	}
	if rec.Ts != "2026-08-22T00:10:28Z" || rec.Command != r.Command {
		t.Errorf("carried fields lost: %+v", rec)
	}

	// Full round trip through the module's ONE canonicaliser and the real
	// decoder -- the same path a chain file travels.
	line, err := model.Canonical(rec)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	back, err := Decode(line)
	if err != nil {
		t.Fatalf("the converted record did NOT round-trip through Decode: %v", err)
	}
	if len(back) != 1 || back[0] != rec {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", back, rec)
	}
	if _, err := Digest(rec); err != nil {
		t.Fatalf("Digest on the converted record: %v", err)
	}
}

// exit_status is NEVER defaulted (FR-003 / T119). A row whose status cannot be
// read must error, because a silent 0 turns a failure into a pass inside a
// digest that then certifies it.
func TestExecRow_ExitStatusNeverDefaulted(t *testing.T) {
	for _, bad := range []string{"", "nope", "0x1", " 1"} {
		r := ExecRow{Ts: "t", Command: "c", ExitStatus: bad}
		if _, err := r.ToRecord(ExecRecordFields{EvidenceClass: "runtime"}); err == nil {
			t.Errorf("exit_status %q was accepted; it must refuse rather than default to 0", bad)
		}
	}
	r := ExecRow{Ts: "t", Command: "c", ExitStatus: "7"}
	rec, err := r.ToRecord(ExecRecordFields{EvidenceClass: "runtime"})
	if err != nil {
		t.Fatalf("a real status was refused: %v", err)
	}
	if rec.ExitStatus != 7 {
		t.Errorf("want 7, got %d", rec.ExitStatus)
	}
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

// Every recorder row is an EXEC by construction of the producer: the recorder
// only ever records a command it actually ran. That is a property of the
// producer, not a guess from the command text -- which is why no argv-sniffing
// table appears anywhere in this adapter.
func TestClassifyExec_RecorderRowIsStateChangingExec(t *testing.T) {
	rows, err := DecodeExecRows([]byte(capturedProducerRow))
	if err != nil {
		t.Fatalf("DecodeExecRows: %v", err)
	}
	c, err := ClassifyExec(rows[0])
	if err != nil {
		t.Fatalf("ClassifyExec: %v", err)
	}
	if c.Kind != CallExec {
		t.Fatalf("want %q, got %q", CallExec, c.Kind)
	}
	if !IsStateChanging(c.Kind) {
		t.Fatal("an executed command must be state-changing")
	}
	if !RequiresEntry(c) {
		t.Fatal("an executed command must REQUIRE a chain entry (FR-026)")
	}
}

// A row that carries no command is not classifiable, and the adapter refuses
// rather than inventing a kind (fail closed, §11.4.252 / §11.4.6).
func TestClassifyExec_RefusesUnclassifiableRow(t *testing.T) {
	if _, err := ClassifyExec(ExecRow{Ts: "t"}); !errors.Is(err, ErrExecUnclassified) {
		t.Fatalf("want ErrExecUnclassified, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// The consumer path both directions (§11.4.107(10)): both verdicts reachable,
// so neither is hardcoded.
// ---------------------------------------------------------------------------

func TestVerifyExecRows_GoldenGoodAndGoldenBad(t *testing.T) {
	rows := make([]ExecRow, 3)
	for i := range rows {
		rows[i] = ExecRow{Ts: "2026-08-22T00:00:00Z", Command: "cmd", ExitStatus: "0"}
	}

	// GOLDEN-GOOD: a chain long enough for the union rule's demand -> PASS.
	good := buildChain(t, 3)
	rep, calls, err := VerifyExecRows(good, rows)
	if err != nil {
		t.Fatalf("VerifyExecRows: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("want 3 classified calls, got %d", len(calls))
	}
	if RequiredEntries(calls) != 3 {
		t.Fatalf("3 executed commands must require 3 entries, got %d", RequiredEntries(calls))
	}
	if rep.Verdict != PASS {
		t.Fatalf("golden-good: want PASS, got %s (%+v)", rep.Verdict, rep.Findings)
	}

	// GOLDEN-BAD: the same calls against a chain that is genuinely short.
	bad := buildChain(t, 1)
	rep, _, err = VerifyExecRows(bad, rows)
	if err != nil {
		t.Fatalf("VerifyExecRows: %v", err)
	}
	if rep.Verdict != DETECTED {
		t.Fatalf("golden-bad: want DETECTED, got %s", rep.Verdict)
	}
	if len(rep.Findings) == 0 || rep.Findings[0].Kind != KindEntryMissing {
		t.Fatalf("golden-bad must name %s, got %+v", KindEntryMissing, rep.Findings)
	}
}

// buildChain returns n genuinely linked records (same digest path as the real
// walk, so PASS is earned rather than constructed).
func buildChain(t *testing.T, n int) []Record {
	t.Helper()
	var out []Record
	prev := GenesisPrev
	for i := 0; i < n; i++ {
		r := Record{
			Seq: int64(i + 1), Ts: "2026-08-22T00:00:00Z",
			Command: "cmd", ExitStatus: 0,
			ArtifactPath: "a.log", EvidenceClass: "runtime",
			AuthorSessionID: "S", IndependenceTier: "instance",
			PrevDigest: prev,
		}
		d, err := Digest(r)
		if err != nil {
			t.Fatalf("Digest: %v", err)
		}
		out = append(out, r)
		prev = d
	}
	return out
}

// ---------------------------------------------------------------------------
// Drift guard: the LIVE producer still emits the captured shape
// ---------------------------------------------------------------------------

// pkg/chain must stay project-agnostic (§11.4.28), so the producer's path is
// injected rather than hardcoded. Unset => honest SKIP with a reason
// (§11.4.3): nothing about the live producer was observed, and saying so is
// not the same as saying it agrees.
func TestExecRow_LiveProducerStillMatchesCapturedShape(t *testing.T) {
	rec := os.Getenv("CONTINUUM_EXEC_RECORDER_SH")
	if rec == "" {
		t.Skip("SKIP(producer_path_not_supplied): set CONTINUUM_EXEC_RECORDER_SH to the " +
			"execution recorder to check the captured row against the live producer")
	}
	if _, err := os.Stat(rec); err != nil {
		t.Fatalf("CONTINUUM_EXEC_RECORDER_SH=%q is not readable: %v", rec, err)
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "rec.jsonl")
	script := ". " + rec + " ; exec_record_run " + out + " " + filepath.Join(dir, "streams") +
		" -- /bin/echo hello-real-producer"
	cmd := exec.Command("sh", "-c", script)
	cmd.Dir = filepath.Dir(rec)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("live producer failed: %v\n%s", err, b)
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the live recorder file: %v", err)
	}
	live, err := DecodeExecRows(b)
	if err != nil {
		t.Fatalf("the LIVE producer row does not decode through DecodeExecRows: %v\nrow: %s", err, b)
	}
	if len(live) != 1 {
		t.Fatalf("want 1 live row, got %d", len(live))
	}

	// Shape, not values: ts/cwd/digests legitimately differ run to run. The
	// contract is the KEY SET and the wire TYPES.
	var liveKeys, capturedKeys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(b))), &liveKeys); err != nil {
		t.Fatalf("live row is not an object: %v", err)
	}
	if err := json.Unmarshal([]byte(capturedProducerRow), &capturedKeys); err != nil {
		t.Fatalf("captured row is not an object: %v", err)
	}
	for k := range capturedKeys {
		if _, ok := liveKeys[k]; !ok {
			t.Errorf("the live producer no longer emits %q: the captured fixture has drifted", k)
		}
	}
	for k := range liveKeys {
		if _, ok := capturedKeys[k]; !ok {
			t.Errorf("the live producer emits a NEW field %q the captured fixture does not carry", k)
		}
	}
	if live[0].ExitStatus != "0" {
		t.Errorf("live exit_status %q: expected the string wire form", live[0].ExitStatus)
	}
	if _, err := ClassifyExec(live[0]); err != nil {
		t.Errorf("a LIVE producer row failed to classify: %v", err)
	}
}

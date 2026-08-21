// Package chainfixtures builds the attack-fixture corpus for the evidence
// chain: one golden-good chain, one golden-bad per MEASURED attack, and the
// lagging-anchor negative control.
//
// # Why this package exists
//
// Every downstream chain test asserts something about a tampered corpus. If a
// "bad" fixture were silently identical to the good one, every one of those
// tests would pass vacuously while proving nothing. So the corpus ships with a
// self-check (fixtures_selfcheck_test.go) that asserts each golden-bad differs
// from golden-good in EXACTLY its intended way, byte-for-byte.
//
// # The measured facts this corpus encodes (research D-2)
//
// On a purpose-built 100,000-entry ledger attacked four ways:
//
//	Attack                    | chain alone | chain + anchor
//	--------------------------|-------------|---------------
//	Mutation                  | detected    | detected
//	Deletion                  | detected    | detected
//	Reorder                   | detected    | detected
//	Tail truncation           | UNDETECTED  | detected
//	Deletion + full re-chain  | UNDETECTED  | detected
//
// The load-bearing measurement: an adversary deleted one entry and recomputed
// the entire 100k chain in 0.43 s, and chain-alone verification reported PASS.
//
// THE TWO "UNDETECTED" ROWS ARE NOT A DEFECT AND MUST NOT BE "FIXED".
// The mechanism is structural, and this corpus makes it visible: tail
// truncation and delete+re-chain are exactly the two attacks that leave behind
// a VALID chain — contiguous sequence numbers, every prev_digest matching its
// predecessor. A chain can only ever prove internal consistency. It cannot know
// what it *should* have contained. Only an external record of the expected head
// and entry count — the anchor — carries that. Hence: the security lives in the
// anchor, and the window of forgeability equals the anchor interval. Against a
// same-user adversary a hash chain alone is security theatre.
//
// The corpus asserts that internal validity explicitly (see the selfcheck), so
// a future reader cannot mistake those two PASS results for a bug.
//
// # Honest boundary on scale (§11.4.6)
//
// This corpus is a STRUCTURAL fixture at small N. It does NOT reproduce the
// 100k-entry timings above; those are cited from the research measurement and
// are not re-measured here. Nothing in this package should be read as evidence
// about performance.
//
// # Canonicalisation contract
//
// The corpus is the CONTRACT. Records are canonicalised with the module's one
// canonicaliser (model.Canonical) and digested with the module's one hash
// (hash.Sum) — deliberately reused rather than re-implemented, so the substrate
// carries exactly one canonicalisation (§11.4.251, no byte-identical forks). An
// implementation of pkg/chain that cannot verify golden_good/chain.jsonl has
// diverged from this contract, and that failure is the intended signal.
package chainfixtures

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vasic-digital/continuum/pkg/hash"
	"github.com/vasic-digital/continuum/pkg/model"
)

// GenesisPrev is the prev_digest of the first record in a chain. It is the
// empty string, and it is the ONLY record permitted to carry it.
const GenesisPrev = ""

// Record mirrors the E2 evidence record's chained field set (data-model.md).
// Field DECLARATION ORDER is load-bearing: encoding/json emits struct fields in
// declaration order, so this order IS the canonical byte order.
//
// Every field below participates in the digest. That is the property
// record_alteration_test.go (T309) asserts field-by-field: a field outside the
// digest is a field an adversary may rewrite freely.
type Record struct {
	Seq              int64  `json:"seq"`
	Ts               string `json:"ts"`
	Command          string `json:"command"`
	ExitStatus       int    `json:"exit_status"`
	ArtifactPath     string `json:"artifact_path"`
	EvidenceClass    string `json:"evidence_class"`
	AuthorSessionID  string `json:"author_session_id"`
	IndependenceTier string `json:"independence_tier"`
	PrevDigest       string `json:"prev_digest"`
}

// Anchor is the external record of what the chain should be. head_digest alone
// is not enough: entry_count is what turns wholesale deletion into a DETECTED
// ABSENCE rather than silence (FR-037).
type Anchor struct {
	HeadDigest string `json:"head_digest"`
	EntryCount int    `json:"entry_count"`
	// Strength is drawn from {policy, mechanism} and is RECORDED, never
	// assumed (FR-038). Today's honest value is "policy": policy-forbidden is
	// not mechanically-prevented, and reporting "mechanism" without a probe
	// result is the exact theatre this feature exists to prevent.
	Strength string `json:"anchor_strength"`
}

// Strength values (closed set).
const (
	StrengthPolicy    = "policy"
	StrengthMechanism = "mechanism"
)

// AttackSpec is one row of the measured attack matrix.
type AttackSpec struct {
	// ID is the stable directory name of the fixture.
	ID string `json:"id"`
	// ChainAloneDetects records the MEASURED result. Two rows are false; those
	// two are the documented honest boundary, not a defect to be fixed.
	ChainAloneDetects bool `json:"chain_alone_detects"`
	// AnchorDetects is true for every measured row: with an anchor, all five
	// attacks are detected.
	AnchorDetects bool `json:"anchor_detects"`
	// LeavesValidChain explains WHY chain-alone detection succeeds or fails.
	// It is the exact inverse of ChainAloneDetects, and that identity is
	// asserted by the selfcheck — the boundary is structural, not incidental.
	LeavesValidChain bool `json:"leaves_valid_chain"`
	// Intent is the one-line description of the tamper this fixture applies.
	Intent string `json:"intent"`
}

// Attack ids (closed set).
const (
	AttackMutation       = "attack_mutation"
	AttackDeletion       = "attack_deletion"
	AttackReorder        = "attack_reorder"
	AttackTailTruncation = "attack_tail_truncation"
	AttackDeleteRechain  = "attack_delete_rechain"
)

// GoldenGoodDir and NegControlDir are corpus members that are NOT attacks.
const (
	GoldenGoodDir = "golden_good"
	// NegControlDir holds the §11.4.201(1) false-positive guard: a chain that
	// has grown by VALID appends since the last anchor. It must verify CLEAN.
	// A verifier that refuses it is committing a FAIL-bluff exactly as serious
	// as a PASS-bluff.
	NegControlDir = "negative_control_lagging_anchor"
)

// Attacks is the CLOSED, measured attack matrix — exactly five rows.
//
// The two rows with ChainAloneDetects=false (tail truncation, delete+re-chain)
// are the documented honest boundary. attack_matrix_test.go (T314) asserts they
// are still here, so a later edit cannot quietly drop them and leave a matrix
// that only shows detections.
var Attacks = []AttackSpec{
	{
		ID:                AttackMutation,
		ChainAloneDetects: true,
		AnchorDetects:     true,
		LeavesValidChain:  false,
		Intent:            "flip exit_status 1 -> 0 on one record without re-chaining (a failure rewritten as a pass)",
	},
	{
		ID:                AttackDeletion,
		ChainAloneDetects: true,
		AnchorDetects:     true,
		LeavesValidChain:  false,
		Intent:            "remove one record and leave every survivor untouched (no re-chain)",
	},
	{
		ID:                AttackReorder,
		ChainAloneDetects: true,
		AnchorDetects:     true,
		LeavesValidChain:  false,
		Intent:            "swap two adjacent records in position, contents untouched (no re-chain)",
	},
	{
		ID:                AttackTailTruncation,
		ChainAloneDetects: false, // MEASURED: undetected by the chain alone.
		AnchorDetects:     true,
		LeavesValidChain:  true, // a strict prefix of a valid chain is a valid chain
		Intent:            "drop the last records, leaving a byte-identical valid prefix",
	},
	{
		ID:                AttackDeleteRechain,
		ChainAloneDetects: false, // MEASURED: undetected. 0.43 s to recompute 100k.
		AnchorDetects:     true,
		LeavesValidChain:  true, // renumbered and fully re-linked: a valid chain
		Intent:            "remove one record, renumber seq contiguously and recompute every prev_digest",
	},
}

// Digest returns the content digest of r: the hash of its canonical bytes.
func Digest(r Record) (string, error) {
	b, err := model.Canonical(r)
	if err != nil {
		return "", err
	}
	return hash.Sum(b), nil
}

// Chain re-links records in place: record i's prev_digest becomes the digest of
// record i-1, and seq is renumbered contiguously from 1. This is the operation
// an adversary performs in the delete+re-chain attack, and the operation an
// honest producer performs when appending. That they are the same operation is
// precisely why the chain alone cannot tell them apart.
func Chain(recs []Record) ([]Record, error) {
	out := make([]Record, len(recs))
	copy(out, recs)
	prev := GenesisPrev
	for i := range out {
		out[i].Seq = int64(i + 1)
		out[i].PrevDigest = prev
		d, err := Digest(out[i])
		if err != nil {
			return nil, err
		}
		prev = d
	}
	return out, nil
}

// Head returns the digest of the last record ("" for an empty chain).
func Head(recs []Record) (string, error) {
	if len(recs) == 0 {
		return "", nil
	}
	return Digest(recs[len(recs)-1])
}

// Encode serialises a chain as JSONL — one canonical record per line. This is
// the on-disk corpus format and the byte-level unit the selfcheck diffs.
func Encode(recs []Record) ([]byte, error) {
	var buf bytes.Buffer
	for _, r := range recs {
		b, err := model.Canonical(r)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// Decode parses a JSONL chain. A malformed line is an ERROR, never a skipped
// line: silently skipping unparseable records is how a corrupt store gets
// reported as intact (FR-030).
func Decode(b []byte) ([]Record, error) {
	var out []Record
	for i, line := range bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("chainfixtures: line %d is not a record: %w", i+1, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// GoldenGood builds a valid chain of n records. Record 3 (1-indexed) carries a
// NON-ZERO exit_status on purpose: the mutation attack rewrites that failure
// into a success, which is the tamper this whole feature exists to catch.
func GoldenGood(n int) ([]Record, error) {
	if n < 8 {
		return nil, fmt.Errorf("chainfixtures: n=%d too small; attacks need room (>=8)", n)
	}
	recs := make([]Record, n)
	for i := range recs {
		exit := 0
		if i == 2 {
			exit = 1
		}
		recs[i] = Record{
			Ts:               fmt.Sprintf("2026-08-21T12:%02d:00Z", i),
			Command:          fmt.Sprintf("run-gate --case %d", i),
			ExitStatus:       exit,
			ArtifactPath:     fmt.Sprintf("qa-results/002-anti-slop/chain/case_%02d.log", i),
			EvidenceClass:    "runtime",
			AuthorSessionID:  "verifier-session-b",
			IndependenceTier: "instance",
		}
	}
	return Chain(recs)
}

// ---- attack transforms -------------------------------------------------
//
// Each returns a chain that differs from good in EXACTLY the declared way. The
// selfcheck re-derives that difference from the emitted bytes, so a transform
// that quietly returns an unmodified copy is caught rather than believed.

// mutateExitStatus flips the one non-zero exit_status to 0 WITHOUT re-chaining.
// Successors keep their old prev_digest, which no longer matches — that broken
// link is what makes this detectable.
func mutateExitStatus(good []Record) []Record {
	out := make([]Record, len(good))
	copy(out, good)
	out[2].ExitStatus = 0
	return out
}

// deleteOne removes one record and leaves every survivor byte-identical. The
// record after the hole still points at a predecessor that is gone.
func deleteOne(good []Record) []Record {
	const k = 4
	out := make([]Record, 0, len(good)-1)
	out = append(out, good[:k]...)
	out = append(out, good[k+1:]...)
	return out
}

// swapAdjacent exchanges two adjacent records' POSITIONS, contents untouched.
// A verifier that sorts by seq before walking silently repairs this — which is
// why attack_reorder_test.go (T304) names that sort as its paired mutation.
func swapAdjacent(good []Record) []Record {
	const k = 5
	out := make([]Record, len(good))
	copy(out, good)
	out[k], out[k+1] = out[k+1], out[k]
	return out
}

// truncateTail keeps a strict, byte-identical PREFIX. The result is a valid
// chain, which is why the chain alone reports PASS here.
func truncateTail(good []Record) []Record {
	out := make([]Record, len(good)-3)
	copy(out, good[:len(good)-3])
	return out
}

// deleteAndRechain removes a record and rebuilds the whole chain: contiguous
// seq, every prev_digest recomputed. The result is INDISTINGUISHABLE from an
// honest chain of n-1 records by any internal check. Only the anchor — which
// recorded head and count BEFORE the deletion — can tell.
func deleteAndRechain(good []Record) ([]Record, error) {
	const k = 3
	kept := make([]Record, 0, len(good)-1)
	kept = append(kept, good[:k]...)
	kept = append(kept, good[k+1:]...)
	return Chain(kept)
}

// ---- corpus emission ---------------------------------------------------

// Intent is the machine-readable declaration of what a fixture directory is.
type Intent struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"` // golden_good | attack | negative_control
	ChainAloneDetects bool   `json:"chain_alone_detects"`
	AnchorDetects     bool   `json:"anchor_detects"`
	LeavesValidChain  bool   `json:"leaves_valid_chain"`
	Description       string `json:"intent"`
}

// Matrix is the emitted attack matrix, written once per corpus so a shell gate
// or an out-of-package test can read the closed row set without importing Go.
type Matrix struct {
	// GoldenGoodEntries is the golden-good chain length, so a reader can tell a
	// truncation (shorter chain) from a lagging anchor (shorter anchor).
	GoldenGoodEntries int          `json:"golden_good_entries"`
	Attacks           []AttackSpec `json:"attacks"`
	// UndetectedByChainAlone names the honest-boundary rows explicitly, so
	// dropping one is a visible edit rather than a quiet deletion.
	UndetectedByChainAlone []string `json:"undetected_by_chain_alone"`
	Note                   string   `json:"note"`
}

const matrixNote = "The two rows in undetected_by_chain_alone are the DOCUMENTED LIMIT of a hash " +
	"chain against a same-user adversary, not a defect. Both leave a structurally valid chain; " +
	"only the anchor detects them. Do not 'fix' chain-alone to report detection here."

// Generate writes the whole corpus under outDir.
func Generate(outDir string, n int) error {
	good, err := GoldenGood(n)
	if err != nil {
		return err
	}

	write := func(dir string, recs []Record, anc Anchor, in Intent) error {
		d := filepath.Join(outDir, dir)
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
		b, err := Encode(recs)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(d, "chain.jsonl"), b, 0o644); err != nil {
			return err
		}
		ab, err := json.MarshalIndent(anc, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(d, "anchor.json"), append(ab, '\n'), 0o644); err != nil {
			return err
		}
		ib, err := json.MarshalIndent(in, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(d, "intent.json"), append(ib, '\n'), 0o644)
	}

	goodHead, err := Head(good)
	if err != nil {
		return err
	}
	// The TRUE anchor: taken when the chain held all n records. Every attack
	// fixture carries this SAME anchor, because an adversary with write access
	// to the local store has no write access to the anchor — that asymmetry is
	// the entire security argument.
	trueAnchor := Anchor{HeadDigest: goodHead, EntryCount: len(good), Strength: StrengthPolicy}

	if err := write(GoldenGoodDir, good, trueAnchor, Intent{
		ID: GoldenGoodDir, Kind: "golden_good", ChainAloneDetects: false, AnchorDetects: false,
		LeavesValidChain: true, Description: "untampered chain; MUST verify clean both ways",
	}); err != nil {
		return err
	}

	for _, a := range Attacks {
		var recs []Record
		switch a.ID {
		case AttackMutation:
			recs = mutateExitStatus(good)
		case AttackDeletion:
			recs = deleteOne(good)
		case AttackReorder:
			recs = swapAdjacent(good)
		case AttackTailTruncation:
			recs = truncateTail(good)
		case AttackDeleteRechain:
			recs, err = deleteAndRechain(good)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("chainfixtures: no transform for attack %q", a.ID)
		}
		if err := write(a.ID, recs, trueAnchor, Intent{
			ID: a.ID, Kind: "attack", ChainAloneDetects: a.ChainAloneDetects,
			AnchorDetects: a.AnchorDetects, LeavesValidChain: a.LeavesValidChain,
			Description: a.Intent,
		}); err != nil {
			return err
		}
	}

	// Negative control: the chain is the UNMODIFIED golden-good chain; the
	// ANCHOR is older (taken at entry m < n). Valid appends happened since.
	// This MUST verify clean. Note the discriminator against truncation: here
	// the chain is LONGER than the anchor and the anchored prefix is intact;
	// under truncation the chain is SHORTER than the anchor. A verifier that
	// compares head digests for equality fails BOTH — which is why
	// anchor_lagging_negative_control_test.go (T307) names that as its mutation.
	const m = 6
	oldHead, err := Head(good[:m])
	if err != nil {
		return err
	}
	if err := write(NegControlDir, good, Anchor{
		HeadDigest: oldHead, EntryCount: m, Strength: StrengthPolicy,
	}, Intent{
		ID: NegControlDir, Kind: "negative_control", ChainAloneDetects: false,
		AnchorDetects: false, LeavesValidChain: true,
		Description: "chain grew by valid appends since the anchor; MUST verify clean (false-positive guard)",
	}); err != nil {
		return err
	}

	var undetected []string
	for _, a := range Attacks {
		if !a.ChainAloneDetects {
			undetected = append(undetected, a.ID)
		}
	}
	mx := Matrix{
		GoldenGoodEntries:      len(good),
		Attacks:                Attacks,
		UndetectedByChainAlone: undetected,
		Note:                   matrixNote,
	}
	mb, err := json.MarshalIndent(mx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "matrix.json"), append(mb, '\n'), 0o644)
}

// LoadChain reads a fixture directory's chain.jsonl.
func LoadChain(dir string) ([]Record, error) {
	b, err := os.ReadFile(filepath.Join(dir, "chain.jsonl"))
	if err != nil {
		return nil, err
	}
	return Decode(b)
}

// LoadChainBytes reads the raw bytes (for byte-level diffing).
func LoadChainBytes(dir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, "chain.jsonl"))
}

// LoadAnchor reads a fixture directory's anchor.json.
func LoadAnchor(dir string) (Anchor, error) {
	var a Anchor
	b, err := os.ReadFile(filepath.Join(dir, "anchor.json"))
	if err != nil {
		return a, err
	}
	return a, json.Unmarshal(b, &a)
}

// LoadMatrix reads the emitted attack matrix.
func LoadMatrix(outDir string) (Matrix, error) {
	var m Matrix
	b, err := os.ReadFile(filepath.Join(outDir, "matrix.json"))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

// IsInternallyValid reports whether recs is a structurally valid chain:
// contiguous seq from 1, genesis prev on the first record, and every
// prev_digest equal to the predecessor's digest. It returns the reason on
// failure so a caller reports WHY, never a bare false.
//
// This is the function that makes the honest boundary legible: the two attacks
// the chain alone cannot detect are exactly the two for which this returns true.
func IsInternallyValid(recs []Record) (bool, string) {
	prev := GenesisPrev
	for i, r := range recs {
		if r.Seq != int64(i+1) {
			return false, fmt.Sprintf("record %d carries seq %d (expected %d)", i, r.Seq, i+1)
		}
		if r.PrevDigest != prev {
			return false, fmt.Sprintf("record %d prev_digest %q != predecessor digest %q", i, r.PrevDigest, prev)
		}
		d, err := Digest(r)
		if err != nil {
			return false, fmt.Sprintf("record %d digest error: %v", i, err)
		}
		prev = d
	}
	return true, ""
}

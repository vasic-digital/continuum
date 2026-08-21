// Package chain implements the evidence hash chain: the canonical record, its
// digest, and CHAIN-ALONE verification.
//
// # What this package proves, and what it does not
//
// A hash chain proves exactly one thing: INTERNAL CONSISTENCY. Every record's
// prev_digest matches the digest of the record physically preceding it, and
// every field of every record is inside that digest. From that it follows that
// mutation, deletion and reorder — tampers that leave a BROKEN chain behind —
// are detected here.
//
// It does NOT prove the chain is complete, and it cannot. A chain has no idea
// what it should have contained. The two measured attacks that leave a
// STRUCTURALLY VALID chain behind — tail truncation, and deletion followed by a
// full re-chain — are therefore UNDETECTABLE at this layer and report PASS. On
// a 100,000-entry ledger an adversary deleted one entry and recomputed the
// whole chain in 0.43 s; chain-alone verification reported PASS (research D-2).
// Those PASS results are the DOCUMENTED LIMIT, asserted by
// attack_tail_truncation_test.go and attack_delete_rechain_boundary_test.go.
// Making this package report detection for them would be a false claim.
//
// The security lives in the ANCHOR (pkg/anchor), an external record of the
// expected head digest and entry count that the producer can append to but not
// rewrite. The window of forgeability equals the anchor interval. Against a
// same-user adversary, a hash chain alone is security theatre; its real value
// is detecting accidental corruption and partial writes, giving a total order
// that cannot drift silently, and leaving an audit trail that makes tampering
// require deliberate reconstructive effort.
//
// # Layering
//
// pkg/chain knows NOTHING about anchors. pkg/anchor imports NOTHING from
// pkg/chain. pkg/verify composes the two and reports them as SEPARATE results,
// because the PAIR of results is the evidence that the anchor — not the chain —
// carries the truncation property.
//
// # Reused, not re-implemented (§11.4.251)
//
// Canonicalisation is model.Canonical and hashing is hash.Sum — the module's
// one canonicaliser and one hash, shared with the fixture corpus and the store.
// A second copy of either would be a byte-identical fork whose drift would be
// invisible until a digest silently stopped matching.
package chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vasic-digital/continuum/pkg/hash"
	"github.com/vasic-digital/continuum/pkg/model"
)

// GenesisPrev is the prev_digest carried by the first record of a chain. It is
// the empty string, and the first record is the ONLY one permitted to carry it.
const GenesisPrev = ""

// Record is one chained evidence record (the E2 field set, data-model.md).
//
// FIELD DECLARATION ORDER IS LOAD-BEARING. encoding/json emits struct fields in
// declaration order, so this order IS the canonical byte order, and it must
// stay identical to the on-disk corpus in test/fixtures/chain — that corpus is
// the byte contract (a pkg/chain that cannot verify golden_good/chain.jsonl has
// diverged from it).
//
// EVERY field below participates in the digest. That is not decoration: a field
// left outside the canonical bytes is a field an adversary may rewrite freely,
// and the two that matter most are exit_status (a failure rewritten as a pass)
// and evidence_class (a source-layer artifact relabelled as runtime evidence).
// record_alteration_test.go (T309) asserts that coverage field by field.
//
// No `omitempty` appears anywhere on purpose: an omitted field is a field
// absent from the canonical bytes, which would make the zero value of that
// field unprotected.
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

// Verdict is the closed result set of a chain-alone verification.
type Verdict string

const (
	// PASS — the chain is internally consistent. It does NOT mean the chain is
	// complete; see the package doc on the two attacks that PASS here.
	PASS Verdict = "PASS"
	// DETECTED — an alteration was found and is named in Findings.
	DETECTED Verdict = "DETECTED"
	// REFUSE — verification could not COMPLETE. Never reported as PASS and
	// never as a silent zero-findings result (FR-030): a walk that could not
	// finish has decided nothing, and "undecided" reported as "intact" is the
	// exact failure this package exists to prevent.
	REFUSE Verdict = "REFUSE"
)

// Finding kinds (closed set).
const (
	// KindChainGap — a record's prev_digest is not the digest of the record
	// that physically precedes it. Seq names the PREDECESSOR: that is the
	// record whose content no longer hashes to what its successor claims, so
	// it is the record an operator must look at.
	KindChainGap = "chain_GAP"
	// KindGenesisBreak — the first record carries a prev_digest. It has no
	// predecessor to check against, so it gets its own kind rather than being
	// silently folded into KindChainGap.
	KindGenesisBreak = "genesis_BREAK"
	// KindDigestUnavailable — a record could not be canonicalised or digested,
	// so the walk cannot continue. Drives REFUSE, never PASS.
	KindDigestUnavailable = "digest_UNAVAILABLE"
)

// Finding is one named, actionable observation. A detection an operator cannot
// act on is barely better than silence, so Seq and Detail are both populated.
type Finding struct {
	Kind   string `json:"kind"`
	Seq    int64  `json:"seq"`
	Detail string `json:"detail"`
}

// Report is the outcome of a verification.
type Report struct {
	Verdict  Verdict   `json:"verdict"`
	Findings []Finding `json:"findings,omitempty"`
}

// ErrMalformedRecord is returned by Decode for a line that is not exactly one
// canonical record.
var ErrMalformedRecord = errors.New("continuum/chain: malformed record")

// Digest returns the content digest of r: the hash of its canonical bytes.
//
// Identical to the corpus generator's digest by construction — same
// canonicaliser, same hash, same field order — which is what makes the on-disk
// corpus a real contract rather than a convention two packages happen to share.
func Digest(r Record) (string, error) {
	b, err := model.Canonical(r)
	if err != nil {
		return "", fmt.Errorf("continuum/chain: canonicalising record seq %d: %w", r.Seq, err)
	}
	return hash.Sum(b), nil
}

// Decode parses a JSONL chain — one canonical record per line.
//
// A malformed line is an ERROR, never a skipped line. Silently skipping an
// unparseable record is precisely how a corrupt store gets reported as intact
// (FR-030): the skipped record vanishes from the walk and the chain that closes
// over the hole looks healthy.
//
// Unknown fields are REFUSED for the same reason the digest covers every known
// field: a field this decoder drops is content that exists on disk, is not in
// the digest, and can therefore be rewritten at will. If the corpus ever grows
// a field, this refuses loudly and names the line — which is the intended
// signal that the byte contract moved, not a bug to be worked around by
// relaxing the decoder.
func Decode(b []byte) ([]Record, error) {
	var out []Record
	lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
	for i, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var r Record
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrMalformedRecord, i+1, err)
		}
		if dec.More() {
			return nil, fmt.Errorf("%w: line %d carries more than one record", ErrMalformedRecord, i+1)
		}
		out = append(out, r)
	}
	return out, nil
}

// Verify walks the chain IN FILE ORDER and reports every broken link.
//
// # File order, never sorted
//
// The walk follows the records as they physically appear, because file order is
// what an adversary controls. Sorting by seq before walking silently REPAIRS a
// reorder — the swapped pair is put back and the chain verifies clean — which
// is why attack_reorder_test.go (T304) names that sort as its paired mutation.
//
// # One detector, on purpose
//
// The prev_digest link walk is the SOLE driver of the verdict. There is
// deliberately NO independent sequence-continuity detector, for two reasons.
//
// First, it would add no detection: seq is inside the digest, so any seq tamper
// that is not accompanied by a full re-chain already breaks a link, and one
// that IS accompanied by a full re-chain is the documented boundary that no
// chain-alone check can see.
//
// Second — and this is the load-bearing reason — a second detector would make
// the T303 paired mutation vacuous. That mutation skips the predecessor walk
// across a missing seq (the plausible-looking "there is a hole here, of course
// the digests will not match, carry on" implementation). With the link walk as
// the only detector, that mutation produces no findings and deletion goes
// unreported, so the test fails, which is exactly what proves the test is
// load-bearing. Add a seq-continuity detector and the mutation still reports
// DETECTED, the test still passes, and the mutation has stopped proving
// anything. If you are here to add one: do not. Sequence continuity as a
// property belongs to the store's lock-held sequence derivation (T006/T316) and
// to the anchor's entry count (FR-037), not to a second chain-alone detector.
//
// Sequence information still reaches the operator: it is carried in the Detail
// of the finding, where it is context rather than a competing verdict source.
//
// # Re-sync after a break
//
// After a broken link the walk continues from the current record's digest
// rather than aborting, so a chain with several independent breaks reports all
// of them. Aborting at the first would under-report a multi-point tamper.
func Verify(recs []Record) Report {
	var findings []Finding

	prev := GenesisPrev
	for i := range recs {
		r := recs[i]

		if r.PrevDigest != prev {
			if i == 0 {
				findings = append(findings, Finding{
					Kind: KindGenesisBreak,
					Seq:  r.Seq,
					Detail: fmt.Sprintf(
						"first record (seq %d) carries prev_digest %q; only the genesis value %q is permitted at position 0",
						r.Seq, short(r.PrevDigest), GenesisPrev),
				})
			} else {
				// Name the PREDECESSOR: it is the record whose content no
				// longer hashes to what its successor claims.
				findings = append(findings, Finding{
					Kind: KindChainGap,
					Seq:  recs[i-1].Seq,
					Detail: fmt.Sprintf(
						"record %d (seq %d) carries prev_digest %q, but its predecessor at position %d (seq %d) digests to %q — the link is broken at seq %d",
						i, r.Seq, short(r.PrevDigest), i-1, recs[i-1].Seq, short(prev), recs[i-1].Seq),
				})
			}
		}

		d, err := Digest(r)
		if err != nil {
			// The walk cannot continue, so it has decided nothing about the
			// records beyond this point. REFUSE, naming the reason.
			findings = append(findings, Finding{
				Kind:   KindDigestUnavailable,
				Seq:    r.Seq,
				Detail: fmt.Sprintf("record %d (seq %d) could not be digested: %v", i, r.Seq, err),
			})
			return Report{Verdict: REFUSE, Findings: findings}
		}
		prev = d
	}

	if len(findings) > 0 {
		return Report{Verdict: DETECTED, Findings: findings}
	}
	// An empty chain is vacuously consistent and reports PASS. That is not a
	// gap being waved through: wholesale deletion is caught by the anchor's
	// entry_count (FR-037), which is the only layer that knows how many records
	// there should have been. Reporting DETECTED here instead would refuse
	// every legitimately-empty chain — a false refusal, and per §11.4.201(1) as
	// serious a bluff as a false pass.
	return Report{Verdict: PASS}
}

// short renders a digest for a message. Display only — never for comparison.
func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

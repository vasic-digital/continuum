package anchor

import (
	"errors"
	"fmt"

	"github.com/vasic-digital/continuum/pkg/hash"
)

// Verdict is the closed result vocabulary for an anchor comparison (§11.4.116).
//
// REFUSE is not a soft FAIL and DETECTED is not a soft REFUSE. They answer
// different questions: DETECTED means "I compared, and the chain is not the one
// that was anchored"; REFUSE means "I could not compare". Collapsing them loses
// exactly the information an operator needs to know whether to investigate a
// tamper or fix an instrument.
type Verdict string

const (
	// PASS — the chain is consistent with the anchor.
	PASS Verdict = "PASS"
	// DETECTED — the chain is NOT the chain that was anchored.
	DETECTED Verdict = "DETECTED"
	// REFUSE — the comparison could not be completed (FR-030). Never PASS.
	REFUSE Verdict = "REFUSE"
	// SKIP — not applicable / could not be probed, with the reason named.
	SKIP Verdict = "SKIP"
)

// Result is one anchor comparison. Reason is populated for every verdict, and
// is REQUIRED to be non-empty for DETECTED and REFUSE: a detection an operator
// cannot act on is barely better than silence.
type Result struct {
	Verdict Verdict
	Reason  string
}

// ErrPrefixUnavailable is returned by a ChainSummary.PrefixHead that cannot
// produce the requested prefix digest. It is a sentinel so a caller can tell
// "the chain is shorter than you asked for" from "the store is broken" — the
// first is ordinary, the second is a refusal.
var ErrPrefixUnavailable = errors.New("anchor: anchored prefix is unavailable")

// ChainSummary is the chain's view of itself, handed to Check.
//
// PrefixHead(n) returns the digest of the head of the FIRST n records — the
// value the anchor would have recorded when the chain held exactly n entries.
// It is the accessor that makes a lagging anchor distinguishable from a rewrite,
// and Check cannot decide without it.
type ChainSummary struct {
	// Head is the digest of the chain's current last record ("" if empty).
	Head string
	// Count is how many records the chain presents now.
	Count int
	// PrefixHead returns the digest of the head of the first n records, or
	// ErrPrefixUnavailable if that prefix cannot be produced.
	PrefixHead func(n int) (string, error)
}

// Check compares a chain against the anchor that was taken of it.
//
// # The rule, and why it is shaped this way
//
// Three situations must be told apart, and they differ in the DIRECTION of the
// count plus the INTACTNESS of the anchored prefix:
//
//	lagging anchor   count > EntryCount, anchored prefix intact  -> PASS
//	tail truncation  count < EntryCount                          -> DETECTED
//	history rewrite  count >= EntryCount, anchored prefix WRONG  -> DETECTED
//
// A HEAD-DIGEST EQUALITY CHECK COLLAPSES ALL THREE. It refuses the lagging
// anchor — a chain that merely grew by valid appends, where nothing whatsoever
// is wrong — and that is a FAIL-bluff exactly as serious as a false pass
// (§11.4.201(1)): it condemns healthy work, and it teaches people to ignore the
// verifier, which is how a real detection later gets waved through. That
// equality check is the named paired mutation for this function; it must make
// the lagging negative control fail.
//
// # Order is load-bearing
//
// The count comparison runs BEFORE the prefix comparison, and not for tidiness.
// Under truncation the chain is SHORTER than the anchor, so the anchored prefix
// literally does not exist in it — PrefixHead(EntryCount) returns
// ErrPrefixUnavailable. Asking for the prefix first would turn every truncation
// into REFUSE ("I could not compare") when the count alone is already positive
// evidence of the thing we are looking for. Truncation is detected, not
// undecidable.
//
// # What this does not do
//
// It does not walk the chain and it does not verify prev_digest links; mutation
// and reorder leave the head and count untouched and are the CHAIN's to detect.
// This is the second of two layers, reported separately from the first on
// purpose: the pair of results is the evidence that the anchor, not the chain,
// carries the truncation property.
func Check(a Anchor, cs ChainSummary) Result {
	if err := Validate(a); err != nil {
		// An unusable anchor is an instrument problem, not a tamper finding.
		return Result{REFUSE, fmt.Sprintf("anchor is not usable: %v", err)}
	}
	if cs.Count < 0 {
		return Result{REFUSE, fmt.Sprintf("chain summary reports a negative count (%d)", cs.Count)}
	}

	// --- truncation / wholesale deletion: the chain is shorter than anchored.
	if cs.Count < a.EntryCount {
		return Result{DETECTED, fmt.Sprintf(
			"chain presents %d records but the anchor recorded %d at head %s: %d entries are missing",
			cs.Count, a.EntryCount, hash.Short(a.HeadDigest, 12), a.EntryCount-cs.Count)}
	}

	// --- from here the chain is at least as long as the anchor. Longer is only
	// fine when the ANCHORED PREFIX is still the one that was anchored;
	// "the chain grew" is not on its own evidence of health.
	if cs.PrefixHead == nil {
		return Result{REFUSE, "chain summary exposes no prefix accessor, so the anchored prefix cannot be re-derived"}
	}
	prefix, err := cs.PrefixHead(a.EntryCount)
	if err != nil {
		return Result{REFUSE, fmt.Sprintf(
			"the anchored prefix (first %d records) could not be obtained: %v", a.EntryCount, err)}
	}
	if prefix == "" {
		return Result{REFUSE, fmt.Sprintf(
			"the prefix accessor returned an empty digest for the first %d records", a.EntryCount)}
	}
	if prefix != a.HeadDigest {
		return Result{DETECTED, fmt.Sprintf(
			"the first %d records now hash to %s, but the anchor recorded %s: the anchored history has been rewritten",
			a.EntryCount, hash.Short(prefix, 12), hash.Short(a.HeadDigest, 12))}
	}

	if cs.Count == a.EntryCount {
		return Result{PASS, fmt.Sprintf(
			"chain matches the anchor exactly: %d entries, head %s", cs.Count, hash.Short(a.HeadDigest, 12))}
	}
	return Result{PASS, fmt.Sprintf(
		"anchor is behind by %d entries and every anchored record is intact: the chain grew by valid appends (anchored %d at %s, chain now %d)",
		cs.Count-a.EntryCount, a.EntryCount, hash.Short(a.HeadDigest, 12), cs.Count)}
}
